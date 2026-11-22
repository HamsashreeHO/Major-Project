"""Tests for Aadhaar validation, Secure QR verification and server-side enforcement.

All data is synthetic: throwaway RSA/ECDSA keys, fake names, checksum-valid fake numbers.
"""
import asyncio
from types import SimpleNamespace

import pytest
from ecdsa import SECP256k1, SigningKey
from fastapi.testclient import TestClient

from crypto_core.crypto_utils import generate_identity_hash, generate_name_hash, sign_identity
from middleware import aadhaar_secure_qr as secure_qr, app as middleware_app
from middleware.aadhaar_validation import (
    canonical_aadhaar,
    match_signed_details,
    normalize_aadhaar,
    verhoeff_valid,
)
from middleware.auth_store import hash_aadhaar_pin
from middleware.eaadhaar_pdf import generate_eaadhaar_password
from middleware.replay_protection import ReplayProtection
from middleware.verification_state import VerificationState
from qr_fixtures import (
    OTHER_AADHAAR_DASHED,
    VALID_AADHAAR,
    VALID_AADHAAR_DASHED,
    build_payload_digits,
    make_pdf_with_qr,
    make_rsa_key,
)

NAME, DOB, GENDER, PIN = "Asha Rao", "05-03-1990", "Female", "4321"


# ───────────── number validation ─────────────

def test_known_verhoeff_value_and_generated_number_are_valid():
    assert verhoeff_valid("2363")
    assert normalize_aadhaar(VALID_AADHAAR) == VALID_AADHAAR


def test_invalid_checksum_is_rejected():
    wrong = VALID_AADHAAR[:-1] + str((int(VALID_AADHAAR[-1]) + 1) % 10)
    with pytest.raises(ValueError):
        normalize_aadhaar(wrong)


@pytest.mark.parametrize("value", ["", "abc", "0" + VALID_AADHAAR[1:], "1" + VALID_AADHAAR[1:], VALID_AADHAAR[:-1], "2345 6789 01x2"])
def test_bad_format_is_rejected(value):
    with pytest.raises(ValueError):
        normalize_aadhaar(value)


def test_spaces_and_dashes_are_stripped_to_canonical_form():
    spaced = f"{VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]}"
    assert canonical_aadhaar(spaced) == VALID_AADHAAR_DASHED
    assert canonical_aadhaar(VALID_AADHAAR) == VALID_AADHAAR_DASHED


# ───────────── field matching ─────────────

SIGNED = {"name": "Asha Rao", "dob": "05-03-1990", "gender": "F", "aadhaar_last4": VALID_AADHAAR[-4:]}


def test_matching_normalizes_case_punctuation_and_date_format():
    result = match_signed_details(SIGNED, "  ASHA   rao. ", "1990-03-05", "female", VALID_AADHAAR)
    assert result["result"] == "verified"


def test_name_mismatch_is_rejected_with_reason_code():
    result = match_signed_details(SIGNED, "Priya Nair", DOB, GENDER, VALID_AADHAAR)
    assert result["result"] == "rejected"
    assert result["reason_codes"]["name"] == "NAME_MISMATCH"


def test_dob_and_gender_are_exact():
    assert match_signed_details(SIGNED, NAME, "06-03-1990", GENDER, VALID_AADHAAR)["reason_codes"]["dob"] == "DOB_MISMATCH"
    assert match_signed_details(SIGNED, NAME, DOB, "Male", VALID_AADHAAR)["reason_codes"]["gender"] == "GENDER_MISMATCH"


def test_missing_signed_field_is_pending_not_verified():
    result = match_signed_details({**SIGNED, "gender": ""}, NAME, DOB, GENDER, VALID_AADHAAR)
    assert result["result"] == "pending"


# ───────────── Secure QR verification ─────────────

def test_valid_signed_qr_verifies_and_photo_bytes_are_not_split():
    key = make_rsa_key()
    details = secure_qr.verify_qr_payload(build_payload_digits(key), [key.public_key()])
    assert details["version"] == "V2"
    assert (details["name"], details["dob"], details["gender"]) == ("Asha Rao", "05-03-1990", "F")
    assert details["aadhaar_last4"] == VALID_AADHAAR[-4:]


def test_v5_marker_is_accepted_and_other_versions_are_rejected():
    key = make_rsa_key()
    assert secure_qr.verify_qr_payload(build_payload_digits(key, version=b"V5"), [key.public_key()])["version"] == "V5"
    with pytest.raises(secure_qr.SecureQRError) as error:
        secure_qr.verify_qr_payload(build_payload_digits(key, version=b"V3"), [key.public_key()])
    assert error.value.code == "QR_UNSUPPORTED_VERSION"


def test_tampered_qr_fails_signature():
    key = make_rsa_key()
    with pytest.raises(secure_qr.SecureQRError) as error:
        secure_qr.verify_qr_payload(build_payload_digits(key, tamper=True), [key.public_key()])
    assert error.value.code == "SIGNATURE_INVALID"


def test_wrong_certificate_fails_signature():
    with pytest.raises(secure_qr.SecureQRError) as error:
        secure_qr.verify_qr_payload(build_payload_digits(make_rsa_key()), [make_rsa_key().public_key()])
    assert error.value.code == "SIGNATURE_INVALID"


def test_no_pinned_certificate_fails_closed():
    key = make_rsa_key()
    with pytest.raises(secure_qr.SecureQRError) as error:
        secure_qr.verify_qr_payload(build_payload_digits(key), [])
    assert error.value.code == "CERTIFICATE_UNAVAILABLE"


def test_payload_without_gzip_magic_is_rejected_before_parsing():
    key = make_rsa_key()
    with pytest.raises(secure_qr.SecureQRError) as error:
        secure_qr.verify_qr_payload(build_payload_digits(key, gzip_magic=False), [key.public_key()])
    assert error.value.code == "QR_ENCODING_INVALID"


def test_non_digit_payload_is_rejected():
    with pytest.raises(secure_qr.SecureQRError):
        secure_qr.verify_qr_payload("12ab" * 100, [make_rsa_key().public_key()])


def test_pdf_without_qr_reports_missing(monkeypatch):
    monkeypatch.setattr(secure_qr, "RENDER_DPIS", (100,))
    assert secure_qr.verify_secure_qr(_write(make_pdf_with_qr()), None, [make_rsa_key().public_key()]) == {
        "ok": False, "code": "QR_MISSING",
    }


def test_qr_is_detected_in_rendered_pdf(tmp_path):
    payload = "9876543210" * 21  # largest the OpenCV test encoder can round-trip
    path = tmp_path / "doc.pdf"
    path.write_bytes(make_pdf_with_qr(payload))
    assert secure_qr.find_qr_payloads(path) == [payload]


def test_larger_of_two_qr_codes_is_tried_first(monkeypatch, tmp_path):
    small, large = "1" * 250, "2" * 900
    monkeypatch.setattr(secure_qr, "_read_qr_codes", lambda image: [small, "not a secure qr", large])
    path = tmp_path / "doc.pdf"
    path.write_bytes(make_pdf_with_qr())
    assert secure_qr.find_qr_payloads(path) == [large, small]


def _write(pdf_bytes):
    import tempfile
    from pathlib import Path
    handle = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    handle.write(pdf_bytes)
    handle.close()
    return Path(handle.name)


# ───────────── API: registration ─────────────

def signup(client, email):
    response = client.post("/auth/applicant/signup", json={"name": "Synthetic", "email": email, "password": "test-only-password"})
    assert response.status_code == 200


@pytest.fixture
def api(monkeypatch):
    accounts = {"applicants": {}, "developers": {}}
    monkeypatch.setattr(middleware_app, "load_accounts", lambda: accounts)
    monkeypatch.setattr(middleware_app, "save_accounts", lambda updated: accounts.update(updated))

    clock = [1000.0]
    monkeypatch.setattr(middleware_app, "replay_protection", ReplayProtection(ttl_seconds=300, clock=lambda: clock[0]))
    monkeypatch.setattr(middleware_app, "verification_state", VerificationState(clock=lambda: clock[0]))

    rsa_key = make_rsa_key()
    monkeypatch.setattr(middleware_app, "pinned_public_keys", lambda: [rsa_key.public_key()])

    ec_private = SigningKey.generate(curve=SECP256k1)
    monkeypatch.setattr(middleware_app, "private_key", ec_private)
    monkeypatch.setattr(middleware_app, "public_key", ec_private.get_verifying_key())

    state = SimpleNamespace(clock=clock, rsa_key=rsa_key, writes=[], chain_writes=[], monkeypatch=monkeypatch)

    async def stub_register(request, name, dob, aadhaar_id, pin, mobile, field_results=None, processing_status=None, verification=None):
        state.writes.append((aadhaar_id, name))
        return middleware_app.JSONResponse({"success": True, "message": "ok", **(verification or {})})

    monkeypatch.setattr(middleware_app, "_register_verified_citizen", stub_register)

    identity_hash = generate_identity_hash(NAME, DOB, VALID_AADHAAR_DASHED)
    record = (identity_hash, sign_identity(ec_private, identity_hash), generate_name_hash(NAME), 1, True)

    class Call:
        def __init__(self, value):
            self.value = value

        async def call(self):
            return self.value

    def get_proof(aadhaar_id):
        return Call(record if aadhaar_id == VALID_AADHAAR_DASHED else ("", "", "", 0, False))

    monkeypatch.setattr(middleware_app, "aadhaar_contract", SimpleNamespace(functions=SimpleNamespace(getIdentityProof=get_proof)))
    class FakeEth:
        @property
        def block_number(self):
            return asyncio.sleep(0, result=7)

    monkeypatch.setattr(middleware_app, "w3", SimpleNamespace(eth=FakeEth()))

    async def no_application(aadhaar_id):
        return None

    async def fake_transaction(call):
        state.chain_writes.append(call)
        return SimpleNamespace(transactionHash=b"\x01", blockNumber=8, gasUsed=1)

    monkeypatch.setattr(middleware_app, "find_approved_application", no_application)
    monkeypatch.setattr(middleware_app, "send_transaction", fake_transaction)
    monkeypatch.setattr(
        middleware_app, "passport_contract",
        SimpleNamespace(functions=SimpleNamespace(submitApplication=lambda *args: ("submit", args))),
    )
    monkeypatch.setattr(
        middleware_app, "load_aadhaar_pins",
        lambda: {VALID_AADHAAR_DASHED: {"name": NAME, "email": "owner@example.test", **hash_aadhaar_pin(PIN)}},
    )

    owner = TestClient(middleware_app.app)
    signup(owner, "owner@example.test")
    other = TestClient(middleware_app.app)
    signup(other, "other@example.test")
    state.owner, state.other = owner, other
    return state


def registration_form(**overrides):
    fields = {"name": NAME, "dob": DOB, "aadhaar_id": VALID_AADHAAR, "pin": "1234", "mobile": "9876543210", "gender": "Female"}
    fields.update(overrides)
    return fields


def register(api, digits_list, **overrides):
    api.monkeypatch.setenv("REGISTRATION_ALLOW_PDF", "true")  # PDF path is off by default
    api.monkeypatch.setattr(secure_qr, "find_qr_payloads", lambda path, password=None: digits_list)
    form = registration_form(**overrides)
    password = generate_eaadhaar_password(form["name"], form["dob"])
    return api.owner.post(
        "/aadhaar/register",
        data=form,
        files={"aadhaar_document": ("doc.pdf", make_pdf_with_qr(None, password), "application/pdf")},
    )


def test_signed_qr_with_matching_details_is_verified_and_uses_canonical_id(api):
    response = register(api, [build_payload_digits(api.rsa_key)])
    assert response.status_code == 200
    assert response.json()["result"] == "verified"
    assert response.json()["document_authenticity"] == "UIDAI_SIGNATURE_VERIFIED"
    assert api.writes == [(VALID_AADHAAR_DASHED, NAME)]


def test_invalid_checksum_is_rejected_by_api(api):
    wrong = VALID_AADHAAR[:-1] + str((int(VALID_AADHAAR[-1]) + 1) % 10)
    response = register(api, [build_payload_digits(api.rsa_key)], aadhaar_id=wrong)
    assert response.status_code == 400
    assert api.writes == []


def test_name_mismatch_is_rejected_and_not_written(api):
    response = register(api, [build_payload_digits(api.rsa_key)], name="Priya Nair")
    body = response.json()
    assert response.status_code == 422
    assert body["result"] == "rejected"
    assert body["reason_codes"]["name"] == "NAME_MISMATCH"
    assert api.writes == []


def test_tampered_qr_is_rejected_without_ocr_fallback(api):
    response = register(api, [build_payload_digits(api.rsa_key, tamper=True)])
    assert response.status_code == 422
    assert response.json()["reason_codes"] == {"document": "SIGNATURE_INVALID"}
    assert api.writes == []


def test_wrong_certificate_is_rejected(api):
    response = register(api, [build_payload_digits(make_rsa_key())])
    assert response.status_code == 422
    assert response.json()["reason_codes"]["document"] == "SIGNATURE_INVALID"
    assert api.writes == []


def test_missing_qr_never_verifies_and_stays_off_chain(api):
    api.monkeypatch.setattr(
        middleware_app, "extract_eaadhaar_details",
        lambda path, password: {
            "password_status": "VERIFIED", "text_available": True, "extraction_method": "TEXT",
            "ocr_status": "NOT_NEEDED", "ocr_message": None, "field_sources": {}, "ocr_confidence": {},
            "name": NAME, "dob": "1990-03-05", "gender": "female", "aadhaar_id": VALID_AADHAAR,
        },
    )
    response = register(api, [])
    body = response.json()
    assert response.status_code == 202
    assert body["result"] == "pending"
    assert body["document_authenticity"] == "NOT_VERIFIED"
    assert api.writes == []


# ───────────── API: verify / apply enforcement ─────────────

def verify(client, aadhaar=VALID_AADHAAR_DASHED, name=NAME, pin=PIN):
    return client.post(f"/aadhaar/verify/{aadhaar}", json={"name": name, "pin": pin})


def apply(client, challenge=None, **overrides):
    body = {"name": NAME, "aadhaar_id": VALID_AADHAAR_DASHED, "pin": PIN, **(challenge or {}), **overrides}
    return client.post("/passport/apply", json=body)


def challenge_from(response):
    data = response.json()
    return {"request_id": data["request_id"], "nonce": data["nonce"]}


def test_apply_without_verification_is_refused(api):
    response = apply(api.owner)
    assert response.status_code == 403
    assert api.chain_writes == []


def test_verified_applicant_can_apply_once(api):
    challenge = challenge_from(verify(api.owner))
    assert apply(api.owner, challenge).status_code == 200
    assert len(api.chain_writes) == 1
    assert apply(api.owner, challenge).status_code == 403  # replay of the same nonce
    assert len(api.chain_writes) == 1


def test_replayed_nonce_is_refused_even_with_fresh_verification_record(api):
    first = challenge_from(verify(api.owner))
    assert apply(api.owner, first).status_code == 200
    verify(api.owner)  # new verification record, but the old nonce is spent
    assert apply(api.owner, first).status_code == 403


def test_expired_nonce_is_refused(api):
    challenge = challenge_from(verify(api.owner))
    api.clock[0] += 301
    assert apply(api.owner, challenge).status_code == 403
    assert api.chain_writes == []


def test_nonce_is_bound_to_the_session(api):
    challenge = challenge_from(verify(api.owner))
    thief = TestClient(middleware_app.app)
    login = thief.post("/auth/applicant/login", json={"email": "owner@example.test", "password": "test-only-password"})
    assert login.status_code == 200  # same applicant, different session
    assert apply(thief, challenge).status_code == 403
    assert api.chain_writes == []


def test_another_persons_aadhaar_id_is_refused_everywhere(api):
    assert verify(api.other).status_code == 403
    assert apply(api.other).status_code == 403
    assert api.other.get(f"/aadhaar/proof/{VALID_AADHAAR_DASHED}").status_code == 403
    assert api.chain_writes == []


def test_unowned_unregistered_id_is_also_forbidden(api):
    assert api.owner.get(f"/aadhaar/proof/{OTHER_AADHAAR_DASHED}").status_code == 403


def test_lockout_after_repeated_wrong_pins_blocks_correct_pin(api):
    for _ in range(5):
        assert verify(api.owner, pin="0000").status_code == 401
    assert verify(api.owner).status_code == 429
    assert apply(api.owner).status_code == 429
    api.clock[0] += 15 * 60 + 1
    assert verify(api.owner).status_code == 200


def test_error_responses_are_generic(api):
    wrong_pin = verify(api.owner, pin="0000")
    wrong_name = verify(api.owner, name="Someone Else")
    assert wrong_pin.json() == wrong_name.json() == {"authenticated": False, "error": "Identity could not be verified"}
