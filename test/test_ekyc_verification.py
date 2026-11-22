"""Offline e-KYC XML verification tests. Synthetic data only; assertions and output
use reason codes, never personal values or the share code."""
import copy
import io
from datetime import datetime, timedelta, timezone

import pytest
from lxml import etree

from ekyc_fixtures import (
    SHARE_CODE, build_xml, make_signer, make_zip, make_zipcrypto_zip, sign_xml,
)
from middleware import aadhaar_ekyc_xml as ekyc, ekyc_check, app as middleware_app
from qr_fixtures import VALID_AADHAAR, VALID_AADHAAR_DASHED
from test_secure_verification import api, NAME, DOB, GENDER  # noqa: F401  (fixture reuse)

LAST4 = VALID_AADHAAR[-4:]
NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def signer():
    return make_signer()


@pytest.fixture(scope="module")
def other_signer():
    return make_signer()


def signed(signer, **kwargs):
    key, certificate = signer
    options = {"last4": LAST4}
    options.update({k: v for k, v in kwargs.items() if k in ("name", "dob", "gender", "last4", "moment", "naive_ist")})
    algorithm = {k: v for k, v in kwargs.items() if k in ("algorithm", "digest")}
    return sign_xml(build_xml(**options), key, certificate, **algorithm)


def verify(xml, signer, now=NOW, settings=None):
    return ekyc.verify_ekyc_xml(xml, [signer[1]], settings or ekyc.load_settings({}), now)


def code_of(callable_):
    with pytest.raises(ekyc.EkycError) as error:
        callable_()
    return error.value.code


# ───────────── signature ─────────────

def test_valid_signed_xml_verifies(signer):
    details = verify(signed(signer), signer)
    assert (details["name"], details["dob"], details["gender"], details["aadhaar_last4"]) == ("Asha Rao", "05-03-1990", "F", LAST4)


def test_tampered_xml_is_rejected(signer):
    xml = signed(signer).replace(b"Asha Rao", b"Zed Rao")
    assert code_of(lambda: verify(xml, signer)) == "EKYC_SIGNATURE_INVALID"


def test_wrong_key_is_rejected_even_though_the_file_embeds_its_own_certificate(signer, other_signer):
    attacker_xml = signed(other_signer)  # signed by another key, its certificate inside the file
    assert code_of(lambda: verify(attacker_xml, signer)) == "EKYC_SIGNATURE_INVALID"


def test_no_pinned_certificate_fails_closed(signer):
    assert code_of(lambda: ekyc.verify_ekyc_xml(signed(signer), [], ekyc.load_settings({}), NOW)) == "CERTIFICATE_UNAVAILABLE"


def test_unsigned_document_is_rejected(signer):
    assert code_of(lambda: verify(build_xml(last4=LAST4), signer)) == "EKYC_SIGNATURE_MISSING"


def test_multiple_signatures_are_rejected(signer):
    root = etree.fromstring(signed(signer))
    signature = root.find(f"{{{ekyc.DS_NS}}}Signature")
    root.append(copy.deepcopy(signature))
    assert code_of(lambda: verify(etree.tostring(root), signer)) == "EKYC_SIGNATURE_MULTIPLE"


def test_signature_must_cover_the_whole_document(signer):
    wrapper = b"<Wrapper>" + signed(signer) + b"<Unsigned/></Wrapper>"
    assert code_of(lambda: verify(wrapper, signer)) == "EKYC_SIGNATURE_SCOPE"


def test_algorithm_allow_list_is_enforced_and_configurable(signer):
    # Validly signed with SHA-512: refused by the SHA-256-only default, accepted when configured.
    xml = signed(signer, algorithm="rsa-sha512", digest="sha512")
    assert code_of(lambda: verify(xml, signer)) == "EKYC_SIGNATURE_INVALID"
    allowed = ekyc.load_settings({"EKYC_ALLOWED_SIGNATURE_METHODS": "RSA_SHA512", "EKYC_ALLOWED_DIGESTS": "SHA512"})
    assert verify(xml, signer, settings=allowed)["aadhaar_last4"] == LAST4


def test_default_algorithms_are_sha256_only():
    settings = ekyc.load_settings({})
    assert [m.name for m in settings["signature_methods"]] == ["RSA_SHA256"]
    assert [d.name for d in settings["digests"]] == ["SHA256"]


def test_sha1_cannot_be_enabled_by_configuration():
    assert code_of(lambda: ekyc.load_settings({"EKYC_ALLOWED_SIGNATURE_METHODS": "RSA_SHA256,RSA_SHA1"})) == "EKYC_CONFIG_INVALID"
    assert code_of(lambda: ekyc.load_settings({"EKYC_ALLOWED_DIGESTS": "SHA1"})) == "EKYC_CONFIG_INVALID"


# ───────────── malformed ─────────────

@pytest.mark.parametrize("xml", [b"<OfflinePaperlessKyc referenceId=", b"not xml at all", b""])
def test_malformed_xml_is_rejected(signer, xml):
    assert code_of(lambda: verify(xml, signer)) == "EKYC_XML_MALFORMED"


def test_doctype_and_entities_are_rejected(signer):
    xml = b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "boom">]><a>&x;</a>'
    assert code_of(lambda: verify(xml, signer)) == "EKYC_XML_MALFORMED"


def test_unexpected_layout_is_rejected(signer):
    key, certificate = signer
    xml = sign_xml(
        f'<OfflinePaperlessKyc referenceId="{LAST4}{NOW:%Y%m%d%H%M%S}000"><UidData/></OfflinePaperlessKyc>'.encode(),
        key, certificate,
    )
    assert code_of(lambda: verify(xml, signer)) == "EKYC_LAYOUT_UNEXPECTED"


# ───────────── freshness ─────────────

def test_stale_file_is_rejected_and_window_is_configurable(signer):
    xml = signed(signer, moment=NOW - timedelta(days=5))
    assert code_of(lambda: verify(xml, signer)) == "EKYC_STALE"
    relaxed = ekyc.load_settings({"EKYC_MAX_AGE_HOURS": "200"})
    assert verify(xml, signer, settings=relaxed)["aadhaar_last4"] == LAST4
    assert verify(signed(signer, moment=NOW - timedelta(hours=71)), signer)["aadhaar_last4"] == LAST4


def test_future_dated_file_is_rejected_beyond_clock_skew(signer):
    assert code_of(lambda: verify(signed(signer, moment=NOW + timedelta(hours=1)), signer)) == "EKYC_FUTURE_DATED"
    assert verify(signed(signer, moment=NOW + timedelta(minutes=2)), signer)["aadhaar_last4"] == LAST4


def test_timestamp_without_timezone_is_treated_as_india_time(signer):
    # Wall-clock IST "now": accepted when read as +05:30, would be 5.5h in the future as UTC.
    assert verify(signed(signer, naive_ist=True), signer)["aadhaar_last4"] == LAST4
    utc_default = ekyc.load_settings({"EKYC_DEFAULT_TIMEZONE": "+00:00"})
    assert code_of(lambda: verify(signed(signer, naive_ist=True), signer, settings=utc_default)) == "EKYC_FUTURE_DATED"


def test_timezone_aware_timestamp_is_respected():
    parsed = ekyc.parse_generation_time("2026-01-01T10:00:00+00:00", timezone(timedelta(hours=5, minutes=30)))
    assert parsed.utcoffset() == timedelta(0)


# ───────────── ZIP ─────────────

def test_wrong_share_code_is_rejected(signer):
    zipped = make_zip(signed(signer))
    assert code_of(lambda: ekyc.read_xml_from_zip(zipped, "0000")) == "EKYC_ZIP_PASSWORD"
    assert code_of(lambda: ekyc.read_xml_from_zip(zipped, "12a4")) == "EKYC_SHARE_CODE_INVALID"
    assert ekyc.read_xml_from_zip(zipped, SHARE_CODE).startswith(b"<OfflinePaperlessKyc")


def test_zip_bomb_by_ratio_is_rejected():
    assert code_of(lambda: ekyc.read_xml_from_zip(make_zip(b"0" * (4 * 1024 * 1024)), SHARE_CODE)) == "EKYC_ZIP_BOMB"


def test_oversized_xml_is_rejected():
    assert code_of(lambda: ekyc.read_xml_from_zip(make_zip(b"0" * (6 * 1024 * 1024)), SHARE_CODE)) == "EKYC_ZIP_TOO_LARGE"


def test_oversized_zip_is_rejected():
    assert code_of(lambda: ekyc.read_xml_from_zip(b"0" * (ekyc.MAX_ZIP_BYTES + 1), SHARE_CODE)) == "EKYC_ZIP_TOO_LARGE"


def test_multiple_entries_are_rejected(signer):
    assert code_of(lambda: ekyc.read_xml_from_zip(make_zip(b"<a/>", extra={"second.xml": b"<b/>"}), SHARE_CODE)) == "EKYC_ZIP_ENTRIES"


@pytest.mark.parametrize("entry", ["../evil.xml", "dir/file.xml", "/abs.xml", "..\\evil.xml", "C:evil.xml"])
def test_path_traversal_entry_names_are_rejected(entry):
    assert code_of(lambda: ekyc.read_xml_from_zip(make_zip(b"<a/>", entry_name=entry), SHARE_CODE)) == "EKYC_ZIP_PATH"


def test_garbage_zip_is_rejected():
    assert code_of(lambda: ekyc.read_xml_from_zip(b"PK\x03\x04 not really a zip", SHARE_CODE)) == "EKYC_ZIP_INVALID"


def test_verify_ekyc_zip_returns_only_reason_code_on_failure(signer):
    result = ekyc.verify_ekyc_zip(make_zip(signed(signer)), "0000", [signer[1]])
    assert result == {"ok": False, "code": "EKYC_ZIP_PASSWORD", "sub": "BAD_PASSWORD"}


# ───────────── ZipCrypto (the real UIDAI shape) and sub-reasons ─────────────

def sub_of(callable_):
    with pytest.raises(ekyc.EkycError) as error:
        callable_()
    return error.value.code, error.value.sub


@pytest.mark.parametrize("data_descriptor", [False, True])
def test_zipcrypto_deflated_encrypted_entry_without_aes_extra_opens(signer, data_descriptor):
    # One DEFLATED entry, flag bit 0 set, standard ZipCrypto, NO AES extra field.
    import zipfile
    zipped = make_zipcrypto_zip(signed(signer), data_descriptor=data_descriptor)
    info = zipfile.ZipFile(io.BytesIO(zipped)).infolist()[0]
    assert (info.compress_type, info.flag_bits & 1, info.extra) == (8, 1, b"")
    assert ekyc.read_xml_from_zip(zipped, SHARE_CODE).startswith(b"<OfflinePaperlessKyc")


def test_zipcrypto_file_verifies_end_to_end(signer):
    result = ekyc.verify_ekyc_zip(make_zipcrypto_zip(signed(signer)), SHARE_CODE, [signer[1]])
    assert result["ok"] and result["details"]["aadhaar_last4"] == LAST4


def test_zipcrypto_wrong_share_code_is_reported_as_password_not_invalid(signer):
    zipped = make_zipcrypto_zip(signed(signer))
    outcomes = {sub_of(lambda c=code: ekyc.read_xml_from_zip(zipped, c)) for code in ("0000", "1234", "9999", "5555", "0001")}
    assert {code for code, _ in outcomes} == {"EKYC_ZIP_PASSWORD"}


def test_zipcrypto_check_byte_collision_still_reports_password():
    # About 1 in 256 wrong codes passes ZipCrypto's one-byte check and then fails to inflate.
    # Find such a code so the CHECK_FAILED path is exercised deterministically.
    xml = b"<a>" + bytes(range(256)) * 60 + b"</a>"
    zipped = make_zipcrypto_zip(xml)
    seen = set()
    for number in range(10000):
        code = f"{number:04d}"
        if code == SHARE_CODE:
            continue
        try:
            ekyc.read_xml_from_zip(zipped, code)
        except ekyc.EkycError as error:
            seen.add((error.code, error.sub))
        if ("EKYC_ZIP_PASSWORD", "CHECK_FAILED_WRONG_CODE_LIKELY") in seen:
            break
    assert ("EKYC_ZIP_PASSWORD", "CHECK_FAILED_WRONG_CODE_LIKELY") in seen
    assert {code for code, _ in seen} == {"EKYC_ZIP_PASSWORD"}


def test_sub_reasons_name_the_failing_rule(signer):
    assert sub_of(lambda: ekyc.read_xml_from_zip(b"junk", SHARE_CODE)) == ("EKYC_ZIP_INVALID", "NOT_A_ZIP")
    assert sub_of(lambda: ekyc.read_xml_from_zip(make_zip(b"<a/>", extra={"b.xml": b"<b/>"}), SHARE_CODE)) == ("EKYC_ZIP_ENTRIES", "ENTRY_COUNT")
    assert sub_of(lambda: ekyc.read_xml_from_zip(make_zip(b"<a/>", entry_name="../x.xml"), SHARE_CODE)) == ("EKYC_ZIP_PATH", "PATH_RULE")
    assert sub_of(lambda: ekyc.read_xml_from_zip(make_zip(b"0" * (6 * 1024 * 1024)), SHARE_CODE)) == ("EKYC_ZIP_TOO_LARGE", "SIZE_RULE")
    assert sub_of(lambda: ekyc.read_xml_from_zip(make_zip(b"0" * (4 * 1024 * 1024)), SHARE_CODE)) == ("EKYC_ZIP_BOMB", "RATIO_RULE")
    assert sub_of(lambda: ekyc.read_xml_from_zip(make_zip(b"<a/>"), "12")) == ("EKYC_SHARE_CODE_INVALID", "SHARE_CODE_FORMAT")


def test_strong_encryption_flag_is_reported_as_unsupported():
    import struct
    zipped = bytearray(make_zipcrypto_zip(b"<a/>"))
    flags = struct.unpack_from("<H", zipped, 6)[0] | 0x40
    struct.pack_into("<H", zipped, 6, flags)
    central = zipped.index(b"PK")
    struct.pack_into("<H", zipped, central + 8, flags)
    assert sub_of(lambda: ekyc.read_xml_from_zip(bytes(zipped), SHARE_CODE)) == ("EKYC_ZIP_INVALID", "ENCRYPTION_UNSUPPORTED")


# ───────────── API ─────────────

def register_xml(api, zipped, share_code=SHARE_CODE, **overrides):
    data = {
        "name": NAME, "dob": DOB, "aadhaar_id": VALID_AADHAAR, "pin": "1234", "mobile": "9876543210",
        "gender": "Female", "verification_method": "offline_xml", "share_code": share_code,
    }
    data.update(overrides)
    return api.owner.post("/aadhaar/register", data=data, files={"ekyc_zip": ("offline.zip", zipped, "application/zip")})


@pytest.fixture
def xml_api(api, signer):
    api.monkeypatch.setattr(middleware_app, "pinned_certificates", lambda: [signer[1]])
    return api


def test_api_valid_offline_xml_is_verified_and_written_with_canonical_id(xml_api, signer):
    response = register_xml(xml_api, make_zip(signed(signer)))
    assert response.status_code == 200
    assert response.json()["result"] == "verified"
    assert response.json()["document_authenticity"] == "UIDAI_SIGNATURE_VERIFIED"
    assert xml_api.writes == [(VALID_AADHAAR_DASHED, NAME)]


def test_api_name_mismatch_is_rejected_with_reason_code(xml_api, signer):
    response = register_xml(xml_api, make_zip(signed(signer, name="Priya Nair")))
    assert response.status_code == 422
    assert response.json()["reason_codes"]["name"] == "NAME_MISMATCH"
    assert xml_api.writes == []


def test_api_tampered_wrong_key_stale_and_wrong_share_code_never_write(xml_api, signer, other_signer):
    cases = {
        "EKYC_SIGNATURE_INVALID": make_zip(signed(signer).replace(b"Asha Rao", b"Zed Rao")),
        "EKYC_STALE": make_zip(signed(signer, moment=NOW - timedelta(days=9))),
    }
    for code, zipped in cases.items():
        response = register_xml(xml_api, zipped)
        assert response.status_code == 422 and response.json()["reason_codes"] == {"document": code}
    assert register_xml(xml_api, make_zip(signed(other_signer))).json()["reason_codes"] == {"document": "EKYC_SIGNATURE_INVALID"}
    assert register_xml(xml_api, make_zip(signed(signer)), share_code="0000").json()["reason_codes"] == {"document": "EKYC_ZIP_PASSWORD"}
    assert xml_api.writes == []


def test_api_signed_file_with_missing_field_is_pending_and_off_chain(xml_api, signer):
    response = register_xml(xml_api, make_zip(signed(signer, gender="")))
    assert response.status_code == 202
    assert response.json()["result"] == "pending"
    assert xml_api.writes == []


def test_share_code_and_personal_data_never_appear_in_logs_or_error_bodies(xml_api, signer, caplog):
    mismatch_zip = make_zip(signed(signer, name="Zed Rao"))  # built before capture: signing is test-side
    valid_zip = make_zip(signed(signer))
    caplog.set_level("DEBUG")
    bodies = [
        register_xml(xml_api, mismatch_zip).text,
        register_xml(xml_api, valid_zip, share_code="0000").text,
        register_xml(xml_api, b"PK\x03\x04junk").text,
        register_xml(xml_api, valid_zip).text,
    ]
    combined = caplog.text + "".join(bodies)
    for secret in (SHARE_CODE, "0000", "Zed Rao", "Asha Rao", VALID_AADHAAR, VALID_AADHAAR_DASHED):
        assert secret not in combined


# ───────────── local command ─────────────

def test_local_command_prints_only_reason_codes_and_structure_names(signer, tmp_path, monkeypatch, capsys):
    path = tmp_path / "file.zip"
    path.write_bytes(make_zip(signed(signer)))
    monkeypatch.setattr(ekyc_check, "pinned_certificates", lambda: [signer[1]])
    monkeypatch.setattr("sys.stdin", io.StringIO(SHARE_CODE + "\n"))
    assert ekyc_check.main([str(path)]) == 0
    output = capsys.readouterr().out
    assert "OfflinePaperlessKyc [referenceId]" in output
    assert "Poi [dob,e,gender,m,name]" in output
    assert "verified-capable" in output
    for forbidden in (SHARE_CODE, "Asha Rao", "05-03-1990", LAST4):
        assert forbidden not in output


def test_local_command_opens_a_zipcrypto_file(signer, tmp_path, monkeypatch, capsys):
    path = tmp_path / "file.zip"
    path.write_bytes(make_zipcrypto_zip(signed(signer)))
    monkeypatch.setattr(ekyc_check, "pinned_certificates", lambda: [signer[1]])
    monkeypatch.setattr("sys.stdin", io.StringIO(SHARE_CODE + "\n"))
    assert ekyc_check.main([str(path)]) == 0
    output = capsys.readouterr().out
    assert "Poi [dob,e,gender,m,name]" in output and "verified-capable" in output


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"not a zip", "REASON: EKYC_ZIP_INVALID  SUBREASON: NOT_A_ZIP"),
        (None, "REASON: EKYC_ZIP_INVALID  SUBREASON: FILE_NOT_FOUND"),
    ],
)
def test_local_command_prints_non_pii_sub_reason_for_zip_failures(content, expected, tmp_path, monkeypatch, capsys):
    path = tmp_path / "secret-looking-name.zip"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr("sys.stdin", io.StringIO(SHARE_CODE + "\n"))
    assert ekyc_check.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert expected in output
    assert "secret-looking-name" not in output and SHARE_CODE not in output


@pytest.mark.parametrize(
    ("typed", "shape"),
    [
        ("", "length=0 digits=0 letters=0 other=0"),
        ("73", "length=2 digits=2 letters=0 other=0"),
        ("73912", "length=5 digits=5 letters=0 other=0"),
        ("73a1", "length=4 digits=3 letters=1 other=0"),
        ("73-1", "length=4 digits=3 letters=0 other=1"),
    ],
)
def test_local_command_describes_share_code_shape_without_echoing_it(typed, shape, signer, tmp_path, monkeypatch, capsys):
    path = tmp_path / "file.zip"
    path.write_bytes(make_zipcrypto_zip(signed(signer)))
    monkeypatch.setattr("sys.stdin", io.StringIO(typed + "\n"))
    assert ekyc_check.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert shape in output and "SUBREASON: SHARE_CODE_FORMAT" in output
    assert typed == "" or typed not in output.replace(shape, "")


def test_local_command_strips_stray_whitespace_from_the_share_code(signer, tmp_path, monkeypatch, capsys):
    path = tmp_path / "file.zip"
    path.write_bytes(make_zipcrypto_zip(signed(signer)))
    monkeypatch.setattr(ekyc_check, "pinned_certificates", lambda: [signer[1]])
    monkeypatch.setattr("sys.stdin", io.StringIO("  " + SHARE_CODE + " \r\n"))
    assert ekyc_check.main([str(path)]) == 0


def test_local_command_reports_reason_code_for_wrong_share_code(signer, tmp_path, monkeypatch, capsys):
    path = tmp_path / "file.zip"
    path.write_bytes(make_zip(signed(signer)))
    monkeypatch.setattr(ekyc_check, "pinned_certificates", lambda: [signer[1]])
    monkeypatch.setattr("sys.stdin", io.StringIO("0000\n"))
    assert ekyc_check.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert "REASON: EKYC_ZIP_PASSWORD  SUBREASON: BAD_PASSWORD" in output and "0000" not in output


# ───────────── signature diagnostics ─────────────

def test_signature_failure_sub_reasons_name_the_verifier_error_type(signer, other_signer):
    wrong_key = signed(other_signer)
    assert sub_of(lambda: verify(wrong_key, signer)) == ("EKYC_SIGNATURE_INVALID", "SIGNXML_InvalidSignature")
    sha512 = signed(signer, algorithm="rsa-sha512", digest="sha512")
    assert sub_of(lambda: verify(sha512, signer)) == ("EKYC_SIGNATURE_INVALID", "SIGNXML_InvalidInput")


def test_signature_diagnostics_report_algorithms_and_key_match_without_personal_data(signer, other_signer):
    xml = signed(signer)
    own = "\n".join(ekyc.describe_signature(xml, [signer[1]]))
    assert "rsa-sha256  (allowed: True)" in own and "sha256  (allowed: True)" in own
    assert "embedded key matches a pinned certificate: True" in own
    foreign = "\n".join(ekyc.describe_signature(signed(other_signer), [signer[1]]))
    assert "embedded key matches a pinned certificate: False" in foreign
    sha512 = "\n".join(ekyc.describe_signature(signed(signer, algorithm="rsa-sha512", digest="sha512"), [signer[1]]))
    assert "rsa-sha512  (allowed: False)" in sha512
    for secret in ("Asha Rao", "05-03-1990", LAST4, "Fake St"):
        assert secret not in own + foreign + sha512


def test_local_command_prints_diagnostics_and_signature_sub_reason(signer, other_signer, tmp_path, monkeypatch, capsys):
    path = tmp_path / "file.zip"
    path.write_bytes(make_zipcrypto_zip(signed(other_signer)))
    monkeypatch.setattr(ekyc_check, "pinned_certificates", lambda: [signer[1]])
    monkeypatch.setattr("sys.stdin", io.StringIO(SHARE_CODE + "\n"))
    assert ekyc_check.main([str(path)]) == 1
    output = capsys.readouterr().out
    assert "embedded key matches a pinned certificate: False" in output
    assert "REASON: EKYC_SIGNATURE_INVALID  SUBREASON: SIGNXML_InvalidSignature" in output
    for forbidden in (SHARE_CODE, "Asha Rao", "05-03-1990"):
        assert forbidden not in output


# ───────────── RSA-SHA1 signature + SHA-256 digest (real UIDAI shape), opt-in ─────────────

from ekyc_fixtures import sign_xml_sha1_real_shape  # noqa: E402

OPT_IN = {"EKYC_ALLOW_SHA1_SIGNATURE_WITH_SHA256_DIGEST": "true"}


def sha1_signed(signer, **kwargs):
    key, certificate = signer
    return sign_xml_sha1_real_shape(build_xml(last4=LAST4, **kwargs), key, certificate)


def test_sha1_signature_is_refused_by_default(signer):
    assert sub_of(lambda: verify(sha1_signed(signer), signer)) == ("EKYC_SIGNATURE_INVALID", "SHA1_NOT_ALLOWED")


def test_sha1_signature_with_sha256_digest_verifies_only_when_opted_in(signer):
    details = verify(sha1_signed(signer), signer, settings=ekyc.load_settings(OPT_IN))
    assert (details["name"], details["aadhaar_last4"]) == ("Asha Rao", LAST4)


def test_opt_in_still_requires_the_pinned_key_and_untampered_data(signer, other_signer):
    settings = ekyc.load_settings(OPT_IN)
    assert code_of(lambda: verify(sha1_signed(other_signer), signer, settings=settings)) == "EKYC_SIGNATURE_INVALID"
    tampered = sha1_signed(signer).replace(b"Asha Rao", b"Zed Rao")
    assert code_of(lambda: verify(tampered, signer, settings=settings)) == "EKYC_SIGNATURE_INVALID"


def test_sha1_digest_is_never_allowed_even_with_opt_in(signer):
    key, certificate = signer
    xml = sign_xml_sha1_real_shape(
        build_xml(last4=LAST4), key, certificate, digest_uri="http://www.w3.org/2000/09/xmldsig#sha1"
    )
    assert sub_of(lambda: verify(xml, signer, settings=ekyc.load_settings(OPT_IN))) == ("EKYC_SIGNATURE_INVALID", "SHA1_NOT_ALLOWED")


def test_opt_in_allows_only_the_sha256_digest_pairing(signer):
    key, certificate = signer
    xml = sign_xml_sha1_real_shape(
        build_xml(last4=LAST4), key, certificate, digest_uri="http://www.w3.org/2001/04/xmlenc#sha512"
    )
    settings = ekyc.load_settings({**OPT_IN, "EKYC_ALLOWED_DIGESTS": "SHA256,SHA512"})
    assert sub_of(lambda: verify(xml, signer, settings=settings)) == ("EKYC_SIGNATURE_INVALID", "SHA1_NOT_ALLOWED")


def test_sha1_still_cannot_be_enabled_through_the_algorithm_lists():
    assert code_of(lambda: ekyc.load_settings({"EKYC_ALLOWED_SIGNATURE_METHODS": "RSA_SHA1"})) == "EKYC_CONFIG_INVALID"
    assert code_of(lambda: ekyc.load_settings({"EKYC_ALLOWED_DIGESTS": "SHA1"})) == "EKYC_CONFIG_INVALID"


def test_opt_in_flag_parsing():
    assert ekyc.load_settings({})["allow_sha1_signature"] is False
    assert ekyc.load_settings({"EKYC_ALLOW_SHA1_SIGNATURE_WITH_SHA256_DIGEST": "false"})["allow_sha1_signature"] is False
    assert ekyc.load_settings(OPT_IN)["allow_sha1_signature"] is True
    assert code_of(lambda: ekyc.load_settings({"EKYC_ALLOW_SHA1_SIGNATURE_WITH_SHA256_DIGEST": "maybe"})) == "EKYC_CONFIG_INVALID"


def test_opt_in_verification_logs_a_warning_without_personal_data(signer, caplog):
    xml = sha1_signed(signer)
    settings = ekyc.load_settings(OPT_IN)
    caplog.set_level("DEBUG")
    verify(xml, signer, settings=settings)
    assert "RSA-SHA1 signature over a SHA-256 digest" in caplog.text
    for secret in ("Asha Rao", "05-03-1990", LAST4):
        assert secret not in caplog.text


def test_api_real_shape_file_is_rejected_by_default_and_verified_when_opted_in(xml_api, signer, monkeypatch):
    zipped = make_zipcrypto_zip(sha1_signed(signer))
    default = register_xml(xml_api, zipped)
    assert default.status_code == 422
    assert default.json()["reason_codes"] == {"document": "EKYC_SIGNATURE_INVALID"}
    assert xml_api.writes == []
    monkeypatch.setenv("EKYC_ALLOW_SHA1_SIGNATURE_WITH_SHA256_DIGEST", "true")
    opted_in = register_xml(xml_api, zipped)
    assert opted_in.status_code == 200 and opted_in.json()["result"] == "verified"
    assert xml_api.writes == [(VALID_AADHAAR_DASHED, NAME)]


# ───────────── Offline e-KYC ZIP is the only registration document ─────────────

from test_aadhaar_registration_upload import make_pdf  # noqa: E402
from middleware.eaadhaar_pdf import generate_eaadhaar_password  # noqa: E402


def base_form(**overrides):
    form = {"name": NAME, "dob": DOB, "aadhaar_id": VALID_AADHAAR, "pin": "1234", "mobile": "9876543210", "gender": "Female"}
    form.update(overrides)
    return {key: value for key, value in form.items() if value is not None}


def assert_requirement_rejected(response, code):
    body = response.json()
    assert response.status_code == 400
    assert body["reason_codes"] == {"document": code}
    assert body["result"] == "rejected" and body["success"] is False
    assert body["error"] == middleware_app.REGISTRATION_REQUIREMENT_MESSAGE  # generic: says nothing about what was sent


@pytest.mark.parametrize("method", [None, "", "secure_qr", "pdf"])
def test_pdf_only_request_is_rejected_by_default(xml_api, monkeypatch, method):
    monkeypatch.delenv("REGISTRATION_ALLOW_PDF", raising=False)
    form = base_form(verification_method=method)
    pdf = make_pdf("", generate_eaadhaar_password(NAME, DOB))
    response = xml_api.owner.post("/aadhaar/register", data=form, files={"aadhaar_document": ("doc.pdf", pdf, "application/pdf")})
    assert_requirement_rejected(response, "REGISTRATION_METHOD_UNSUPPORTED")
    assert xml_api.writes == []


def test_offline_xml_method_with_only_a_pdf_is_rejected(xml_api, monkeypatch):
    monkeypatch.delenv("REGISTRATION_ALLOW_PDF", raising=False)
    pdf = make_pdf("", generate_eaadhaar_password(NAME, DOB))
    response = xml_api.owner.post(
        "/aadhaar/register",
        data=base_form(verification_method="offline_xml", share_code=SHARE_CODE),
        files={"aadhaar_document": ("doc.pdf", pdf, "application/pdf")},
    )
    assert_requirement_rejected(response, "EKYC_ZIP_REQUIRED")


def test_missing_zip_is_rejected(xml_api):
    response = xml_api.owner.post("/aadhaar/register", data=base_form(verification_method="offline_xml", share_code=SHARE_CODE))
    assert_requirement_rejected(response, "EKYC_ZIP_REQUIRED")
    assert xml_api.writes == []


@pytest.mark.parametrize("share_code", [None, "", "   "])
def test_missing_share_code_is_rejected(xml_api, signer, share_code):
    response = xml_api.owner.post(
        "/aadhaar/register",
        data=base_form(verification_method="offline_xml", share_code=share_code),
        files={"ekyc_zip": ("offline.zip", make_zip(signed(signer)), "application/zip")},
    )
    assert_requirement_rejected(response, "EKYC_SHARE_CODE_REQUIRED")
    assert xml_api.writes == []


def test_zip_registration_succeeds_without_any_pdf_setting(xml_api, signer, monkeypatch):
    monkeypatch.delenv("REGISTRATION_ALLOW_PDF", raising=False)
    response = register_xml(xml_api, make_zipcrypto_zip(signed(signer)))
    assert response.status_code == 200 and response.json()["result"] == "verified"
    assert xml_api.writes == [(VALID_AADHAAR_DASHED, NAME)]


def test_pdf_path_is_restored_only_by_the_off_by_default_setting(xml_api, monkeypatch):
    monkeypatch.setenv("REGISTRATION_ALLOW_PDF", "true")
    monkeypatch.setattr(middleware_app, "verify_secure_qr", lambda *args: {"ok": False, "code": "SIGNATURE_INVALID"})
    pdf = make_pdf("", generate_eaadhaar_password(NAME, DOB))
    response = xml_api.owner.post("/aadhaar/register", data=base_form(), files={"aadhaar_document": ("doc.pdf", pdf, "application/pdf")})
    assert response.status_code == 422
    assert response.json()["reason_codes"] == {"document": "SIGNATURE_INVALID"}  # reached the PDF/QR logic


def test_result_panel_status_reports_signature_and_freshness_not_pdf_rows(xml_api, signer, other_signer):
    def checks(zipped, share_code=SHARE_CODE):
        body = register_xml(xml_api, zipped, share_code=share_code).json()
        assert "pdf_password" not in body["processing_status"] and "ocr" not in body["processing_status"]
        return {key: body["processing_status"][key] for key in ("zip", "signature", "freshness")}

    assert checks(make_zip(signed(other_signer))) == {"zip": "OPENED", "signature": "FAILED", "freshness": "NOT_CHECKED"}
    assert checks(make_zip(signed(signer, moment=NOW - timedelta(days=9)))) == {"zip": "OPENED", "signature": "VERIFIED", "freshness": "FAILED"}
    assert checks(make_zip(signed(signer)), share_code="0000") == {"zip": "FAILED", "signature": "NOT_CHECKED", "freshness": "NOT_CHECKED"}
    assert middleware_app._ekyc_processing_status(None) == {
        "extraction_method": "OFFLINE_EKYC_XML", "zip": "OPENED", "signature": "VERIFIED", "freshness": "OK",
    }
