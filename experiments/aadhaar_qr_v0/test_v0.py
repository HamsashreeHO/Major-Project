import hashlib
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from v0 import (
    PayloadError,
    decimal_to_big_integer_bytes,
    decompress_payload,
    load_certificate_public_key,
    parse_decompressed_payload,
    verify_sha256_with_rsa,
)


FIXTURE = Path(__file__).parent / "fixtures" / "official_sample_decimal.txt"
UIDAI_CERTIFICATE = (
    Path(__file__).resolve().parents[2]
    / "middleware"
    / "certificates"
    / "uidai_offline_publickey_2026.cer"
)


def test_official_sample_fixture_is_extracted_from_specification():
    decimal_payload = FIXTURE.read_text(encoding="ascii")
    digits = "".join(decimal_payload.split())
    assert len(digits) == 3143
    assert hashlib.sha256(digits.encode("ascii")).hexdigest() == (
        "24e9c3dfc0546525ba12f4dc3d3a36b622182b40bf6f8a6ef163f4d2d0eb3311"
    )
    assert len(decimal_to_big_integer_bytes(digits)) == 1306


def test_official_sample_does_not_decompress_with_diagnostic_candidates():
    encoded = decimal_to_big_integer_bytes(FIXTURE.read_text(encoding="ascii"))
    for codec in ("gzip", "zlib", "raw-deflate"):
        with pytest.raises(PayloadError):
            decompress_payload(encoded, codec)


def test_supplied_uidai_certificate_contains_rsa_2048_public_key():
    public_key = load_certificate_public_key(UIDAI_CERTIFICATE.read_bytes())

    assert public_key.key_size == 2048
    assert public_key.public_numbers().e == 65537


@pytest.mark.parametrize(
    ("decimal_payload", "expected"),
    [("0", b"\x00"), ("258", b"\x01\x02"), ("128", b"\x00\x80")],
)
def test_decimal_to_positive_big_integer_bytes(decimal_payload, expected):
    assert decimal_to_big_integer_bytes(decimal_payload) == expected


def test_decimal_conversion_rejects_non_decimal_input():
    with pytest.raises(PayloadError, match="decimal digits"):
        decimal_to_big_integer_bytes("123x")


def _synthetic_payload(private_key, indicator=3):
    values = [
        str(indicator),
        "123420260101000000000",
        "Ren\u00e9 Test",
        "01-01-2000",
        "X",
        "Care of",
        "District",
        "Landmark",
        "House",
        "Location",
        "123456",
        "Post Office",
        "State",
        "Street",
        "Sub district",
        "VTC",
    ]
    text = b"".join(value.encode("iso-8859-1") + b"\xff" for value in values)
    photo = b"\x00\x00\x00\x0cjP  \r\n\x87\nsynthetic-only"
    contact_hashes = b"E" * 32 + b"M" * 32 if indicator == 3 else b""
    signed_data = text + photo + contact_hashes
    signature = private_key.sign(
        signed_data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signed_data + signature


def test_synthetic_zlib_payload_parses_fields_and_verifies_signature():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    decompressed = _synthetic_payload(private_key)
    compressed = zlib.compress(decompressed)

    parsed = parse_decompressed_payload(decompress_payload(compressed, "zlib"))

    assert parsed.contact_indicator == 3
    assert parsed.fields[2] == "Ren\u00e9 Test"
    assert parsed.photo.startswith(b"\x00\x00\x00\x0cjP")
    assert parsed.contact_hashes == (b"E" * 32, b"M" * 32)
    assert parsed.signed_data == decompressed[:-256]
    assert verify_sha256_with_rsa(parsed, private_key.public_key()) is True


def test_modified_payload_fails_synthetic_signature():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = bytearray(_synthetic_payload(private_key))
    payload[4] ^= 0x01

    parsed = parse_decompressed_payload(bytes(payload))

    assert verify_sha256_with_rsa(parsed, private_key.public_key()) is False


def test_incorrect_signature_fails_synthetic_verification():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = bytearray(_synthetic_payload(private_key))
    payload[-1] ^= 0x01
    parsed = parse_decompressed_payload(bytes(payload))

    assert verify_sha256_with_rsa(parsed, private_key.public_key()) is False


def test_parser_rejects_missing_field_delimiter():
    with pytest.raises(PayloadError, match="16 delimited"):
        parse_decompressed_payload(b"0\xff" + b"x" * 300)


def test_parser_rejects_unsupported_indicator():
    payload = b"4\xff" + b"x\xff" * 15 + b"photo" + b"s" * 256
    with pytest.raises(PayloadError, match="indicator"):
        parse_decompressed_payload(payload)


def test_decompressor_requires_explicit_supported_codec():
    with pytest.raises(PayloadError, match="Unsupported explicit"):
        decompress_payload(b"synthetic", "auto")
