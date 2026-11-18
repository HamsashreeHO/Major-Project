"""Experimental parser and verifier for UIDAI Secure QR Specification V0."""

from dataclasses import dataclass
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate


SIGNATURE_SIZE = 256
CONTACT_HASH_SIZE = 32
TEXT_FIELD_COUNT = 16
SUPPORTED_CODECS = ("gzip", "zlib", "raw-deflate")


class PayloadError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedV0:
    contact_indicator: int
    fields: tuple
    photo: bytes
    contact_hashes: tuple
    signature: bytes
    signed_data: bytes


def decimal_to_big_integer_bytes(decimal_payload):
    """Convert decimal digits to a positive BigInteger-style big-endian array."""
    if isinstance(decimal_payload, bytes):
        try:
            decimal_payload = decimal_payload.decode("ascii")
        except UnicodeDecodeError as error:
            raise PayloadError("QR integer must contain ASCII decimal digits") from error
    if not isinstance(decimal_payload, str):
        raise PayloadError("QR integer must be text or ASCII bytes")

    digits = "".join(decimal_payload.split())
    if not digits or not digits.isascii() or not digits.isdecimal():
        raise PayloadError("QR payload must contain only decimal digits")

    integer = int(digits, 10)
    if integer == 0:
        return b"\x00"

    length = (integer.bit_length() + 7) // 8
    encoded = integer.to_bytes(length, byteorder="big", signed=False)
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return encoded


def decompress_payload(encoded, codec):
    """Decompress with an explicit codec; the UIDAI V0 document omits which one."""
    if codec not in SUPPORTED_CODECS:
        raise PayloadError(f"Unsupported explicit compression codec: {codec}")

    try:
        if codec == "gzip":
            decompressor = zlib.decompressobj(31)
        elif codec == "zlib":
            decompressor = zlib.decompressobj(15)
        else:
            decompressor = zlib.decompressobj(-15)
        decoded = decompressor.decompress(encoded)
        decoded += decompressor.flush()
    except (OSError, EOFError, zlib.error) as error:
        raise PayloadError(f"Payload is not valid {codec} data") from error

    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise PayloadError(f"Payload is incomplete or has trailing data for {codec}")
    return decoded


def parse_decompressed_payload(data):
    """Parse the documented delimiter fields and fixed-size trailing values."""
    if not isinstance(data, bytes):
        raise PayloadError("Decompressed payload must be bytes")

    fields = []
    cursor = 0
    for _ in range(TEXT_FIELD_COUNT):
        delimiter = data.find(b"\xff", cursor)
        if delimiter < 0:
            raise PayloadError("Payload does not contain all 16 delimited text fields")
        fields.append(data[cursor:delimiter].decode("iso-8859-1"))
        cursor = delimiter + 1

    if fields[0] not in ("0", "1", "2", "3"):
        raise PayloadError("Contact-presence indicator must be 0, 1, 2, or 3")
    indicator = int(fields[0])
    hash_count = 2 if indicator == 3 else (1 if indicator in (1, 2) else 0)
    trailing_size = SIGNATURE_SIZE + hash_count * CONTACT_HASH_SIZE
    if len(data) < cursor + trailing_size:
        raise PayloadError("Payload is too short for its documented hashes and signature")

    trailing_start = len(data) - trailing_size
    photo = data[cursor:trailing_start]
    if not photo:
        raise PayloadError("Payload does not contain photograph bytes")

    hash_start = trailing_start
    contact_hashes = tuple(
        data[hash_start + offset:hash_start + offset + CONTACT_HASH_SIZE]
        for offset in range(0, hash_count * CONTACT_HASH_SIZE, CONTACT_HASH_SIZE)
    )
    signature = data[-SIGNATURE_SIZE:]
    return ParsedV0(
        contact_indicator=indicator,
        fields=tuple(fields),
        photo=photo,
        contact_hashes=contact_hashes,
        signature=signature,
        signed_data=data[:-SIGNATURE_SIZE],
    )


def load_certificate_public_key(certificate_bytes):
    """Load an X.509 certificate key only; this does not build or validate trust."""
    try:
        try:
            certificate = load_der_x509_certificate(certificate_bytes)
        except ValueError:
            certificate = load_pem_x509_certificate(certificate_bytes)
    except ValueError as error:
        raise PayloadError("Certificate is neither valid DER nor PEM X.509") from error

    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PayloadError("Version 0 SHA256withRSA requires an RSA public key")
    return public_key


def verify_sha256_with_rsa(parsed, public_key):
    """Verify Java SHA256withRSA semantics (RSASSA-PKCS1-v1_5 with SHA-256)."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PayloadError("SHA256withRSA requires an RSA public key")
    if len(parsed.signature) != SIGNATURE_SIZE:
        return False
    if public_key.key_size != SIGNATURE_SIZE * 8:
        raise PayloadError("Version 0 specifies a fixed 256-byte RSA signature")

    try:
        public_key.verify(
            parsed.signature,
            parsed.signed_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True
