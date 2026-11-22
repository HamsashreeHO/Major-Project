"""Verify the UIDAI Secure QR of an e-Aadhaar PDF against pinned certificates.

Pipeline: decimal digits -> big integer -> minimal-length big-endian bytes ->
require gzip magic (1f 8b) -> gzip decompress -> signature is the last 256 bytes,
RSA PKCS#1 v1.5 / SHA-256 over everything before it. The signature is checked
BEFORE any field is parsed, and only keys from the pinned certificate files in
middleware/certificates/ are used (never a key taken from the document).

Failures return only a reason code. Personal data is never logged; debug output
contains only the digit count, the first two bytes and the version marker.
"""
import logging
import sys
import zlib
from pathlib import Path

import fitz
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from PIL import Image

from middleware.aadhaar_qr import _read_qr_codes
from middleware.document_upload import DocumentUploadError

logger = logging.getLogger(__name__)

CERT_DIR = Path(__file__).resolve().parent / "certificates"
SIGNATURE_SIZE = 256
MAX_QR_DIGITS = 12000
MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024
MIN_QR_DIGITS = 200
RENDER_DPIS = (300, 400, 500)
MAX_QR_PAGES = 2
SUPPORTED_VERSIONS = (b"V2", b"V5")
# Leading 0xFF-terminated text fields before the photo (marker included):
# version, email/mobile indicator, reference id, name, dob, gender, care-of,
# district, landmark, house, location, pincode, post office, state, street,
# sub-district, VTC. The photo (JPEG2000, may contain 0xFF) is never split.
# V5 is assumed to keep the V2 leading layout; confirm against a real V5 document.
DEMOGRAPHIC_FIELD_COUNT = 17

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(max(MAX_QR_DIGITS + 100, sys.get_int_max_str_digits() or 0))


class SecureQRError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def pinned_public_keys(cert_dir=CERT_DIR):
    return [
        certificate.public_key()
        for certificate in pinned_certificates(cert_dir)
        if isinstance(certificate.public_key(), rsa.RSAPublicKey)
    ]


def pinned_certificates(cert_dir=CERT_DIR):
    """X.509 certificates from the pinned certificate directory (DER or PEM)."""
    certificates = []
    for path in sorted(Path(cert_dir).iterdir()) if Path(cert_dir).is_dir() else []:
        if path.suffix.lower() not in (".cer", ".crt", ".pem"):
            continue
        data = path.read_bytes()
        try:
            try:
                certificate = load_der_x509_certificate(data)
            except ValueError:
                certificate = load_pem_x509_certificate(data)
        except ValueError:
            continue
        certificates.append(certificate)
    return certificates


def decode_payload(digits):
    """Decimal digit string -> decompressed bytes (signature still attached)."""
    if not digits.isascii() or not digits.isdigit() or len(digits) > MAX_QR_DIGITS:
        raise SecureQRError("QR_ENCODING_INVALID")
    number = int(digits)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    logger.debug("secure qr: digits=%d first_two=%s", len(digits), raw[:2].hex())
    if raw[:2] != b"\x1f\x8b":
        raise SecureQRError("QR_ENCODING_INVALID")
    inflater = zlib.decompressobj(wbits=31)
    try:
        data = inflater.decompress(raw, MAX_DECOMPRESSED_BYTES)
    except zlib.error as error:
        raise SecureQRError("QR_DECOMPRESS_FAILED") from error
    if inflater.unconsumed_tail or not inflater.eof:
        raise SecureQRError("QR_DECOMPRESS_FAILED")
    if len(data) <= SIGNATURE_SIZE:
        raise SecureQRError("QR_PARSE_ERROR")
    return data


def verify_signature(data, public_keys):
    signed, signature = data[:-SIGNATURE_SIZE], data[-SIGNATURE_SIZE:]
    for key in public_keys:
        try:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            continue
    return False


def parse_signed_data(data):
    """Parse demographics from already-verified data. Never splits the photo."""
    marker = data.split(b"\xff", 1)[0]
    logger.debug("secure qr: version=%r", marker[:4])
    if marker not in SUPPORTED_VERSIONS:
        raise SecureQRError("QR_UNSUPPORTED_VERSION")
    fields, position = [], 0
    for _ in range(DEMOGRAPHIC_FIELD_COUNT):
        end = data.find(b"\xff", position, len(data) - SIGNATURE_SIZE)
        if end < 0:
            raise SecureQRError("QR_PARSE_ERROR")
        fields.append(data[position:end].decode("iso-8859-1"))
        position = end + 1
    reference_id = fields[2]
    if len(reference_id) < 4 or not reference_id[:4].isdigit():
        raise SecureQRError("QR_PARSE_ERROR")
    return {
        "version": marker.decode("ascii"),
        "name": fields[3].strip(),
        "dob": fields[4].strip(),
        "gender": fields[5].strip(),
        "aadhaar_last4": reference_id[:4],
    }


def verify_qr_payload(digits, public_keys):
    if not public_keys:
        raise SecureQRError("CERTIFICATE_UNAVAILABLE")
    data = decode_payload(digits)
    if not verify_signature(data, public_keys):
        raise SecureQRError("SIGNATURE_INVALID")
    return parse_signed_data(data)


def _render_pages(path, password, dpi):
    document = fitz.open(Path(path))
    try:
        if document.is_encrypted and not (password and document.authenticate(password)):
            return
        for page in list(document)[:MAX_QR_PAGES]:
            pixmap = page.get_pixmap(matrix=fitz.Matrix(dpi / 72, dpi / 72), alpha=False)
            yield Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
    finally:
        document.close()


def find_qr_payloads(path, password=None):
    """Digit-only QR payloads, largest first. Retries at higher DPI if none decode."""
    for dpi in RENDER_DPIS:
        found = set()
        try:
            for image in _render_pages(path, password, dpi):
                with image:
                    try:
                        decoded = _read_qr_codes(image)
                    except DocumentUploadError:
                        continue
                    found.update(
                        text.strip() for text in decoded
                        if len(text.strip()) >= MIN_QR_DIGITS
                        and text.strip().isascii() and text.strip().isdigit()
                    )
        except (fitz.FileDataError, OSError, RuntimeError, ValueError):
            return []
        if found:
            return sorted(found, key=len, reverse=True)
    return []


def verify_secure_qr(path, password=None, public_keys=None):
    """Return {"ok": True, "details": {...}} or {"ok": False, "code": REASON}."""
    keys = pinned_public_keys() if public_keys is None else public_keys
    payloads = find_qr_payloads(path, password)
    if not payloads:
        return {"ok": False, "code": "QR_MISSING"}
    first_error = None
    for digits in payloads:  # largest first (it carries the photo)
        try:
            return {"ok": True, "details": verify_qr_payload(digits, keys)}
        except SecureQRError as error:
            first_error = first_error or error.code
    return {"ok": False, "code": first_error}
