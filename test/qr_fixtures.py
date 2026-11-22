"""Synthetic Secure QR fixtures. All keys are throwaway RSA keys generated in-test;
all personal data is fake. Nothing here is a UIDAI key, signature or real record."""
import gzip

import cv2
import fitz
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from middleware.aadhaar_validation import verhoeff_check_digit

# Fake but checksum-valid number (first digit 2-9, Verhoeff ok).
_BASE = "23456789012"
VALID_AADHAAR = _BASE + verhoeff_check_digit(_BASE)
VALID_AADHAAR_DASHED = f"{VALID_AADHAAR[:4]}-{VALID_AADHAAR[4:8]}-{VALID_AADHAAR[8:]}"
OTHER_BASE = "34567890123"
OTHER_AADHAAR = OTHER_BASE + verhoeff_check_digit(OTHER_BASE)
OTHER_AADHAAR_DASHED = f"{OTHER_AADHAAR[:4]}-{OTHER_AADHAAR[4:8]}-{OTHER_AADHAAR[8:]}"


def make_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_payload_digits(key, *, version=b"V2", name="Asha Rao", dob="05-03-1990",
                         gender="F", last4=None, tamper=False, gzip_magic=True):
    last4 = last4 or VALID_AADHAAR[-4:]
    fields = [
        version, b"3", (last4 + "20260101120000000").encode(), name.encode("iso-8859-1"),
        dob.encode(), gender.encode(), b"C/O Fake", b"District", b"Landmark", b"House",
        b"Location", b"560001", b"PostOffice", b"State", b"Street", b"SubDistrict", b"VTC",
    ]
    data = b"".join(field + b"\xff" for field in fields)
    data += b"\x00\xff\xd8\xff\xff\xff\x01" * 40      # photo-like bytes containing 0xFF
    data += b"\x11" * 64                              # contact hashes
    signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if tamper:  # change a signed byte after signing
        data = data.replace(name.encode("iso-8859-1"), b"Zed Rao", 1)
    compressed = gzip.compress(data + signature)
    if not gzip_magic:
        compressed = b"\x00\x00" + compressed[2:]
    return str(int.from_bytes(compressed, "big"))


def make_pdf_with_qr(digits=None, password=None, text=""):
    document = fitz.open()
    page = document.new_page()
    if text:
        page.insert_textbox(fitz.Rect(40, 40, 550, 300), text, fontsize=12)
    if digits:
        qr = cv2.QRCodeEncoder.create().encode(digits)
        qr = cv2.copyMakeBorder(qr, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
        qr = cv2.resize(qr, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST)
        ok, png = cv2.imencode(".png", np.asarray(qr, dtype=np.uint8))
        assert ok
        page.insert_image(fitz.Rect(60, 320, 420, 680), stream=png.tobytes())
    options = {}
    if password:
        options = {
            "encryption": fitz.PDF_ENCRYPT_AES_256,
            "owner_pw": "test-owner-password",
            "user_pw": password,
        }
    result = document.tobytes(**options)
    document.close()
    return result
