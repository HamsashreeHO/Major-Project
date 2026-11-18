"""Aadhaar number validation and field matching (no I/O, no logging of values)."""
import re
import unicodedata
from datetime import datetime
from difflib import SequenceMatcher

_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

NAME_MATCH_THRESHOLD = 0.85
_DOB_FORMATS = ("%d-%m-%Y", "%d/%m/%Y", "%d.%m.%Y", "%Y-%m-%d", "%Y/%m/%d")
_GENDERS = {
    "m": "male", "male": "male", "f": "female", "female": "female",
    "t": "other", "transgender": "other", "trans": "other", "other": "other",
}


def verhoeff_valid(number):
    checksum = 0
    for index, digit in enumerate(reversed(number)):
        checksum = _D[checksum][_P[index % 8][int(digit)]]
    return checksum == 0


def verhoeff_check_digit(number):
    checksum = 0
    for index, digit in enumerate(reversed(number)):
        checksum = _D[checksum][_P[(index + 1) % 8][int(digit)]]
    return str(_INV[checksum])


def normalize_aadhaar(value):
    """Strip spaces/dashes and validate. Returns 12 digits or raises ValueError."""
    text = str(value or "")
    if not re.fullmatch(r"[0-9 \-]+", text):
        raise ValueError("INVALID_AADHAAR")
    digits = re.sub(r"[ \-]", "", text)
    if not re.fullmatch(r"[2-9][0-9]{11}", digits) or not verhoeff_valid(digits):
        raise ValueError("INVALID_AADHAAR")
    return digits


def format_aadhaar(digits):
    """Canonical key used on chain and in local records: XXXX-XXXX-XXXX."""
    return f"{digits[0:4]}-{digits[4:8]}-{digits[8:12]}"


def canonical_aadhaar(value):
    return format_aadhaar(normalize_aadhaar(value))


def _normalize_name(value):
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return " ".join(re.sub(r"[^\w]+", " ", text, flags=re.UNICODE).replace("_", " ").split())


def _name_score(left, right):
    left, right = _normalize_name(left), _normalize_name(right)
    if not left or not right:
        return 0.0
    plain = SequenceMatcher(None, left, right).ratio()
    ordered = SequenceMatcher(None, " ".join(sorted(left.split())), " ".join(sorted(right.split()))).ratio()
    return max(plain, ordered)


def _parse_dob(value):
    text = str(value or "").strip()
    if re.fullmatch(r"\d{4}", text):
        return text
    for date_format in _DOB_FORMATS:
        try:
            return datetime.strptime(text, date_format).date().isoformat()
        except ValueError:
            pass
    return None


def _gender(value):
    return _GENDERS.get(re.sub(r"[^a-z]", "", str(value or "").casefold()))


def match_signed_details(signed, name, dob, gender, aadhaar_digits):
    """Compare typed details with UIDAI-signed QR data.

    DOB, gender and the last four Aadhaar digits are exact; name is fuzzy.
    Returns {"result": verified|pending|rejected, "reason_codes": {field: code}}.
    """
    codes = {}

    signed_name = signed.get("name")
    if not signed_name:
        codes["name"] = "NAME_UNAVAILABLE"
    else:
        codes["name"] = "OK" if _name_score(signed_name, name) >= NAME_MATCH_THRESHOLD else "NAME_MISMATCH"

    signed_dob, typed_dob = _parse_dob(signed.get("dob")), _parse_dob(dob)
    if signed_dob is None:
        codes["dob"] = "DOB_UNAVAILABLE"
    elif typed_dob is None:
        codes["dob"] = "DOB_MISMATCH"
    else:
        # A year-only signed value is compared on the year alone.
        left, right = (signed_dob[:4], typed_dob[:4]) if len(signed_dob) == 4 else (signed_dob, typed_dob)
        codes["dob"] = "OK" if left == right else "DOB_MISMATCH"

    signed_gender, typed_gender = _gender(signed.get("gender")), _gender(gender)
    if signed_gender is None:
        codes["gender"] = "GENDER_UNAVAILABLE"
    else:
        codes["gender"] = "OK" if signed_gender == typed_gender else "GENDER_MISMATCH"

    last4 = signed.get("aadhaar_last4")
    if not last4:
        codes["aadhaar_id"] = "AADHAAR_UNAVAILABLE"
    else:
        codes["aadhaar_id"] = "OK" if str(aadhaar_digits)[-4:] == last4 else "AADHAAR_MISMATCH"

    if any(code.endswith("_MISMATCH") for code in codes.values()):
        result = "rejected"
    elif all(code == "OK" for code in codes.values()):
        result = "verified"
    else:
        result = "pending"
    return {"result": result, "reason_codes": codes}
