"""Local-only check of a real Offline e-KYC ZIP. Prints reason codes and the XML
structure (tag and attribute NAMES only) -- never values, never the share code.

    python -m middleware.ekyc_check path\\to\\offlineaadhaar.zip

The 4-digit share code is read from a hidden prompt (or one line of stdin when piped),
so it never appears in the command line or shell history. The file is not uploaded
anywhere and nothing is written to disk.
"""
import getpass
import re
import sys
from pathlib import Path

from middleware.aadhaar_ekyc_xml import (
    EkycError,
    MAX_ZIP_BYTES,
    describe_signature,
    describe_structure,
    load_settings,
    read_xml_from_zip,
    verify_ekyc_xml,
)
from middleware.aadhaar_secure_qr import pinned_certificates

REQUIRED_FIELDS = ("name", "dob", "gender", "aadhaar_last4")


def fail(code, sub=None):
    """Reason code and non-PII sub-reason only; never paths, values or the share code."""
    print(f"RESULT: rejected  REASON: {code}" + (f"  SUBREASON: {sub}" if sub else ""))
    return 1


def describe_share_code(code):
    """Non-secret shape of the entered code (counts only, never the characters)."""
    digits = sum(character.isdigit() and character.isascii() for character in code)
    letters = sum(character.isalpha() and character.isascii() for character in code)
    return f"length={len(code)} digits={digits} letters={letters} other={len(code) - digits - letters}"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m middleware.ekyc_check <zip-file>")
        return 2
    path = Path(argv[0])
    if not path.is_file():
        return fail("EKYC_ZIP_INVALID", "FILE_NOT_FOUND")  # checked before any prompt
    if path.stat().st_size > MAX_ZIP_BYTES:
        return fail("EKYC_ZIP_TOO_LARGE", "SIZE_RULE")
    share_code = getpass.getpass("Share code (hidden): ") if sys.stdin.isatty() else sys.stdin.readline().strip()

    share_code = share_code.strip()  # drop stray whitespace/CR from the prompt or a paste
    certificates = pinned_certificates()
    print(f"pinned certificates loaded: {len(certificates)}")
    if not re.fullmatch(r"[0-9]{4}", share_code):
        print(f"share code shape: {describe_share_code(share_code)} (expected length=4 digits=4)")
        return fail("EKYC_SHARE_CODE_INVALID", "SHARE_CODE_FORMAT")
    try:
        settings = load_settings()
        xml_bytes = read_xml_from_zip(path.read_bytes(), share_code)
    except EkycError as error:
        return fail(error.code, error.sub)
    except Exception as error:  # type name only
        return fail("EKYC_ZIP_INVALID", f"UNEXPECTED_{type(error).__name__}")
    finally:
        share_code = None  # drop the reference; it was never printed

    try:
        print("XML structure (names only):")
        for line in describe_structure(xml_bytes):
            print("  " + line)
    except EkycError as error:
        return fail(error.code, error.sub)

    try:
        print("signature diagnostics (identifiers and certificate facts only):")
        for line in describe_signature(xml_bytes, certificates, settings):
            print("  " + line)
    except EkycError as error:
        return fail(error.code, error.sub)

    try:
        details = verify_ekyc_xml(xml_bytes, certificates, settings)
    except EkycError as error:
        return fail(error.code, error.sub)
    missing = [field for field in REQUIRED_FIELDS if not details.get(field)]
    print("signature: VALID (pinned certificate); freshness: OK")
    print("fields present: " + ", ".join(field for field in REQUIRED_FIELDS if field not in missing))
    print("RESULT: " + ("pending  REASON: " + ",".join(f"{f.upper()}_UNAVAILABLE" for f in missing) if missing else "verified-capable"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
