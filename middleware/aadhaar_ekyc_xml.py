"""Offline e-KYC XML verification (ZIP + share code).

Checked against ONE real UIDAI file (ZipCrypto ZIP, RSA-SHA1 signature over a SHA-256
digest, pinned 2026 certificate): ZIP, signature, freshness and field presence pass. Field
*value* formats (dob/gender) matched against typed details are covered by synthetic tests
only. Other file variants and certificate rotations are untested.

Pipeline: safe ZIP open (size/entry/path/ratio guards, AES via pyzipper, share code
as password) -> hardened XML parse -> exactly one enveloped signature that covers the
whole document -> signxml verification against the PINNED certificates only (never a
key or certificate from the file) -> data taken ONLY from what signxml returns as
signed -> freshness check on the generation time.

Failures return only reason codes. The share code and personal data are never logged
and never placed in exception messages.

Settings (environment, read at call time):
  EKYC_MAX_AGE_HOURS            default 72
  EKYC_DEFAULT_TIMEZONE         default +05:30 (for timestamps without a timezone)
  EKYC_CLOCK_SKEW_SECONDS       default 300
  EKYC_ALLOWED_SIGNATURE_METHODS default RSA_SHA256   (signxml SignatureMethod names)
  EKYC_ALLOWED_DIGESTS           default SHA256        (signxml DigestAlgorithm names)
  EKYC_ALLOW_SHA1_SIGNATURE_WITH_SHA256_DIGEST  default false (opt-in)
SHA-1 and HMAC names are refused in the lists above even if configured. The single
opt-in flag allows exactly one combination, because real UIDAI Offline e-KYC files use
it: an RSA-SHA1 *signature method* over a SHA-256 *digest*. SHA-1 digests are never
allowed, and the pinned-certificate-only rule is unchanged.
"""
import io
import logging
import os
import re
import zipfile
import zlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pyzipper
from lxml import etree
from signxml import CanonicalizationMethod, DigestAlgorithm, SignatureConfiguration, SignatureMethod, XMLVerifier

logger = logging.getLogger(__name__)

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
SHA256_DIGEST_URI = "http://www.w3.org/2001/04/xmlenc#sha256"
MAX_ZIP_BYTES = 5 * 1024 * 1024
MAX_XML_BYTES = 5 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
READ_CHUNK = 64 * 1024
DEFAULT_MAX_AGE_HOURS = 72.0
DEFAULT_TIMEZONE = "+05:30"
DEFAULT_SKEW_SECONDS = 300.0
DEFAULT_SIGNATURE_METHODS = "RSA_SHA256"
DEFAULT_DIGESTS = "SHA256"


class EkycError(Exception):
    """code = reason code; sub = optional non-PII sub-reason for diagnostics."""

    def __init__(self, code, sub=None):
        super().__init__(code)
        self.code = code
        self.sub = sub


# ───────────── settings ─────────────

def _timezone(value):
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", str(value).strip())
    if not match:
        raise EkycError("EKYC_CONFIG_INVALID")
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return timezone(delta if match.group(1) == "+" else -delta)


def _enum_set(enum, raw):
    members = set()
    for name in str(raw).split(","):
        name = name.strip().upper()
        if not name or "SHA1" in name or name.startswith("HMAC") or name not in enum.__members__:
            raise EkycError("EKYC_CONFIG_INVALID")
        members.add(enum[name])
    if not members:
        raise EkycError("EKYC_CONFIG_INVALID")
    return frozenset(members)


def _flag(value):
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    raise EkycError("EKYC_CONFIG_INVALID")


def load_settings(environ=None):
    env = os.environ if environ is None else environ
    try:
        max_age = float(env.get("EKYC_MAX_AGE_HOURS", DEFAULT_MAX_AGE_HOURS))
        skew = float(env.get("EKYC_CLOCK_SKEW_SECONDS", DEFAULT_SKEW_SECONDS))
    except ValueError:
        raise EkycError("EKYC_CONFIG_INVALID") from None
    if max_age <= 0 or skew < 0:
        raise EkycError("EKYC_CONFIG_INVALID")
    allow_sha1_signature = _flag(env.get("EKYC_ALLOW_SHA1_SIGNATURE_WITH_SHA256_DIGEST", "false"))
    signature_methods = _enum_set(SignatureMethod, env.get("EKYC_ALLOWED_SIGNATURE_METHODS", DEFAULT_SIGNATURE_METHODS))
    if allow_sha1_signature:
        signature_methods = signature_methods | {SignatureMethod.RSA_SHA1}
    return {
        "allow_sha1_signature": allow_sha1_signature,
        "max_age": timedelta(hours=max_age),
        "skew": timedelta(seconds=skew),
        "timezone": _timezone(env.get("EKYC_DEFAULT_TIMEZONE", DEFAULT_TIMEZONE)),
        "signature_methods": signature_methods,
        "digests": _enum_set(DigestAlgorithm, env.get("EKYC_ALLOWED_DIGESTS", DEFAULT_DIGESTS)),
    }


# ───────────── ZIP ─────────────

WZ_AES_METHOD = 99
STORED, DEFLATED = 0, 8


def _unsafe_name(name):
    return (
        name.startswith(("/", "\\"))
        or "/" in name or "\\" in name or ".." in name or ":" in name or "\x00" in name
    )


def _read_limited(entry):
    chunks, total = [], 0
    while True:
        chunk = entry.read(READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_XML_BYTES:  # header lied about the size
            raise EkycError("EKYC_ZIP_BOMB", "RATIO_RULE")
        chunks.append(chunk)


def read_xml_from_zip(data, share_code):
    """Return the single XML entry's bytes.

    The stdlib parses the archive and opens standard ZipCrypto entries (what UIDAI
    files use); pyzipper is used only for WinZip-AES entries. Raises
    EkycError(code, sub_reason); neither carries the share code or file content.
    """
    if len(data) > MAX_ZIP_BYTES:
        raise EkycError("EKYC_ZIP_TOO_LARGE", "SIZE_RULE")
    if not re.fullmatch(r"[0-9]{4}", str(share_code or "")):
        raise EkycError("EKYC_SHARE_CODE_INVALID", "SHARE_CODE_FORMAT")
    password = str(share_code).encode("ascii")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError):
        raise EkycError("EKYC_ZIP_INVALID", "NOT_A_ZIP") from None
    with archive:
        infos = archive.infolist()
        if len(infos) != 1:
            raise EkycError("EKYC_ZIP_ENTRIES", "ENTRY_COUNT")
        info = infos[0]
        if info.is_dir() or _unsafe_name(info.filename):
            raise EkycError("EKYC_ZIP_PATH", "PATH_RULE")
        if info.file_size > MAX_XML_BYTES:
            raise EkycError("EKYC_ZIP_TOO_LARGE", "SIZE_RULE")
        if info.file_size > max(info.compress_size, 1) * MAX_COMPRESSION_RATIO:
            raise EkycError("EKYC_ZIP_BOMB", "RATIO_RULE")
        if info.flag_bits & 0x40:  # strong (PKWARE) encryption
            raise EkycError("EKYC_ZIP_INVALID", "ENCRYPTION_UNSUPPORTED")
        encrypted = bool(info.flag_bits & 0x1)
        try:
            if info.compress_type == WZ_AES_METHOD:
                with pyzipper.AESZipFile(io.BytesIO(data)) as aes_archive:
                    aes_archive.setpassword(password)
                    with aes_archive.open(info.filename) as entry:
                        return _read_limited(entry)
            if info.compress_type not in (STORED, DEFLATED):
                raise EkycError("EKYC_ZIP_INVALID", "COMPRESSION_UNSUPPORTED")
            with archive.open(info, pwd=password if encrypted else None) as entry:
                return _read_limited(entry)
        except EkycError:
            raise
        except RuntimeError as error:
            if "password" in str(error).lower():
                raise EkycError("EKYC_ZIP_PASSWORD", "BAD_PASSWORD") from None
            raise EkycError("EKYC_ZIP_INVALID", "UNEXPECTED_RuntimeError") from None
        except (zipfile.BadZipFile, zlib.error, EOFError):
            # ZipCrypto's check byte lets ~1/256 wrong codes through; the failure then
            # surfaces as a CRC/inflate error. Treat that as a wrong share code.
            if encrypted:
                raise EkycError("EKYC_ZIP_PASSWORD", "CHECK_FAILED_WRONG_CODE_LIKELY") from None
            raise EkycError("EKYC_ZIP_INVALID", "CORRUPT_DATA") from None
        except NotImplementedError:
            raise EkycError("EKYC_ZIP_INVALID", "ENCRYPTION_UNSUPPORTED") from None
        except Exception as error:  # type name only: never the message
            raise EkycError("EKYC_ZIP_INVALID", f"UNEXPECTED_{type(error).__name__}") from None


# ───────────── XML ─────────────

def parse_xml(xml_bytes):
    """Hardened parse: no DTD/entities/network. Raises EKYC_XML_MALFORMED."""
    head = xml_bytes[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in xml_bytes.lower():
        raise EkycError("EKYC_XML_MALFORMED")
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False,
        dtd_validation=False, huge_tree=False, remove_pis=True,
    )
    try:
        return etree.fromstring(xml_bytes, parser)
    except (etree.XMLSyntaxError, ValueError):
        raise EkycError("EKYC_XML_MALFORMED") from None


def describe_structure(xml_bytes, max_lines=200):
    """Tag and attribute NAMES only (no values, no text). For layout debugging."""
    root = parse_xml(xml_bytes)
    lines = []

    def walk(element, depth):
        if len(lines) >= max_lines:
            return
        names = ",".join(sorted(etree.QName(key).localname for key in element.attrib))
        lines.append("  " * depth + etree.QName(element).localname + (f" [{names}]" if names else ""))
        for child in element:
            if isinstance(child.tag, str):
                walk(child, depth + 1)

    walk(root, 0)
    return lines


@contextmanager
def _signxml_logging_silenced():
    """signxml logs the canonicalized document (personal data) at DEBUG; never allow it."""
    signxml_logger = logging.getLogger("signxml")
    previous = signxml_logger.level
    signxml_logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        signxml_logger.setLevel(previous)


def _signed_root(root, certificates, settings):
    signatures = root.findall(f".//{{{DS_NS}}}Signature")
    if not signatures:
        raise EkycError("EKYC_SIGNATURE_MISSING")
    if len(signatures) > 1:
        raise EkycError("EKYC_SIGNATURE_MULTIPLE")
    signature = signatures[0]
    references = signature.findall(f".//{{{DS_NS}}}Reference")
    # Enveloped signature over the WHOLE document: direct child of the root, URI="".
    if signature.getparent() is not root or len(references) != 1 or references[0].get("URI") not in ("", None):
        raise EkycError("EKYC_SIGNATURE_SCOPE")
    if not certificates:
        raise EkycError("CERTIFICATE_UNAVAILABLE")

    # SHA-1 policy, checked before the verifier runs: never as a digest; as a signature
    # method only when explicitly opted in AND paired with a SHA-256 digest.
    method_element = signature.find(f".//{{{DS_NS}}}SignatureMethod")
    digest_element = signature.find(f".//{{{DS_NS}}}DigestMethod")
    method_uri = (method_element.get("Algorithm") if method_element is not None else "") or ""
    digest_uri = (digest_element.get("Algorithm") if digest_element is not None else "") or ""
    uses_sha1_signature = "sha1" in method_uri.lower()
    if "sha1" in digest_uri.lower() or (
        uses_sha1_signature and not (settings["allow_sha1_signature"] and digest_uri == SHA256_DIGEST_URI)
    ):
        raise EkycError("EKYC_SIGNATURE_INVALID", "SHA1_NOT_ALLOWED")

    config = SignatureConfiguration(
        require_x509=True,
        expect_references=1,
        signature_methods=settings["signature_methods"],
        digest_algorithms=settings["digests"],
        # XMLDSig 1.0 default for a reference with no explicit c14n transform (what
        # Java/Santuario signers, including UIDAI's, use).
        default_reference_c14n_method=CanonicalizationMethod.CANONICAL_XML_1_0,
    )
    failure_sub = None
    for certificate in certificates:
        try:
            with _signxml_logging_silenced():
                result = XMLVerifier().verify(root, x509_cert=certificate, expect_config=config)
        except Exception as error:  # signxml/lxml/cryptography errors; type only
            failure_sub = failure_sub or f"SIGNXML_{type(error).__name__}"
            logger.debug("ekyc signature attempt failed: %s", type(error).__name__)
            continue
        if isinstance(result, list):
            raise EkycError("EKYC_SIGNATURE_MULTIPLE")
        signed = result.signed_xml
        if not isinstance(signed.tag, str) or signed.tag != root.tag:
            raise EkycError("EKYC_SIGNATURE_SCOPE")
        if uses_sha1_signature:
            logger.warning("Offline e-KYC verified with an RSA-SHA1 signature over a SHA-256 digest (opt-in enabled)")
        return signed
    raise EkycError("EKYC_SIGNATURE_INVALID", failure_sub)


# ───────────── diagnostics (non-PII) ─────────────

_SAFE_URI = re.compile(r"[A-Za-z0-9:/#.\-_]{1,120}")


def _safe(value):
    return value if value and _SAFE_URI.fullmatch(value) else ("(absent)" if not value else "(unrecognized)")


def describe_signature(xml_bytes, certificates, settings=None):
    """Algorithm identifiers and certificate facts only; no names, dates of birth or values.

    The certificate embedded in the file is NEVER trusted: it is only compared with the
    pinned certificates so a mismatch can be diagnosed.
    """
    import base64
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    settings = settings or load_settings()
    root = parse_xml(xml_bytes)
    signature = root.find(f".//{{{DS_NS}}}Signature")
    if signature is None:
        return ["no Signature element"]

    def attribute(tag):
        element = signature.find(f".//{{{DS_NS}}}{tag}")
        return _safe(element.get("Algorithm") if element is not None else None)

    signature_method = attribute("SignatureMethod")
    digest_method = attribute("DigestMethod")
    reference = signature.find(f".//{{{DS_NS}}}Reference")
    lines = [
        f"signature method : {signature_method}  (allowed: {any(m.value == signature_method for m in settings['signature_methods'])})",
        f"digest method    : {digest_method}  (allowed: {any(d.value == digest_method for d in settings['digests'])})",
        f"canonicalization : {attribute('CanonicalizationMethod')}",
        "reference URI    : " + (_safe(reference.get("URI")) if reference is not None and reference.get("URI") else "(empty = whole document)"),
        "reference transforms: " + (", ".join(_safe(t.get("Algorithm")) for t in signature.iter(f"{{{DS_NS}}}Transform")) or "(none)"),
    ]
    node = signature.find(f".//{{{DS_NS}}}X509Certificate")
    try:
        embedded = x509.load_der_x509_certificate(base64.b64decode("".join((node.text or "").split())))
    except Exception:
        lines.append("embedded certificate: (absent or unreadable)")
        embedded = None

    def spki(certificate):
        return certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def fingerprint(certificate):
        return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()

    if embedded is not None:
        lines.append(
            f"embedded certificate: sha256={fingerprint(embedded)} "
            f"valid {embedded.not_valid_before_utc:%Y-%m-%d}..{embedded.not_valid_after_utc:%Y-%m-%d}"
        )
        lines.append(
            "embedded key matches a pinned certificate: "
            + str(any(spki(embedded) == spki(pinned) for pinned in certificates))
        )
    for index, pinned in enumerate(certificates, 1):
        lines.append(
            f"pinned certificate {index}: sha256={fingerprint(pinned)} "
            f"valid {pinned.not_valid_before_utc:%Y-%m-%d}..{pinned.not_valid_after_utc:%Y-%m-%d}"
        )
    return lines


# ───────────── generation time ─────────────

def parse_generation_time(value, default_tz):
    """ISO-8601 (with or without tz) or a digit timestamp: YYYYMMDDHHMMSS[mmm] or
    DDMMYYYYHHMMSS[mmm]. Naive times are interpreted in default_tz."""
    text = str(value or "").strip()
    moment = None
    if re.fullmatch(r"\d{14}(\d{3})?", text):
        for pattern in ("%Y%m%d%H%M%S", "%d%m%Y%H%M%S"):
            try:
                candidate = datetime.strptime(text[:14], pattern)
            except ValueError:
                continue
            if 2000 <= candidate.year <= 2100:
                moment = candidate
                break
    else:
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            moment = None
    if moment is None:
        raise EkycError("EKYC_TIMESTAMP_INVALID")
    return moment if moment.tzinfo else moment.replace(tzinfo=default_tz)


def _local_children(element, name):
    return [node for node in element.iter() if isinstance(node.tag, str) and etree.QName(node).localname == name]


def extract_signed_details(signed, settings, now):
    """Use ONLY the element signxml returned as signed."""
    reference_id = str(signed.get("referenceId", ""))
    if not re.fullmatch(r"\d{4}\d{14}(\d{3})?", reference_id):
        raise EkycError("EKYC_REFERENCE_INVALID")
    generated = parse_generation_time(reference_id[4:], settings["timezone"])
    current = now or datetime.now(timezone.utc)
    if generated - current > settings["skew"]:
        raise EkycError("EKYC_FUTURE_DATED")
    if current - generated > settings["max_age"]:
        raise EkycError("EKYC_STALE")
    poi = _local_children(signed, "Poi")
    if len(poi) != 1:
        raise EkycError("EKYC_LAYOUT_UNEXPECTED")
    return {
        "version": "OFFLINE_EKYC_XML",
        "name": (poi[0].get("name") or "").strip(),
        "dob": (poi[0].get("dob") or "").strip(),
        "gender": (poi[0].get("gender") or "").strip(),
        "aadhaar_last4": reference_id[:4],
    }


def verify_ekyc_xml(xml_bytes, certificates, settings=None, now=None):
    settings = settings or load_settings()
    root = parse_xml(xml_bytes)
    signed = _signed_root(root, certificates, settings)
    return extract_signed_details(signed, settings, now)


def verify_ekyc_zip(zip_bytes, share_code, certificates, settings=None, now=None):
    """Return {"ok": True, "details": {...}} or {"ok": False, "code": REASON}."""
    try:
        settings = settings or load_settings()
        xml_bytes = read_xml_from_zip(zip_bytes, share_code)
        return {"ok": True, "details": verify_ekyc_xml(xml_bytes, certificates, settings, now)}
    except EkycError as error:
        failure = {"ok": False, "code": error.code}
        if error.sub:
            failure["sub"] = error.sub
        return failure
