from functools import wraps
from datetime import datetime
import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException
from starlette.middleware.sessions import SessionMiddleware
from starlette.datastructures import UploadFile
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

CERT_PATH = (
    BASE_DIR / "certificates" /
    "uidai_offline_publickey_2026.cer"
)

from middleware.document_upload import (
    DocumentUploadError,
    configured_max_upload_bytes,
    validated_upload,
)
from middleware.aadhaar_ekyc_xml import MAX_ZIP_BYTES as EKYC_MAX_ZIP_BYTES, verify_ekyc_zip
from middleware.aadhaar_secure_qr import pinned_certificates, pinned_public_keys, verify_secure_qr
from middleware.aadhaar_validation import canonical_aadhaar, match_signed_details
from middleware.verification_state import VerificationState, session_binding
from middleware.eaadhaar_pdf import (
    compare_applicant_details,
    extract_eaadhaar_details,
    generate_eaadhaar_password,
)

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'crypto_core'))
from crypto_utils import (
    generate_identity_hash,
    generate_name_hash,
    sign_identity,
    sign_verification_message,
    verify_signature,
    verify_verification_signature,
)
from keys import load_or_generate_keys
from middleware.replay_protection import ReplayProtection
try:
    from .pin_reset import PinResetError, PinResetManager, normalize_mobile
    from .email_service import is_configured as email_is_configured, send_email
except ImportError:
    from pin_reset import PinResetError, PinResetManager, normalize_mobile
    from email_service import is_configured as email_is_configured, send_email

try:
    from .auth_store import (
        DEVELOPER_USNS,
        hash_aadhaar_pin,
        hash_password,
        load_accounts,
        load_aadhaar_pins,
        save_accounts,
        save_aadhaar_pins,
        verify_aadhaar_pin,
        verify_developer_password,
        verify_password,
    )
except ImportError:
    from auth_store import (
        DEVELOPER_USNS,
        hash_aadhaar_pin,
        hash_password,
        load_accounts,
        load_aadhaar_pins,
        save_accounts,
        save_aadhaar_pins,
        verify_aadhaar_pin,
        verify_developer_password,
        verify_password,
    )

app = FastAPI(title="Cross-Blockchain Middleware")
logger = logging.getLogger(__name__)

AADHAAR_FIELD_LABELS = {
    "name": "Name",
    "dob": "DOB",
    "gender": "Gender",
    "aadhaar_id": "Aadhaar number",
}

SESSION_SECRET_FILE = os.path.join(os.path.dirname(__file__), ".session_secret")
if not os.path.exists(SESSION_SECRET_FILE):
    with open(SESSION_SECRET_FILE, "x", encoding="utf-8") as secret_file:
        secret_file.write(secrets.token_hex(32))
with open(SESSION_SECRET_FILE, "r", encoding="utf-8") as secret_file:
    session_secret = secret_file.read().strip()

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    session_cookie="session",
    max_age=60 * 60 * 24 * 30,
    same_site="lax",
    https_only=False,
)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_roles(*allowed_roles):
    def decorator(view):
        @wraps(view)
        async def wrapped(request: Request, *args, **kwargs):
            user = request.session.get("user")
            if not user:
                return JSONResponse({"error": "Please sign in to continue"}, status_code=401)
            if user.get("role") not in allowed_roles:
                return JSONResponse({"error": "You do not have permission to access this service"}, status_code=403)
            return await view(request, *args, **kwargs)

        return wrapped

    return decorator


async def establish_session(request: Request, role, username, email, name=None):
    request.session.clear()
    request.session["sid"] = secrets.token_urlsafe(16)
    user = {
        "role": role,
        "username": username,
        "email": email,
        "name": name or username,
    }
    request.session["user"] = user
    return JSONResponse({"success": True, "user": user})


GENERIC_ERROR = "The request could not be completed"
GENERIC_IDENTITY_ERROR = "Identity could not be verified"
LOCKED_ERROR = "Too many attempts. Please try again later."
verification_state = VerificationState()


def server_error(context, error):
    # Log only the exception type: web3 errors can echo call arguments (Aadhaar IDs).
    logger.error("%s failed: %s", context, type(error).__name__)
    return JSONResponse({"error": GENERIC_ERROR}, status_code=500)


def session_email(request):
    return str((request.session.get("user") or {}).get("email", "")).strip().lower()


def owns_aadhaar(request, aadhaar_id):
    """A signed-in applicant may only use the Aadhaar ID they registered."""
    record = load_aadhaar_pins().get(aadhaar_id) or {}
    owner = str(record.get("email", "")).strip().lower()
    email = session_email(request)
    return bool(owner and email and hmac.compare_digest(owner, email))


def lockout_keys(request, aadhaar_id):
    return (f"id:{aadhaar_id}", f"user:{session_email(request)}")


def binding_for(request, aadhaar_id):
    return session_binding(request.session.setdefault("sid", secrets.token_urlsafe(16)), session_email(request), aadhaar_id)


# ─────────────────────────────────────────
# Connect to Ganache
# ─────────────────────────────────────────
w3 = AsyncWeb3(AsyncHTTPProvider("http://127.0.0.1:8545"))
ganache_connected = False
default_account = None


async def initialize_blockchain():
    global ganache_connected, default_account
    ganache_connected = await w3.is_connected()
    if ganache_connected:
        print("   ✅ Connected to Ganache blockchain!")
        accounts = await w3.eth.accounts
        if accounts:
            default_account = accounts[0]
            w3.eth.default_account = default_account
    else:
        print("   ❌ Could not connect to Ganache!")


@app.on_event("startup")
async def startup_event():
    await initialize_blockchain()


# ─────────────────────────────────────────
# Load contract addresses
# ─────────────────────────────────────────
ADDRESSES_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'crypto_core', 'contract_addresses.json'
)
with open(ADDRESSES_FILE, encoding="utf-8") as f:
    addresses = json.load(f)

AADHAAR_ADDRESS = addresses["AadhaarRegistry"]
PASSPORT_ADDRESS = addresses["PassportRegistry"]

# ─────────────────────────────────────────
# Load contract ABIs from build folder
# ─────────────────────────────────────────
BUILD_DIR = os.path.join(os.path.dirname(__file__), '..', 'build', 'contracts')

with open(os.path.join(BUILD_DIR, 'AadhaarRegistry.json'), encoding="utf-8") as f:
    AADHAAR_ABI = json.load(f)["abi"]

with open(os.path.join(BUILD_DIR, 'PassportRegistry.json'), encoding="utf-8") as f:
    PASSPORT_ABI = json.load(f)["abi"]

# ─────────────────────────────────────────
# Create contract instances
# ─────────────────────────────────────────
aadhaar_contract = w3.eth.contract(
    address=AsyncWeb3.to_checksum_address(AADHAAR_ADDRESS),
    abi=AADHAAR_ABI,
)
passport_contract = w3.eth.contract(
    address=AsyncWeb3.to_checksum_address(PASSPORT_ADDRESS),
    abi=PASSPORT_ABI,
)

# ─────────────────────────────────────────
# Load shared ECDSA keys
# ─────────────────────────────────────────
private_key, public_key = load_or_generate_keys()
replay_protection = ReplayProtection()
pin_reset_manager = PinResetManager()
SMS_DEFAULT_COUNTRY_CODE = os.getenv("SMS_DEFAULT_COUNTRY_CODE", "+91")


def find_pin_record_by_email(email):
    matches = []
    for aadhaar_id, record in load_aadhaar_pins().items():
        record_email = str(record.get("email", "")).strip().lower()
        if record_email and hmac.compare_digest(record_email, email):
            matches.append((aadhaar_id, record))
    return matches


async def deliver_pin_reset_otp(email, otp):
    try:
        await asyncio.to_thread(
            send_email,
            email,
            "IdentiGate PIN reset OTP",
            f"Your IdentiGate PIN reset OTP is {otp}. It expires in 5 minutes.",
        )
    except Exception:
        return False
    return True


@app.post("/pin-reset/request")
async def request_pin_reset(request: Request):
    if not email_is_configured():
        return JSONResponse({"error": "PIN reset email is not configured on the server"}, status_code=503)

    data = await request.json() or {}
    email = str(data.get("email", "")).strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return JSONResponse({"error": "Enter a valid email address"}, status_code=400)

    matches = find_pin_record_by_email(email)
    aadhaar_id = matches[0][0] if len(matches) == 1 else None
    try:
        flow_id, otp = pin_reset_manager.start(aadhaar_id, email)
    except PinResetError as error:
        return JSONResponse({"error": str(error)}, status_code=error.status_code)

    if otp:
        await deliver_pin_reset_otp(email, otp)
    return JSONResponse({
        "success": True,
        "flow_id": flow_id,
        "message": "If the email matches a registered applicant, an OTP has been sent.",
    })


@app.post("/pin-reset/resend")
async def resend_pin_reset_otp(request: Request):
    if not email_is_configured():
        return JSONResponse({"error": "PIN reset email is not configured on the server"}, status_code=503)

    data = await request.json() or {}
    flow_id = str(data.get("flow_id", ""))
    try:
        otp = pin_reset_manager.resend(flow_id)
    except PinResetError as error:
        return JSONResponse({"error": str(error)}, status_code=error.status_code)

    if otp:
        email = pin_reset_manager.challenges[flow_id]["recipient"]
        await deliver_pin_reset_otp(email, otp)
    return JSONResponse({"success": True, "message": "If the request is valid, a new OTP has been sent."})


@app.post("/pin-reset/verify")
async def verify_pin_reset_otp(request: Request):
    data = await request.json() or {}
    flow_id = str(data.get("flow_id", ""))
    otp = str(data.get("otp", ""))
    if not re.fullmatch(r"[0-9]{6}", otp):
        return JSONResponse({"error": "The OTP is invalid or expired"}, status_code=400)
    try:
        pin_reset_manager.verify(flow_id, otp)
    except PinResetError as error:
        return JSONResponse({"error": str(error)}, status_code=error.status_code)
    return JSONResponse({"success": True})


@app.post("/pin-reset/complete")
async def complete_pin_reset(request: Request):
    data = await request.json() or {}
    flow_id = str(data.get("flow_id", ""))
    pin = str(data.get("new_pin", ""))
    if not re.fullmatch(r"[0-9]{4}", pin):
        return JSONResponse({"error": "PIN must be exactly 4 digits"}, status_code=400)
    try:
        aadhaar_id = pin_reset_manager.consume_verified(flow_id)
    except PinResetError as error:
        return JSONResponse({"error": str(error)}, status_code=error.status_code)

    pin_records = load_aadhaar_pins()
    pin_record = pin_records.get(aadhaar_id)
    if not pin_record:
        return JSONResponse({"error": "Applicant record was not found"}, status_code=404)
    pin_record.update(hash_aadhaar_pin(pin))
    save_aadhaar_pins(pin_records)
    return JSONResponse({"success": True, "message": "PIN reset successfully."})


async def send_transaction(func):
    tx_hash = await func.transact({"from": default_account})
    tx_receipt = await w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt


async def find_approved_application(aadhaar_id):
    total = await passport_contract.functions.getTotalApplications().call()
    for application_id in range(total, 0, -1):
        application = await passport_contract.functions.getApplication(application_id).call()
        if application[1] == aadhaar_id and application[2].strip().upper() == "APPROVED":
            return {
                "app_id": application_id,
                "applicant_name": application[0],
                "aadhaar_id": application[1],
                "status": application[2],
                "timestamp": application[3],
            }
    return None


@app.post("/auth/applicant/signup")
async def applicant_signup(request: Request):
    data = await request.json() or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(password) < 8:
        return JSONResponse({"error": "Enter your name, a valid email, and a password with at least 8 characters"}, status_code=400)

    accounts = load_accounts()
    if email in accounts["applicants"]:
        return JSONResponse({"error": "An account already exists for this email. Please sign in."}, status_code=409)

    accounts["applicants"][email] = {
        "name": name,
        "email": email,
        **hash_password(password),
    }
    save_accounts(accounts)
    return await establish_session(request, "applicant", email, email, name)


@app.post("/auth/applicant/login")
async def applicant_login(request: Request):
    data = await request.json() or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    account = load_accounts()["applicants"].get(email)
    if not account or not verify_password(password, account):
        return JSONResponse({"error": "Email or password is incorrect"}, status_code=401)
    return await establish_session(request, "applicant", email, email, account["name"])


@app.post("/auth/developer/login")
async def developer_login(request: Request):
    data = await request.json() or {}
    usn = str(data.get("usn", "")).strip().lower()
    password = str(data.get("password", ""))
    if usn not in DEVELOPER_USNS:
        return JSONResponse({"error": "This USN is not authorized for developer access"}, status_code=403)

    if not verify_developer_password(password):
        return JSONResponse({"error": "USN or password is incorrect"}, status_code=401)
    return await establish_session(request, "developer", usn, "")


@app.get("/auth/session")
async def auth_session(request: Request):
    user = request.session.get("user")
    return JSONResponse({"authenticated": bool(user), "user": user})


@app.post("/auth/logout")
async def auth_logout(request: Request):
    request.session.clear()
    return JSONResponse({"success": True})


@app.get("/")
async def home():
    return JSONResponse({
        "message": "Cross-Blockchain Middleware running on Ganache!",
        "status": "online",
        "ganache": "connected" if ganache_connected else "disconnected",
        "aadhaar_contract": AADHAAR_ADDRESS,
        "passport_contract": PASSPORT_ADDRESS,
        "routes": [
            "GET  /health",
            "GET  /stats",
            "POST /auth/applicant/signup",
            "POST /auth/applicant/login",
            "POST /auth/developer/login",
            "GET  /auth/session",
            "POST /auth/logout",
            "POST /aadhaar/register",
            "GET  /aadhaar/citizens",
            "GET  /aadhaar/proof/<aadhaar_id>",
            "POST /aadhaar/verify/<aadhaar_id>",
            "POST /passport/apply",
            "GET  /passport/progress/<aadhaar_id>",
            "GET  /passport/applications",
            "GET  /passport/validate",
        ],
    })


@app.get("/health")
async def health():
    try:
        aadhaar_count = await aadhaar_contract.functions.getTotalRegistered().call()
        passport_count = await passport_contract.functions.getTotalApplications().call()
        return JSONResponse({
            "middleware": "online",
            "ganache": "connected",
            "aadhaar_registered": aadhaar_count,
            "passport_applications": passport_count,
            "block_number": await w3.eth.block_number,
            "network_id": await w3.net.version,
        })
    except Exception as e:
        return server_error("request", e)


@app.get("/stats")
async def public_stats():
    try:
        total = await passport_contract.functions.getTotalApplications().call()
        approved = 0
        rejected = 0
        for application_id in range(1, total + 1):
            status = (await passport_contract.functions.getApplication(application_id).call())[2]
            approved += status == "APPROVED"
            rejected += status == "REJECTED"
        return JSONResponse({
            "aadhaar_registered": await aadhaar_contract.functions.getTotalRegistered().call(),
            "passport_applications": total,
            "approved": approved,
            "rejected": rejected,
        })
    except Exception as e:
        return server_error("request", e)


@app.post("/aadhaar/register")
@require_roles("applicant")
async def register_citizen(request: Request):
    max_upload_bytes = configured_max_upload_bytes()
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_upload_bytes + 128 * 1024:
                return JSONResponse({
                    "error": "The uploaded document exceeds the size limit",
                    "verification_status": "VERIFICATION_FAILED",
                    "stages_completed": [],
                }, status_code=413)
        except ValueError:
            return JSONResponse({
                "error": "The request has an invalid Content-Length",
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": [],
            }, status_code=400)

    try:
        form = await request.form(
            max_files=1,
            max_fields=10,
            max_part_size=16 * 1024,
        )
    except (MultiPartException, StarletteHTTPException):
        return JSONResponse({
            "error": "Registration requires a valid multipart/form-data request",
            "verification_status": "VERIFICATION_FAILED",
            "stages_completed": [],
        }, status_code=400)

    stages_completed = []
    try:
        def form_text(field):
            value = form.get(field)
            return value.strip() if isinstance(value, str) else ""

        name = form_text("name")
        dob = form_text("dob")
        aadhaar_id = form_text("aadhaar_id")
        pin = form_text("pin")
        gender = form_text("gender")
        upload = form.get("aadhaar_document")

        # Offline e-KYC XML is the only registration method unless the PDF path is
        # explicitly restored with REGISTRATION_ALLOW_PDF=true.
        if form_text("verification_method") != "offline_xml" and not pdf_registration_allowed():
            return _requirement_rejected("REGISTRATION_METHOD_UNSUPPORTED")

        if (
            not name
            or not dob
            or not aadhaar_id
            or not gender
            or not re.fullmatch(r"\d{4}", pin)
        ):
            return JSONResponse({
                "error": "name, dob, Aadhaar ID, gender and a 4-digit PIN are required",
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": [],
            }, status_code=400)

        try:
            aadhaar_id = canonical_aadhaar(aadhaar_id)
        except ValueError:
            return JSONResponse({
                "error": "Enter a valid 12-digit Aadhaar number",
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": [],
            }, status_code=400)

        if form_text("verification_method") == "offline_xml":
            return await _register_with_ekyc_xml(request, form, name, dob, aadhaar_id, pin, gender)

        try:
            pdf_password = generate_eaadhaar_password(name, dob)
        except ValueError:
            return JSONResponse({
                "error": "Enter a valid name and date of birth",
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": [],
            }, status_code=400)

        try:
            mobile = normalize_mobile(form_text("mobile"), SMS_DEFAULT_COUNTRY_CODE)
        except ValueError:
            return JSONResponse({
                "error": "A valid registered mobile number is required",
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": [],
            }, status_code=400)

        if not isinstance(upload, UploadFile):
            return JSONResponse({
                "error": "Upload an Aadhaar document with the registration form",
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": [],
            }, status_code=400)

        field_results = None
        processing_status = {
            "pdf_password": "NOT_VERIFIED",
            "text_extraction": "NOT_STARTED",
            "extraction_method": "NOT_STARTED",
            "ocr": "NOT_STARTED",
            "ocr_message": None,
            "field_sources": {},
            "ocr_confidence": {},
        }
        try:
            async with validated_upload(
                upload,
                max_bytes=max_upload_bytes,
                password=pdf_password,
            ) as document_path:
                stages_completed.append("DOCUMENT_UPLOADED")
                qr_result = await asyncio.to_thread(
                    verify_secure_qr,
                    document_path,
                    pdf_password,
                    pinned_public_keys(),
                )
                aadhaar_digits = aadhaar_id.replace("-", "")
                if qr_result["ok"]:
                    processing_status["extraction_method"] = "SECURE_QR"
                    stages_completed.append("UIDAI_SIGNATURE_VERIFIED")
                    matched = match_signed_details(
                        qr_result["details"], name, dob, gender, aadhaar_digits
                    )
                    decision = matched["result"]
                    reason_codes = matched["reason_codes"]
                    authenticity = "UIDAI_SIGNATURE_VERIFIED"
                    field_results = {
                        field: "MATCH" if code == "OK" else "NO_MATCH"
                        for field, code in reason_codes.items()
                    }
                elif qr_result["code"] != "QR_MISSING":
                    # Present but invalid/unsupported QR: never fall back to OCR.
                    logger.warning("Secure QR rejected: %s", qr_result["code"])
                    decision = "rejected"
                    reason_codes = {"document": qr_result["code"]}
                    authenticity = "NOT_VERIFIED"
                    field_results = {}
                else:
                    # No QR: OCR text is an UNSIGNED fallback and can never be "verified".
                    extracted_details = extract_eaadhaar_details(
                        document_path,
                        pdf_password,
                    )
                    processing_status = {
                        "pdf_password": extracted_details["password_status"],
                        "text_extraction": (
                            "COMPLETED"
                            if extracted_details["text_available"]
                            else "NO_TEXT"
                        ),
                        "extraction_method": extracted_details["extraction_method"],
                        "ocr": extracted_details["ocr_status"],
                        "ocr_message": extracted_details["ocr_message"],
                        "field_sources": extracted_details["field_sources"],
                        "ocr_confidence": extracted_details["ocr_confidence"],
                    }
                    stages_completed.append("UNSIGNED_OCR_FALLBACK")
                    field_results = compare_applicant_details(
                        extracted_details, name, dob, gender, aadhaar_id
                    )
                    authenticity = "NOT_VERIFIED"
                    reason_codes = {"document": "QR_MISSING"}
                    reason_codes.update({
                        field: {"MATCH": "UNSIGNED_OCR_MATCH", "NO_MATCH": f"{field.upper()}_MISMATCH"}.get(result, f"{field.upper()}_UNAVAILABLE")
                        for field, result in field_results.items()
                    })
                    decision = (
                        "rejected"
                        if "NO_MATCH" in field_results.values()
                        else "pending"
                    )
                all_fields_match = decision == "verified"
                if all_fields_match:
                    stages_completed.append("DEMOGRAPHIC_DETAILS_MATCHED")

            if decision != "verified":
                return _not_verified_response(
                    decision, reason_codes, authenticity, field_results,
                    stages_completed, processing_status,
                    "No UIDAI-signed QR code could be read, so the details cannot be "
                    "verified automatically. Nothing was recorded on the blockchain.",
                )
            return await _register_verified_citizen(
                request,
                name,
                dob,
                aadhaar_id,
                pin,
                mobile,
                field_results=field_results,
                processing_status=processing_status,
                verification={
                    "result": "verified",
                    "reason_codes": reason_codes,
                    "document_authenticity": authenticity,
                    "limitation": (
                        "Signature checked against the pinned UIDAI certificate only; "
                        "certificate chain and revocation are not validated."
                    ),
                },
            )
        except DocumentUploadError as error:
            if str(error) == "Invalid e-Aadhaar PDF password":
                processing_status["pdf_password"] = "FAILED"
            return JSONResponse({
                "success": False,
                "verification_status": "VERIFICATION_FAILED",
                "stages_completed": stages_completed,
                "processing_status": processing_status,
                "error": str(error),
            }, status_code=error.status_code)
    finally:
        await form.close()


REGISTRATION_REQUIREMENT_MESSAGE = (
    "Registration requires the Aadhaar Offline e-KYC ZIP and its share code."
)


def pdf_registration_allowed():
    """Off by default. REGISTRATION_ALLOW_PDF=true restores the PDF (Secure QR / OCR) path."""
    return os.getenv("REGISTRATION_ALLOW_PDF", "").strip().lower() in ("1", "true", "yes", "on")


def _requirement_rejected(code):
    """Reason code plus a generic client message; no details about what was received."""
    return JSONResponse({
        "success": False,
        "result": "rejected",
        "verification_status": "VERIFICATION_FAILED",
        "stages_completed": [],
        "reason_codes": {"document": code},
        "error": REGISTRATION_REQUIREMENT_MESSAGE,
    }, status_code=400)


def _ekyc_processing_status(code=None):
    """What the result panel shows for the signed-file checks (no PDF/OCR rows)."""
    checks = {"extraction_method": "OFFLINE_EKYC_XML", "zip": "OPENED", "signature": "VERIFIED", "freshness": "OK"}
    if code is None or code == "EKYC_LAYOUT_UNEXPECTED":
        return checks
    if code.startswith(("EKYC_ZIP_", "EKYC_SHARE_CODE_", "EKYC_CONFIG_")):
        checks.update(zip="FAILED", signature="NOT_CHECKED", freshness="NOT_CHECKED")
    elif code.startswith("EKYC_SIGNATURE_") or code == "CERTIFICATE_UNAVAILABLE":
        checks.update(signature="FAILED", freshness="NOT_CHECKED")
    elif code in ("EKYC_STALE", "EKYC_FUTURE_DATED", "EKYC_TIMESTAMP_INVALID", "EKYC_REFERENCE_INVALID"):
        checks.update(freshness="FAILED")
    else:  # malformed XML or anything unexpected: nothing after the ZIP was established
        checks.update(signature="NOT_CHECKED", freshness="NOT_CHECKED")
    return checks


def _not_verified_response(decision, reason_codes, authenticity, field_results,
                           stages_completed, processing_status, pending_message):
    logger.warning("Registration not verified: %s", decision)
    review_fields = [
        AADHAAR_FIELD_LABELS[field]
        for field, result in (field_results or {}).items()
        if result == "REVIEW_REQUIRED"
    ]
    return JSONResponse({
        "success": False,
        "result": decision,
        "verification_status": (
            "VERIFICATION_PENDING" if decision == "pending" else "VERIFICATION_FAILED"
        ),
        "stages_completed": stages_completed,
        "field_results": field_results,
        "reason_codes": reason_codes,
        "document_authenticity": authenticity,
        "manual_review_required": decision == "pending",
        "review_required_fields": review_fields,
        "review_message": pending_message if decision == "pending" else None,
        "processing_status": processing_status,
        "error": (
            "Applicant details could not be verified against the uploaded "
            "e-Aadhaar document."
        ),
    }, status_code=202 if decision == "pending" else 422)


async def _register_with_ekyc_xml(request, form, name, dob, aadhaar_id, pin, gender):
    """Signed Offline e-KYC XML (ZIP + 4-digit share code): the registration method.

    The share code is never logged, echoed or stored. Reason codes only on failure.
    """
    def invalid(message):
        return JSONResponse({
            "error": message,
            "verification_status": "VERIFICATION_FAILED",
            "stages_completed": [],
        }, status_code=400)

    mobile_value = form.get("mobile")
    try:
        mobile = normalize_mobile(mobile_value.strip() if isinstance(mobile_value, str) else "", SMS_DEFAULT_COUNTRY_CODE)
    except ValueError:
        return invalid("A valid registered mobile number is required")
    upload = form.get("ekyc_zip")
    share_code = form.get("share_code")
    if not isinstance(upload, UploadFile):
        return _requirement_rejected("EKYC_ZIP_REQUIRED")
    if not isinstance(share_code, str) or not share_code.strip():
        await upload.close()
        return _requirement_rejected("EKYC_SHARE_CODE_REQUIRED")

    chunks, total = [], 0
    await upload.seek(0)
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > EKYC_MAX_ZIP_BYTES:
            break
        chunks.append(chunk)
    await upload.close()

    stages_completed = ["DOCUMENT_UPLOADED"]
    if total > EKYC_MAX_ZIP_BYTES:
        result = {"ok": False, "code": "EKYC_ZIP_TOO_LARGE"}
    else:
        result = await asyncio.to_thread(
            verify_ekyc_zip, b"".join(chunks), share_code.strip(), pinned_certificates(),
        )

    processing_status = _ekyc_processing_status(None if result["ok"] else result["code"])
    if not result["ok"]:
        logger.warning("Offline e-KYC rejected: %s %s", result["code"], result.get("sub", ""))
        return _not_verified_response(
            "rejected", {"document": result["code"]}, "NOT_VERIFIED", {},
            stages_completed, processing_status, None,
        )

    stages_completed.append("UIDAI_SIGNATURE_VERIFIED")
    matched = match_signed_details(
        result["details"], name, dob, gender, aadhaar_id.replace("-", "")
    )
    decision, reason_codes = matched["result"], matched["reason_codes"]
    field_results = {
        field: "MATCH" if code == "OK" else ("NO_MATCH" if code.endswith("_MISMATCH") else "REVIEW_REQUIRED")
        for field, code in reason_codes.items()
    }
    if decision != "verified":
        return _not_verified_response(
            decision, reason_codes, "UIDAI_SIGNATURE_VERIFIED", field_results,
            stages_completed, processing_status,
            "The signed file did not contain every field needed to verify your details. "
            "Nothing was recorded on the blockchain.",
        )
    stages_completed.append("DEMOGRAPHIC_DETAILS_MATCHED")
    return await _register_verified_citizen(
        request, name, dob, aadhaar_id, pin, mobile,
        field_results=field_results,
        processing_status=processing_status,
        verification={
            "result": "verified",
            "reason_codes": reason_codes,
            "document_authenticity": "UIDAI_SIGNATURE_VERIFIED",
            "limitation": (
                "Signature checked against the pinned UIDAI certificate only; "
                "certificate chain and revocation are not validated. "
                "Offline e-KYC XML was checked against one real file only; other variants are untested."
            ),
        },
    )


async def _register_verified_citizen(
    request,
    name,
    dob,
    aadhaar_id,
    pin,
    mobile,
    field_results=None,
    processing_status=None,
    verification=None,
):
    try:
        already = await aadhaar_contract.functions.isRegistered(aadhaar_id).call()
        if already:
            return JSONResponse({
                "error": (
                    "This Aadhaar number is already registered. Your details were "
                    "verified, but nothing new was recorded."
                ),
                "success": False,
                "verification_status": "DETAILS_VERIFIED",
                "field_results": field_results,
                "processing_status": processing_status,
                **(verification or {}),
            }, status_code=400)

        identity_hash = generate_identity_hash(name, dob, aadhaar_id)
        name_hash = generate_name_hash(name)
        signature = sign_identity(private_key, identity_hash)

        receipt = await send_transaction(
            aadhaar_contract.functions.registerIdentity(
                aadhaar_id,
                name_hash,
                identity_hash,
                signature,
            )
        )

        pin_records = load_aadhaar_pins()
        user_email = str(request.session["user"].get("email", "")).strip().lower()
        pin_records[aadhaar_id] = {
            "name": name,
            "mobile": mobile,
            "email": user_email,
            **hash_aadhaar_pin(pin),
        }
        save_aadhaar_pins(pin_records)

        return JSONResponse({
            "success": True,
            "name": name,
            "aadhaar_id": aadhaar_id,
            "verification_status": "DETAILS_VERIFIED",
            "message": "e-Aadhaar details verified successfully.",
            "field_results": field_results,
            "processing_status": processing_status,
            "document_authenticity": "NOT_VERIFIED",
            "limitation": (
                "UIDAI digital signature authenticity is not verified by this module."
            ),
            "identity_hash": identity_hash,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            **(verification or {}),
        })
    except Exception as error:
        logger.error("registration failed: %s", type(error).__name__)
        return JSONResponse({
            "error": GENERIC_ERROR,
            "verification_status": "DETAILS_VERIFIED",
            "field_results": field_results,
            "processing_status": processing_status,
            "document_authenticity": "NOT_VERIFIED",
            "limitation": (
                "UIDAI digital signature authenticity is not verified by this module."
            ),
        }, status_code=500)


@app.get("/aadhaar/citizens")
@require_roles("developer")
async def get_citizens(request: Request):
    try:
        total = await aadhaar_contract.functions.getTotalRegistered().call()
        citizens = []
        for i in range(total):
            aadhaar_id = await aadhaar_contract.functions.registeredIds(i).call()
            proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
            citizens.append({
                "aadhaar_id": aadhaar_id,
                "identity_hash": proof[0][:30] + "...",
                "timestamp": proof[3],
            })
        return JSONResponse({
            "total": total,
            "citizens": citizens,
        })
    except Exception as e:
        return server_error("request", e)


@app.get("/aadhaar/proof/{aadhaar_id}")
@require_roles("applicant")
async def get_identity_proof(request: Request, aadhaar_id: str):
    try:
        aadhaar_id = canonical_aadhaar(aadhaar_id)
    except ValueError:
        return JSONResponse({"found": False, "error": "Enter a valid 12-digit Aadhaar number"}, status_code=400)
    if not owns_aadhaar(request, aadhaar_id):
        return JSONResponse({"found": False, "error": "You do not have permission to access this service"}, status_code=403)
    try:
        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature = proof[1]
        name_hash = proof[2]
        timestamp = proof[3]
        exists = proof[4]

        if not exists:
            return JSONResponse({"found": False, "error": "Aadhaar ID not found"}, status_code=404)

        return JSONResponse({
            "found": True,
            "aadhaar_id": aadhaar_id,
            "identity_hash": identity_hash,
            "signature": signature,
            "name_hash": name_hash,
            "timestamp": timestamp,
            "block_number": await w3.eth.block_number,
        })
    except Exception as e:
        return server_error("request", e)


@app.post("/aadhaar/verify/{aadhaar_id}")
@require_roles("applicant")
async def verify_identity_proof(request: Request, aadhaar_id: str):
    try:
        aadhaar_id = canonical_aadhaar(aadhaar_id)
    except ValueError:
        return JSONResponse({"authenticated": False, "error": "Enter a valid 12-digit Aadhaar number"}, status_code=400)
    if not owns_aadhaar(request, aadhaar_id):
        return JSONResponse({"authenticated": False, "error": "You do not have permission to access this service"}, status_code=403)
    keys = lockout_keys(request, aadhaar_id)
    if verification_state.is_locked(*keys):
        return JSONResponse({"authenticated": False, "error": LOCKED_ERROR}, status_code=429)

    try:
        data = await request.json() or {}
        applicant_name = str(data.get("name", "")).strip()
        pin = str(data.get("pin", ""))
        if not applicant_name or not re.fullmatch(r"\d{4}", pin):
            return JSONResponse({"authenticated": False, "error": "Name and a 4-digit PIN are required for identity verification"}, status_code=400)

        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash, signature, name_hash, timestamp, exists = proof[0], proof[1], proof[2], proof[3], proof[4]
        pin_record = load_aadhaar_pins().get(aadhaar_id)
        # Evaluate every check before answering so failures are indistinguishable.
        checks = [
            bool(exists),
            bool(exists) and verify_signature(public_key, identity_hash, signature),
            bool(exists) and hmac.compare_digest(generate_name_hash(applicant_name), name_hash),
            bool(pin_record) and verify_aadhaar_pin(pin, pin_record),
        ]
        if not all(checks):
            verification_state.record_failure(*keys)
            return JSONResponse({"authenticated": False, "error": GENERIC_IDENTITY_ERROR}, status_code=401)

        binding = binding_for(request, aadhaar_id)
        request_id, nonce, expires_at = replay_protection.issue(binding)
        verification_signature = sign_verification_message(
            private_key, identity_hash, nonce, request_id
        )
        verification_state.mark_verified(binding)
        verification_state.reset(*keys)

        approved_application = await find_approved_application(aadhaar_id)

        return JSONResponse({
            "authenticated": True,
            "already_applied": approved_application is not None,
            "previous_application": approved_application,
            "aadhaar_id": aadhaar_id,
            "identity_hash": identity_hash,
            "signature": signature,
            "verification_signature": verification_signature,
            "nonce": nonce,
            "request_id": request_id,
            "nonce_expires_at": expires_at,
            "name_hash": name_hash,
            "timestamp": timestamp,
            "block_number": await w3.eth.block_number,
        })
    except Exception as e:
        return server_error("identity verification", e)


@app.post("/passport/apply")
@require_roles("applicant")
async def apply_for_passport(request: Request):
    data = await request.json() or {}
    applicant_name = data.get("name")
    pin = str(data.get("pin", ""))
    try:
        aadhaar_id = canonical_aadhaar(data.get("aadhaar_id"))
    except ValueError:
        return JSONResponse({"error": "Enter a valid 12-digit Aadhaar number"}, status_code=400)

    if not applicant_name or not re.fullmatch(r"\d{4}", pin):
        return JSONResponse({"error": "name, aadhaar_id and a 4-digit pin are required"}, status_code=400)
    if not owns_aadhaar(request, aadhaar_id):
        return JSONResponse({"error": "You do not have permission to access this service"}, status_code=403)
    keys = lockout_keys(request, aadhaar_id)
    if verification_state.is_locked(*keys):
        return JSONResponse({"error": LOCKED_ERROR}, status_code=429)

    # Server-side enforcement: a recent verification record AND a valid, single-use
    # nonce bound to this session, applicant, Aadhaar ID and application are required.
    binding = binding_for(request, aadhaar_id)
    request_id = str(data.get("request_id", ""))
    nonce = str(data.get("nonce", ""))
    valid_nonce, _ = replay_protection.consume(binding, nonce, request_id)
    if not verification_state.consume_verified(binding) or not valid_nonce:
        verification_state.record_failure(*keys)
        return JSONResponse({"error": "Identity verification is required before applying"}, status_code=403)

    try:
        approved_application = await find_approved_application(aadhaar_id)
        if approved_application:
            return JSONResponse({
                "already_applied": True,
                "application": approved_application,
                "error": "A passport application for this Aadhaar ID has already been approved. You cannot apply again.",
            }, status_code=409)

        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash, signature, name_hash, exists = proof[0], proof[1], proof[2], proof[4]
        pin_record = load_aadhaar_pins().get(aadhaar_id)
        checks = [
            bool(exists),
            bool(exists) and verify_signature(public_key, identity_hash, signature),
            bool(exists) and hmac.compare_digest(generate_name_hash(applicant_name), name_hash),
            bool(pin_record) and verify_aadhaar_pin(pin, pin_record),
        ]
        if not all(checks):
            verification_state.record_failure(*keys)
            return JSONResponse({"error": GENERIC_IDENTITY_ERROR}, status_code=401)
        verification_state.reset(*keys)

        receipt = await send_transaction(
            passport_contract.functions.submitApplication(
                aadhaar_id,
                applicant_name,
                "APPROVED",
                identity_hash,
            )
        )

        return JSONResponse({
            "applicant": applicant_name,
            "aadhaar_id": aadhaar_id,
            "status": "APPROVED",
            "reason": "Identity and PIN verified successfully",
            "verified": True,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "identity_hash": identity_hash[:30] + "...",
        })
    except Exception as e:
        return server_error("passport application", e)


@app.get("/passport/applications")
@require_roles("developer")
async def get_applications(request: Request):
    try:
        total = await passport_contract.functions.getTotalApplications().call()
        applications = []
        for i in range(1, total + 1):
            app_data = await passport_contract.functions.getApplication(i).call()
            applications.append({
                "app_id": i,
                "applicant_name": app_data[0],
                "aadhaar_id": app_data[1],
                "status": app_data[2],
                "timestamp": app_data[3],
            })
        return JSONResponse({
            "total": total,
            "applications": applications,
        })
    except Exception as e:
        return server_error("request", e)


@app.get("/passport/progress/{aadhaar_id}")
@require_roles("applicant")
async def get_applicant_progress(request: Request, aadhaar_id: str):
    try:
        total = await passport_contract.functions.getTotalApplications().call()
        applications = []
        for application_id in range(1, total + 1):
            app_data = await passport_contract.functions.getApplication(application_id).call()
            if app_data[1] == aadhaar_id:
                applications.append({
                    "app_id": application_id,
                    "applicant_name": app_data[0],
                    "aadhaar_id": app_data[1],
                    "status": app_data[2],
                    "timestamp": app_data[3],
                })
        proof = await aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        return JSONResponse({
            "applications": applications,
            "registration_found": proof[4],
            "registration": ({"aadhaar_id": aadhaar_id} if proof[4] else None),
        })
    except Exception as e:
        return server_error("request", e)


@app.get("/passport/validate")
@require_roles("developer")
async def validate(request: Request):
    try:
        return JSONResponse({
            "valid": True,
            "block_number": await w3.eth.block_number,
            "total_registered": await aadhaar_contract.functions.getTotalRegistered().call(),
            "total_applications": await passport_contract.functions.getTotalApplications().call(),
            "aadhaar_contract": AADHAAR_ADDRESS,
            "passport_contract": PASSPORT_ADDRESS,
            "message": "Blockchain is valid and running on Ganache!",
        })
    except Exception as e:
        return server_error("request", e)


if __name__ == "__main__":
    import uvicorn

    print("\n✅ Cross-Blockchain Middleware Starting...")
    print(f"   Ganache              : http://127.0.0.1:8545")
    print(f"   Aadhaar Contract     : {AADHAAR_ADDRESS}")
    print(f"   Passport Contract    : {PASSPORT_ADDRESS}")
    print(f"   Server running at    : http://localhost:5000\n")
    # access_log is off: Aadhaar IDs appear in URL paths and must not be logged.
    uvicorn.run(app, host="127.0.0.1", port=5000, reload=False, access_log=False)