from flask               import Flask, request, jsonify, session
from flask_cors          import CORS
from web3                import Web3
from functools            import wraps
import hmac
import json
import os
import re
import secrets
import sys
from datetime            import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'crypto_core'))
from crypto_utils import generate_identity_hash, generate_name_hash, sign_identity, verify_signature
from keys         import load_or_generate_keys
try:
    from .auth_store import DEVELOPER_USNS, hash_password, load_accounts, save_accounts, verify_developer_password, verify_password
except ImportError:
    from auth_store import DEVELOPER_USNS, hash_password, load_accounts, save_accounts, verify_developer_password, verify_password

app  = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)
CORS(app, supports_credentials=True, origins=r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?")

SESSION_SECRET_FILE = os.path.join(os.path.dirname(__file__), ".session_secret")
if not os.path.exists(SESSION_SECRET_FILE):
    with open(SESSION_SECRET_FILE, "x", encoding="utf-8") as secret_file:
        secret_file.write(secrets.token_hex(32))
with open(SESSION_SECRET_FILE, "r", encoding="utf-8") as secret_file:
    app.secret_key = secret_file.read().strip()


def require_roles(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = session.get("user")
            if not user:
                return jsonify({"error": "Please sign in to continue"}), 401
            if user.get("role") not in allowed_roles:
                return jsonify({"error": "You do not have permission to access this service"}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def establish_session(role, username, email, name=None):
    session.clear()
    session["user"] = {
        "role": role,
        "username": username,
        "email": email,
        "name": name or username,
    }
    return jsonify({"success": True, "user": session["user"]})

# ─────────────────────────────────────────
# Connect to Ganache
# ─────────────────────────────────────────
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

if w3.is_connected():
    print("   ✅ Connected to Ganache blockchain!")
else:
    print("   ❌ Could not connect to Ganache!")

# ─────────────────────────────────────────
# Load contract addresses
# ─────────────────────────────────────────
ADDRESSES_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'crypto_core', 'contract_addresses.json'
)
with open(ADDRESSES_FILE) as f:
    addresses = json.load(f)

AADHAAR_ADDRESS  = addresses["AadhaarRegistry"]
PASSPORT_ADDRESS = addresses["PassportRegistry"]

# ─────────────────────────────────────────
# Load contract ABIs from build folder
# ─────────────────────────────────────────
BUILD_DIR = os.path.join(os.path.dirname(__file__), '..', 'build', 'contracts')

with open(os.path.join(BUILD_DIR, 'AadhaarRegistry.json')) as f:
    AADHAAR_ABI = json.load(f)["abi"]

with open(os.path.join(BUILD_DIR, 'PassportRegistry.json')) as f:
    PASSPORT_ABI = json.load(f)["abi"]

# ─────────────────────────────────────────
# Create contract instances
# ─────────────────────────────────────────
aadhaar_contract  = w3.eth.contract(
    address = Web3.to_checksum_address(AADHAAR_ADDRESS),
    abi     = AADHAAR_ABI
)
passport_contract = w3.eth.contract(
    address = Web3.to_checksum_address(PASSPORT_ADDRESS),
    abi     = PASSPORT_ABI
)

# ─────────────────────────────────────────
# Default account (Ganache account 0)
# ─────────────────────────────────────────
default_account = w3.eth.accounts[0]
w3.eth.default_account = default_account

# ─────────────────────────────────────────
# Load shared ECDSA keys
# ─────────────────────────────────────────
private_key, public_key = load_or_generate_keys()

# ─────────────────────────────────────────
# Helper: send transaction
# ─────────────────────────────────────────
def send_transaction(func):
    tx_hash    = func.transact({"from": default_account})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt


def find_approved_application(aadhaar_id):
    total = passport_contract.functions.getTotalApplications().call()
    for application_id in range(total, 0, -1):
        application = passport_contract.functions.getApplication(application_id).call()
        if application[1] == aadhaar_id and application[2].strip().upper() == "APPROVED":
            return {
                "app_id": application_id,
                "applicant_name": application[0],
                "aadhaar_id": application[1],
                "status": application[2],
                "timestamp": application[3],
            }
    return None


@app.route("/auth/applicant/signup", methods=["POST"])
def applicant_signup():
    data = request.get_json() or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(password) < 8:
        return jsonify({"error": "Enter your name, a valid email, and a password with at least 8 characters"}), 400

    accounts = load_accounts()
    if email in accounts["applicants"]:
        return jsonify({"error": "An account already exists for this email. Please sign in."}), 409

    accounts["applicants"][email] = {
        "name": name,
        "email": email,
        **hash_password(password),
    }
    save_accounts(accounts)
    return establish_session("applicant", email, email, name)


@app.route("/auth/applicant/login", methods=["POST"])
def applicant_login():
    data = request.get_json() or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    account = load_accounts()["applicants"].get(email)
    if not account or not verify_password(password, account):
        return jsonify({"error": "Email or password is incorrect"}), 401
    return establish_session("applicant", email, email, account["name"])


@app.route("/auth/developer/login", methods=["POST"])
def developer_login():
    data = request.get_json() or {}
    usn = str(data.get("usn", "")).strip().lower()
    password = str(data.get("password", ""))
    if usn not in DEVELOPER_USNS:
        return jsonify({"error": "This USN is not authorized for developer access"}), 403

    if not verify_developer_password(password):
        return jsonify({"error": "USN or password is incorrect"}), 401
    return establish_session("developer", usn, "")


@app.route("/auth/session", methods=["GET"])
def auth_session():
    user = session.get("user")
    return jsonify({"authenticated": bool(user), "user": user})


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"success": True})

# ═══════════════════════════════════════════════════
# ROUTE 1 — Home
# ═══════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message"          : "Cross-Blockchain Middleware running on Ganache!",
        "status"           : "online",
        "ganache"          : "connected" if w3.is_connected() else "disconnected",
        "aadhaar_contract" : AADHAAR_ADDRESS,
        "passport_contract": PASSPORT_ADDRESS,
        "routes"           : [
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
            "GET  /aadhaar/verify/<aadhaar_id>",
            "POST /passport/apply",
            "GET  /passport/progress/<aadhaar_id>",
            "GET  /passport/applications",
            "GET  /passport/validate"
        ]
    })

# ═══════════════════════════════════════════════════
# ROUTE 2 — Health check
# ═══════════════════════════════════════════════════
@app.route("/health", methods=["GET"])
def health():
    try:
        aadhaar_count  = aadhaar_contract.functions.getTotalRegistered().call()
        passport_count = passport_contract.functions.getTotalApplications().call()
        return jsonify({
            "middleware"          : "online",
            "ganache"             : "connected",
            "aadhaar_registered"  : aadhaar_count,
            "passport_applications": passport_count,
            "block_number"        : w3.eth.block_number,
            "network_id"          : w3.net.version
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stats", methods=["GET"])
def public_stats():
    try:
        total = passport_contract.functions.getTotalApplications().call()
        approved = 0
        rejected = 0
        for application_id in range(1, total + 1):
            status = passport_contract.functions.getApplication(application_id).call()[2]
            approved += status == "APPROVED"
            rejected += status == "REJECTED"
        return jsonify({
            "aadhaar_registered": aadhaar_contract.functions.getTotalRegistered().call(),
            "passport_applications": total,
            "approved": approved,
            "rejected": rejected,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 3 — Register citizen on Aadhaar blockchain
# ═══════════════════════════════════════════════════
@app.route("/aadhaar/register", methods=["POST"])
@require_roles("applicant")
def register_citizen():
    data       = request.get_json()
    name       = data.get("name")
    dob        = data.get("dob")
    aadhaar_id = data.get("aadhaar_id")

    if not name or not dob or not aadhaar_id:
        return jsonify({"error": "name, dob and aadhaar_id are required"}), 400

    try:
        # Check if already registered on blockchain
        already = aadhaar_contract.functions.isRegistered(aadhaar_id).call()
        if already:
            return jsonify({"error": "Aadhaar ID already registered on blockchain"}), 400

        # Generate hash and signature
        identity_hash = generate_identity_hash(name, dob, aadhaar_id)
        name_hash     = generate_name_hash(name)
        signature     = sign_identity(private_key, identity_hash)

        # Register on Aadhaar blockchain (Ganache)
        receipt = send_transaction(
            aadhaar_contract.functions.registerIdentity(
                aadhaar_id,
                name_hash,
                identity_hash,
                signature
            )
        )

        return jsonify({
            "success"         : True,
            "name"            : name,
            "aadhaar_id"      : aadhaar_id,
            "identity_hash"   : identity_hash,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number"    : receipt.blockNumber,
            "gas_used"        : receipt.gasUsed
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 4 — Get all registered citizens
# ═══════════════════════════════════════════════════
@app.route("/aadhaar/citizens", methods=["GET"])
@require_roles("developer")
def get_citizens():
    try:
        total = aadhaar_contract.functions.getTotalRegistered().call()
        citizens = []
        for i in range(total):
            aadhaar_id = aadhaar_contract.functions.registeredIds(i).call()
            proof      = aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
            citizens.append({
                "aadhaar_id"   : aadhaar_id,
                "identity_hash": proof[0][:30] + "...",
                "timestamp"    : proof[3]
            })
        return jsonify({
            "total"   : total,
            "citizens": citizens
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 5 — Get identity proof from Aadhaar chain
# ═══════════════════════════════════════════════════
@app.route("/aadhaar/proof/<aadhaar_id>", methods=["GET"])
@require_roles("applicant")
def get_identity_proof(aadhaar_id):
    try:
        proof = aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature     = proof[1]
        name_hash     = proof[2]
        timestamp     = proof[3]
        exists        = proof[4]

        if not exists:
            return jsonify({"found": False, "error": "Aadhaar ID not found"}), 404

        return jsonify({
            "found"        : True,
            "aadhaar_id"   : aadhaar_id,
            "identity_hash": identity_hash,
            "signature"    : signature,
            "name_hash"    : name_hash,
            "timestamp"    : timestamp,
            "block_number" : w3.eth.block_number
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 6 — Authenticate identity proof
# ═══════════════════════════════════════════════════
@app.route("/aadhaar/verify/<aadhaar_id>", methods=["GET"])
@require_roles("applicant")
def verify_identity_proof(aadhaar_id):
    try:
        applicant_name = request.args.get("name", "").strip()
        if not applicant_name:
            return jsonify({"authenticated": False, "error": "Name is required for identity verification"}), 400

        proof = aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature = proof[1]
        name_hash = proof[2]
        timestamp = proof[3]
        exists = proof[4]

        if not exists:
            return jsonify({"authenticated": False, "error": "Aadhaar ID not found"}), 404

        authenticated = verify_signature(public_key, identity_hash, signature)
        if not authenticated:
            return jsonify({"authenticated": False, "error": "Identity proof could not be authenticated"}), 401
        if not hmac.compare_digest(generate_name_hash(applicant_name), name_hash):
            return jsonify({"authenticated": False, "error": "Name does not match the registered identity"}), 401

        approved_application = find_approved_application(aadhaar_id)

        return jsonify({
            "authenticated": True,
            "already_applied": approved_application is not None,
            "previous_application": approved_application,
            "aadhaar_id": aadhaar_id,
            "identity_hash": identity_hash,
            "signature": signature,
            "name_hash": name_hash,
            "timestamp": timestamp,
            "block_number": w3.eth.block_number
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 6 — Apply for passport
# ═══════════════════════════════════════════════════
@app.route("/passport/apply", methods=["POST"])
@require_roles("applicant")
def apply_for_passport():
    data           = request.get_json()
    applicant_name = data.get("name")
    aadhaar_id     = data.get("aadhaar_id")

    if not applicant_name or not aadhaar_id:
        return jsonify({"error": "name and aadhaar_id are required"}), 400

    try:
        approved_application = find_approved_application(aadhaar_id)
        if approved_application:
            return jsonify({
                "already_applied": True,
                "application": approved_application,
                "error": "A passport application for this Aadhaar ID has already been approved. You cannot apply again."
            }), 409

        # Step 1: Get proof from Aadhaar blockchain
        proof         = aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        identity_hash = proof[0]
        signature     = proof[1]
        name_hash     = proof[2]
        exists        = proof[4]

        # Step 2: Verify signature
        if not exists:
            status   = "REJECTED"
            reason   = "Aadhaar ID not found on blockchain"
            verified = False
            identity_hash = "0" * 64
        else:
            verified = verify_signature(public_key, identity_hash, signature) and hmac.compare_digest(generate_name_hash(applicant_name), name_hash)
            if verified:
                status = "APPROVED"
                reason = "Identity verified successfully"
            else:
                status   = "REJECTED"
                reason   = "Name mismatch or invalid identity proof"

        # Step 3: Record result on Passport blockchain
        receipt = send_transaction(
            passport_contract.functions.submitApplication(
                aadhaar_id,
                applicant_name,
                status,
                identity_hash
            )
        )

        return jsonify({
            "applicant"        : applicant_name,
            "aadhaar_id"       : aadhaar_id,
            "status"           : status,
            "reason"           : reason,
            "verified"         : verified,
            "transaction_hash" : receipt.transactionHash.hex(),
            "block_number"     : receipt.blockNumber,
            "gas_used"         : receipt.gasUsed,
            "timestamp"        : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "identity_hash"    : identity_hash[:30] + "..."
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 7 — Get all passport applications
# ═══════════════════════════════════════════════════
@app.route("/passport/applications", methods=["GET"])
@require_roles("developer")
def get_applications():
    try:
        total        = passport_contract.functions.getTotalApplications().call()
        applications = []
        for i in range(1, total + 1):
            app_data = passport_contract.functions.getApplication(i).call()
            applications.append({
                "app_id"        : i,
                "applicant_name": app_data[0],
                "aadhaar_id"    : app_data[1],
                "status"        : app_data[2],
                "timestamp"     : app_data[3]
            })
        return jsonify({
            "total"       : total,
            "applications": applications
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/passport/progress/<aadhaar_id>", methods=["GET"])
@require_roles("applicant")
def get_applicant_progress(aadhaar_id):
    try:
        total = passport_contract.functions.getTotalApplications().call()
        applications = []
        for application_id in range(1, total + 1):
            app_data = passport_contract.functions.getApplication(application_id).call()
            if app_data[1] == aadhaar_id:
                applications.append({
                    "app_id": application_id,
                    "applicant_name": app_data[0],
                    "aadhaar_id": app_data[1],
                    "status": app_data[2],
                    "timestamp": app_data[3],
                })
        proof = aadhaar_contract.functions.getIdentityProof(aadhaar_id).call()
        return jsonify({
            "applications": applications,
            "registration_found": proof[4],
            "registration": ({"aadhaar_id": aadhaar_id} if proof[4] else None),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# ROUTE 8 — Validate (show blockchain stats)
# ═══════════════════════════════════════════════════
@app.route("/passport/validate", methods=["GET"])
@require_roles("developer")
def validate():
    try:
        return jsonify({
            "valid"                : True,
            "block_number"         : w3.eth.block_number,
            "total_registered"     : aadhaar_contract.functions.getTotalRegistered().call(),
            "total_applications"   : passport_contract.functions.getTotalApplications().call(),
            "aadhaar_contract"     : AADHAAR_ADDRESS,
            "passport_contract"    : PASSPORT_ADDRESS,
            "message"              : "Blockchain is valid and running on Ganache!"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════
# Run Flask
# ═══════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n✅ Cross-Blockchain Middleware Starting...")
    print(f"   Ganache              : http://127.0.0.1:8545")
    print(f"   Aadhaar Contract     : {AADHAAR_ADDRESS}")
    print(f"   Passport Contract    : {PASSPORT_ADDRESS}")
    print(f"   Server running at    : http://localhost:5000\n")
    app.run(debug=True, port=5000)