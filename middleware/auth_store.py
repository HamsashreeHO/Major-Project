import hashlib
import hmac
import json
import os
import secrets

AUTH_FILE = os.path.join(os.path.dirname(__file__), "accounts.json")
DEVELOPER_USNS = {
    "1si23is025",
    "1si23is038",
    "1si23is119",
    "1si23is120",
}
PASSWORD_ITERATIONS = 310_000
DEVELOPER_PASSWORD_SALT = b"identigate-team-developer-v1"
DEVELOPER_PASSWORD_HASH = "22687c0dfdec5377aa95865a671d461caf89d4078dced6e547c7f55799146eaf"


def load_accounts():
    if not os.path.exists(AUTH_FILE):
        return {"applicants": {}, "developers": {}}
    with open(AUTH_FILE, "r", encoding="utf-8") as account_file:
        accounts = json.load(account_file)
    accounts.setdefault("applicants", {})
    accounts.setdefault("developers", {})
    return accounts


def save_accounts(accounts):
    temporary_file = AUTH_FILE + ".tmp"
    with open(temporary_file, "w", encoding="utf-8") as account_file:
        json.dump(accounts, account_file, indent=2)
    os.replace(temporary_file, AUTH_FILE)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PASSWORD_ITERATIONS
    ).hex()
    return {"salt": salt, "password_hash": digest}


def verify_password(password, account):
    actual = hash_password(password, account["salt"])["password_hash"]
    return hmac.compare_digest(actual, account["password_hash"])


def verify_developer_password(password):
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        DEVELOPER_PASSWORD_SALT,
        PASSWORD_ITERATIONS,
    ).hex()
    return hmac.compare_digest(actual, DEVELOPER_PASSWORD_HASH)
