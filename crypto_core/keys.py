import os
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1

KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aadhaar_keys.json")

def load_or_generate_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            data = json.load(f)
        private_key = SigningKey.from_string(
            bytes.fromhex(data["private_key"]), curve=SECP256k1
        )
        public_key = VerifyingKey.from_string(
            bytes.fromhex(data["public_key"]), curve=SECP256k1
        )
        print("   🔑 Keys loaded from file ✅")
    else:
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key  = private_key.get_verifying_key()
        with open(KEYS_FILE, "w") as f:
            json.dump({
                "private_key": private_key.to_string().hex(),
                "public_key" : public_key.to_string().hex()
            }, f, indent=4)
        print("   🔑 New keys generated and saved ✅")
    return private_key, public_key