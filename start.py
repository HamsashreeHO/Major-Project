import subprocess
import time
import json
import os
import socket
import sys
import requests

print("\n🚀 Cross-Blockchain Passport System — Auto Startup")
print("=" * 52)

project_root = os.path.dirname(os.path.abspath(__file__))
addresses_file = os.path.join(
    project_root,
    "crypto_core", "contract_addresses.json"
)

def contract_has_code(address):
    response = requests.post(
        "http://127.0.0.1:8545",
        json={"jsonrpc": "2.0", "method": "eth_getCode", "params": [address, "latest"], "id": 1},
        timeout=5,
    )
    response.raise_for_status()
    return response.json().get("result") not in (None, "0x", "0x0")


aadhaar_address = None
passport_address = None
reuse_existing_contracts = False

try:
    with open(addresses_file, "r", encoding="utf-8") as address_file:
        existing_addresses = json.load(address_file)
    aadhaar_address = existing_addresses["AadhaarRegistry"]
    passport_address = existing_addresses["PassportRegistry"]
    reuse_existing_contracts = contract_has_code(aadhaar_address) and contract_has_code(passport_address)
except (OSError, KeyError, ValueError, requests.RequestException):
    reuse_existing_contracts = False

if reuse_existing_contracts:
    print("\n✅ Existing contract deployments found; preserving their records.")
else:
    print("\n📦 No saved deployment found. Deploying contracts to Ganache...")
    result = subprocess.run(
        "truffle migrate --network development",
        capture_output=True,
        text=True,
        shell=True,
        cwd=project_root,
    )
    output = result.stdout + result.stderr
    print(output)
    if result.returncode != 0:
        print("❌ Contract migration failed. Check that Ganache is running on port 8545.")
        sys.exit(result.returncode)

    current_contract = None
    for line in output.split("\n"):
        if "Deploying 'AadhaarRegistry'" in line:
            current_contract = "aadhaar"
        if "Deploying 'PassportRegistry'" in line:
            current_contract = "passport"
        if "contract address:" in line:
            address = line.split("contract address:")[-1].strip()
            if current_contract == "aadhaar":
                aadhaar_address = address
            elif current_contract == "passport":
                passport_address = address

if not aadhaar_address or not passport_address:
    print("❌ Could not locate both deployed contract addresses.")
    print("   Existing contracts must be saved in crypto_core/contract_addresses.json.")
    sys.exit(1)

if not reuse_existing_contracts:
    try:
        with open(addresses_file, "w", encoding="utf-8") as address_file:
            json.dump({
                "AadhaarRegistry": aadhaar_address,
                "PassportRegistry": passport_address
            }, address_file, indent=4)
    except OSError as error:
        print(f"❌ Could not save the contract addresses: {error}")
        sys.exit(1)

print(f"✅ AadhaarRegistry  : {aadhaar_address}")
print(f"✅ PassportRegistry : {passport_address}")
print("✅ Contract addresses ready (existing deployments are preserved).")
print("\n⚠️  Please restart Flask now:")
print("   Stop Flask (Ctrl+C) and run: python app.py")
input("\nPress Enter after Flask is restarted...")

print("\n🎉 Blockchain services are ready. Sign in to register identities through the portal.")
print("\n🌐 Starting the frontend web server...")

frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
frontend_server = None
frontend_port = None

for port in range(5500, 5511):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_check:
        try:
            port_check.bind(("127.0.0.1", port))
        except OSError:
            continue

    creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    frontend_server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        cwd=frontend_dir,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags
    )

    frontend_url = f"http://127.0.0.1:{port}/"
    for _ in range(20):
        if frontend_server.poll() is not None:
            break
        try:
            response = requests.get(frontend_url, timeout=1)
            if response.ok and "IdentiGate" in response.text:
                frontend_port = port
                break
        except requests.RequestException:
            time.sleep(0.25)

    if frontend_port is not None:
        break

if frontend_port is None:
    print("❌ Could not start the frontend web server.")
    print("   Run: python -m http.server 5500 --directory frontend")
    sys.exit(1)

print(f"✅ Frontend running at http://127.0.0.1:{frontend_port}/")
print("=" * 52)