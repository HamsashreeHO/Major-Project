# 🔐 Cross-Blockchain Passport Authentication

> Privacy-Preserving Cross-Blockchain Framework for Secure Passport Authentication using Aadhaar Identity Verification

[![Python](https://img.shields.io/badge/Python-3.9-blue.svg)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.19-orange.svg)](https://soliditylang.org)
[![Ethereum](https://img.shields.io/badge/Ethereum-Ganache-purple.svg)](https://trufflesuite.com/ganache)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Proposed Solution](#proposed-solution)
- [System Architecture](#system-architecture)
- [Algorithms Used](#algorithms-used)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [API Endpoints](#api-endpoints)

---

## 📌 Overview

This project implements a **Privacy-Preserving Cross-Blockchain Framework** for secure passport authentication using Aadhaar identity verification. The system uses two independent Ethereum smart contracts deployed on Ganache blockchain — one representing the Aadhaar Blockchain and one representing the Passport Blockchain — connected through a FastAPI middleware layer.

The system verifies citizen identity using **SHA-256 hashing** and **ECDSA digital signatures** without exposing any raw personal data across blockchain boundaries.

---

## ❗ Problem Statement

Traditional passport authentication systems suffer from:

- Centralized databases vulnerable to data breaches
- Identity theft and unauthorized access
- Single points of failure
- No integration with Aadhaar infrastructure
- Privacy concerns when sharing identity data

---

## ✅ Proposed Solution

A privacy-preserving cross-blockchain authentication framework that:

- Uses **two independent blockchains** — Aadhaar and Passport
- Stores only **SHA-256 hashed identity** — never raw personal data
- Uses **ECDSA digital signatures** for cross-chain trust
- Transfers only **cryptographic proofs** through middleware
- Eliminates relay bridges reducing attack surface
- Provides immutable audit trail of all transactions

### Request Replay Protection

Each identity verification now receives a cryptographically random, single-use nonce from the middleware after the existing name and PIN checks succeed. The Aadhaar authority signs a SHA-256 hash of a domain-separated message containing the identity hash, request ID, and nonce. The middleware verifies that signature and consumes the request before returning success. Reused, expired, mismatched, or tampered challenges are rejected.

Nonce state is intentionally kept in the middleware because it protects the short-lived verification exchange and does not require changing or redeploying either existing registry contract. No raw Aadhaar data or private key material is added to blockchain records or API responses.

---

## 🏗️ System Architecture
 <img width="2962" height="2893" alt="archetecture1" src="https://github.<img width="950" height="509" alt="Picture1" src="https://github.com/user-attachments/assets/b0fa6999-9444-4865-b90b-73eb1b646009" />
com/user-attachments/assets/e941a527-7bf4-4eb9-9d59-25e8ba7a7872" />

### Three Main Components

| Component | Technology | Purpose |
|---|---|---|
| Aadhaar Blockchain | AadhaarRegistry.sol on Ganache | Stores hashed identity records |
| Passport Blockchain | PassportRegistry.sol on Ganache | Records passport applications |
| Middleware Layer | FastAPI + web3.py | Connects both blockchains |

---

## 🔐 Algorithms Used

### Algorithm 1 — SHA-256 Based Identity Hashing
Input  : Name + DOB + AadhaarID
Process: SHA-256 cryptographic hash function
Output : 256-bit identity hash H

Properties:
- One-way function — cannot reverse hash
- Deterministic — same input always gives same output
- Avalanche effect — one character change changes entire hash
- Collision resistant — no two inputs produce same hash

### Algorithm 2 — ECDSA Based Cross-Blockchain Verification

**Signing (Aadhaar Side):**
Input  : Hash H, Private Key PrivA
- Step 1 : Generate random k
- Step 2 : R = k · G (elliptic curve point)
- Step 3 : r = x-coordinate of R
- Step 4 : s = k⁻¹(H + r · PrivA) mod n
- Output : Signature (r, s)

**Verification (Passport Side):**
Input  : Hash H, Signature (r,s), Public Key PubA
- Step 1 : w  = s⁻¹ mod n
- Step 2 : u1 = H · w mod n
- Step 3 : u2 = r · w mod n
- Step 4 : P  = u1·G + u2·PubA
- Check  : x-coordinate of P = r → ACCEPT
else → REJECT

---

## 🛠️ Technology Stack

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.9 | Primary backend language |
| SHA-256 (hashlib) | Built-in | Identity hashing |
| ECDSA (ecdsa library) | Latest | Digital signatures |
| Solidity | 0.8.19 | Smart contract language |
| Ganache | 7.9.2 | Local Ethereum blockchain |
| Truffle | 5.11.5 | Contract deployment framework |
| web3.py | Latest | Blockchain interaction |
| FastAPI | Latest | Middleware REST API |
| Uvicorn | Latest | ASGI server |
| HTML/CSS/JavaScript | — | Frontend interface |
| Node.js | 22.x | Runtime for Truffle and Ganache |

---

## 📁 Project Structure

```
cross-blockchain-passport/
|
|-- contracts/
|   |-- AadhaarRegistry.sol        (Aadhaar Blockchain smart contract)
|   |-- PassportRegistry.sol       (Passport Blockchain smart contract)
|
|-- migrations/
|   |-- 2_deploy_contracts.js      (Contract deployment script)
|
|-- crypto_core/
|   |-- crypto_utils.py            (SHA-256 + ECDSA implementation)
|   |-- keys.py                    (Key management system)
|   |-- contract_addresses.json    (Deployed contract addresses)
|
|-- middleware/
|   |-- app.py                     (FastAPI middleware)
|   |-- document_upload.py         (Private upload staging and file validation)
|   |-- aadhaar_qr.py              (QR detection without authenticity claims)
|
|-- frontend/
|   |-- index.html                 (Web interface)
|
|-- test/
|   |-- test_aadhaar_documents.py (Upload validation and QR detection tests)
|   |-- test_aadhaar_registration_upload.py (Multipart registration fail-closed tests)
|
|-- start.py                       (Auto startup script)
|-- truffle-config.js              (Truffle configuration)
|-- README.md                      (Project documentation)
```
---

## ⚙️ Installation

### Prerequisites

Make sure you have installed:
- Python 3.9+
- Node.js 18+
- VS Code

### Step 1 — Clone Repository

```bash
git clone https://github.com/HamsashreeHO/Major-Project.git
cd cross-blockchain-passport
```

### Step 2 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Install Local OCR Engine

The Python requirements include `pytesseract`, but OCR also requires the local Tesseract executable and English language data. On Windows, install Tesseract-OCR (select English and, if needed, Kannada during setup):

```powershell
winget install --id UB-Mannheim.TesseractOCR --exact --source winget
tesseract --version
tesseract --list-langs
```

On Debian/Ubuntu:

```bash
sudo apt-get install tesseract-ocr tesseract-ocr-kan
tesseract --version
tesseract --list-langs
```

Selectable-text extraction uses PyMuPDF; OCR runs locally in memory. It renders PDF pages at up to 300 DPI, preprocesses them with OpenCV, and uses `eng` or `eng+kan` when the Kannada model is installed. OCR field lines must meet a 60% average word-confidence threshold, so one weakly recognized word does not invalidate the entire line. For dense layouts, extraction also checks a lower-left demographic crop; unlabeled date/gender candidates must be high-confidence and spatially adjacent, Aadhaar candidates must be near an Aadhaar label, and a fallback name must repeat in the address and demographic areas. Ambiguous values still require manual review. No rendered page images are saved. If Tesseract or its English model is unavailable, the request fails closed and reports manual review.

### Aadhaar e-PDF Verification

`POST /aadhaar/register` accepts `multipart/form-data` with `name`, `dob`, `aadhaar_id`, `pin`, `gender`, `mobile`, and `aadhaar_document`. JSON requests and image files are rejected. The backend validates and temporarily stages readable PDFs up to 10 MiB, checks for JavaScript/unsafe PDF actions and embedded files, and removes the temporary file when processing ends. Digital signature fields are allowed; the uploaded PDF is never rewritten.

The PDF password is generated from the applicant's entered details (first four letters of the normalized name in uppercase + four-digit birth year); no separate PDF password field is sent. The existing 4-digit application PIN remains separate. After the PDF is read (and decrypted when password-protected), the module first extracts selectable text and automatically runs local OCR if any required field is missing or ambiguous. It extracts name, DOB/year of birth, gender, and a complete Aadhaar number, then compares them to the form. Low-confidence OCR and missing or ambiguous fields require manual review. Every returned field result must be `MATCH` before the existing Aadhaar blockchain registration and PIN storage are called. Incorrect PDF passwords return `Invalid e-Aadhaar PDF password`.

On failed comparisons, middleware logs only the failed field identifiers (for example, `name` or `aadhaar_id`), never extracted values, Aadhaar numbers, or the generated PDF password.

These checks do **not** establish UIDAI document authenticity. UIDAI digital-signature verification remains a separate pending module while the applicable UIDAI technical specifications and verification procedure are awaited. Do not treat successful demographic matching as cryptographic proof that a document originated from UIDAI.

The backend enforces the 10 MiB maximum. `AADHAAR_DOCUMENT_MAX_BYTES` may be set to a positive number of bytes to lower the limit; it cannot raise the 10 MiB maximum.

Run the upload, extraction, and registration tests (OCR engine calls are mocked in tests) with:

```bash
python -m pytest test/test_aadhaar_documents.py test/test_eaadhaar_pdf.py test/test_aadhaar_registration_upload.py
```

### Step 3 — Install Node Dependencies

```bash
npm install -g ganache
npm install -g truffle
```

### Step 4 — Verify Installation

```bash
ganache --version
truffle version
python -c "import fastapi, web3, ecdsa, fitz, cv2; print('All good!')"
```

### Account Access

Applicants create an account with their name, email, and password from **Login**. Their password is stored as a salted hash in the local, ignored file `middleware/accounts.json`; it is never stored as readable text. Returning applicants sign in with email and password.

Developer sign-in accepts only these four USNs: `1si23is025`, `1si23is038`, `1si23is119`, and `1si23is120`. All four use the shared development password `12345678`. The backend stores only its password hash and rejects all other USNs. This shared password is for local development only; replace it with individual credentials before any real deployment. Protected services are checked by the middleware, so changing browser storage cannot grant a role.

---

## ▶️ How to Run

### Step 1 — Start Ganache (Terminal 1)

```bash
ganache --database.dbPath ./.ganache --port 8545 --accounts 10 --deterministic
```

The `.ganache` directory preserves registrations and application decisions between Ganache restarts. `start.py` reuses saved deployed contracts and never force-resets them, so restarting the web application does not clear history. If you previously ran Ganache without a database path, its in-memory records cannot automatically be transferred into `.ganache`; an earlier forced reset also permanently removed any history that was already cleared.

Wait until you see:
✅ Connected to Ganache blockchain!
Running on http://127.0.0.1:5000

### Step 3 — Run Startup Script (Terminal 3)

```bash
python start.py
```

This automatically:
- Deploys both smart contracts to Ganache
- Updates contract addresses
- Starts the frontend after the middleware is restarted

Applicants create an account from the portal, then sign in to register identities and submit applications. The startup script no longer inserts anonymous sample citizens.

### PIN Reset Email

PIN-reset OTPs are sent to the email address on the applicant account used when registering the Aadhaar record. Configure SMTP credentials in the same terminal before starting the middleware. For Gmail, enable 2-Step Verification and create an App Password; use that App Password here, not your Google account password:

```powershell
$env:SMTP_USERNAME = "your-address@gmail.com"
$env:SMTP_PASSWORD = "your-16-character-app-password"
$env:SMTP_FROM_EMAIL = "your-address@gmail.com"
```

The default SMTP server is `smtp.gmail.com` on port `587`. `SMTP_HOST` and `SMTP_PORT` can be set to use another SMTP provider. Existing Aadhaar PIN records without an `email` field must be linked to the correct applicant account email before email-based PIN reset can be used.

### Step 4 — Restart the Middleware After start.py Asks

Stop the middleware with Ctrl+C and restart the FastAPI module:
```bash
python -m middleware.app
```

Then return to Terminal 3 and press Enter so `start.py` can finish and launch the frontend. Applicants register their identities after creating an account in the portal.

### Step 5 — Open Frontend

After setup finishes, `start.py` starts the frontend server and prints its URL (normally `http://127.0.0.1:5500/`). Open that URL in your browser. You do not need to start Live Server separately.

---

## 🌐 API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check system status |
| GET | `/stats` | View public aggregate counts |
| POST | `/auth/applicant/signup` | Create an applicant account |
| POST | `/auth/applicant/login` | Sign in as an applicant |
| POST | `/auth/developer/login` | Sign in with an authorized, provisioned developer USN |
| GET | `/auth/session` | Check the current sign-in |
| POST | `/auth/logout` | End the current sign-in |
| POST | `/aadhaar/register` | Verify e-Aadhaar PDF password and demographic fields before Aadhaar blockchain registration |
| GET | `/aadhaar/citizens` | View all registered citizens |
| GET | `/aadhaar/proof/<aadhaar_id>` | Get identity proof from blockchain |
| POST | `/passport/apply` | Apply for passport |
| GET | `/passport/progress/<aadhaar_id>` | View an applicant's matching progress |
| GET | `/passport/applications` | View all passport applications |
| GET | `/passport/validate` | Validate blockchain stats |

### Example API Calls

**Register Citizen (authenticated applicant session required):**
```bash
curl -X POST http://localhost:5000/aadhaar/register \
  -b cookies.txt \
  -F "name=Kusumitha" \
  -F "dob=10-05-2004" \
  -F "aadhaar_id=1234-5678-9012" \
  -F "pin=1234" \
  -F "gender=Female" \
  -F "mobile=9876543210" \
  -F "aadhaar_document=@/path/to/eaadhaar.pdf;type=application/pdf"
```
The PDF password is generated server-side from the posted name and DOB, so do not send a PDF password or use the application PIN as the PDF password. On success, the response includes `field_results` for Name, DOB, Gender, and Aadhaar number. Incorrect password or mismatches fail before any blockchain write.

**Frontend test:** start the application using the existing steps above, open the printed frontend URL (normally `http://127.0.0.1:5500/`), sign in as an applicant, and open **Register New Citizen**. Enter the e-Aadhaar details exactly as shown in the PDF, select the PDF, set the separate 4-digit PIN, provide the mobile number and consent, then submit. Confirm the selected filename and individual field results. For a negative check, use a PDF encrypted with a password that does not match the generated format, or deliberately change a demographic field; the form should show the password or mismatch error and must not proceed to blockchain registration.

**Apply for Passport:**
```bash
POST http://localhost:5000/passport/apply
{
    "name"      : "Rajesh Kumar",
    "aadhaar_id": "1111-2222-3333"
}
```

**Get Identity Proof:**
```bash
GET http://localhost:5000/aadhaar/proof/1111-2222-3333
```

---

## 🔒 Security Properties

| Property | Implementation |
|---|---|
| **Privacy** | Raw personal data never leaves Aadhaar Blockchain |
| **Integrity** | SHA-256 ensures any tampering changes the hash |
| **Authentication** | ECDSA signature proves identity from Aadhaar authority |
| **Immutability** | All records permanently stored on blockchain |
| **Non-repudiation** | Aadhaar authority cannot deny signing identity |
| **Cross-chain trust** | Passport chain verifies locally using public key |

---

## 🔄 Cross-Blockchain Verification Flow
- Step 1 → Citizen submits passport application
- Step 2 → Middleware contacts Aadhaar Blockchain
- Step 3 → Aadhaar Blockchain returns Hash + Signature only
- Step 4 → Middleware passes proof to Passport Blockchain
- Step 5 → Passport Blockchain verifies ECDSA signature
- Step 6 → APPROVED or REJECTED recorded on Passport Blockchain

---

## 📊 Sample Test Data

| Name | DOB | Aadhaar ID |
|---|---|---|
| Rajesh Kumar | 15-06-1985 | 1111-2222-3333 |
| Priya Sharma | 22-03-1990 | 2222-3333-4444 |
| Arun Mehta | 08-11-1978 | 3333-4444-5555 |
| Divya Nair | 30-07-1995 | 4444-5555-6666 |

---

## 🚀 Future Work

- Zero Knowledge Proofs for enhanced privacy
- Real Aadhaar UIDAI API integration
- Multi-node permissioned blockchain deployment
- Performance benchmarking against existing systems
- Biometric verification support
- Hardware Security Module for key management

---

## 📚 References

1. Cheng et al. — Secure Cross-Blockchain Interaction Framework — IEEE Access 2024
2. Gupta et al. — Blockchain-Based Digital Passport Management — SMARTCOMP 2023
3. Singh and Patel — Blockchain-Based Identity Management — Future Generation Computer Systems 2024
4. Verma and Rao — Privacy-Preserving Blockchain Authentication Using ZKP — IEEE Access 2024
5. UIDAI — Aadhaar Authentication Framework — Government of India 2022

---
