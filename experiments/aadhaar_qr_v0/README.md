# Aadhaar Secure QR Version 0 experiment

This directory is isolated from the production registration path. It implements
an experimental parser for the March 2019 UIDAI Secure QR Code Specification,
Version 0. It does not claim support for later QR formats and does not enable
registration.

## Source and sample

The cited UIDAI PDF is
[User_manulal_QR_Code_15032019.pdf](https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf).
The live URL returned HTTP 404 during this experiment, and the old UIDAI host
returned HTTP 503. The official-origin PDF was therefore read from its Internet
Archive snapshot at
[2026-07-10](https://web.archive.org/web/20260710134716id_/https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf).
Its title page identifies UIDAI, March 2019; page 2 identifies Version 0.
The decimal sample on pages 6-7 is stored as
`fixtures/official_sample_decimal.txt`. The fixture SHA-256 is
`24e9c3dfc0546525ba12f4dc3d3a36b622182b40bf6f8a6ef163f4d2d0eb3311`.

The sample converts to 1,306 bytes using a positive, big-endian integer
representation. The specification says to convert a base-10 value to a
BigInteger and then to a byte array, but does not state signedness or byte
order. This experiment uses the canonical big-endian representation for a
positive integer (with a leading sign byte when Java BigInteger requires one).

## Implemented format steps

As described in sections 2.2, 3.1, and 3.2 (PDF pages 4-6):

- The first 16 fields are split on byte `0xff`, then decoded as ISO-8859-1.
- The photograph bytes follow the VTC delimiter.
- There are zero, one, or two 32-byte contact hashes based on the indicator.
- The final 256 bytes are treated as the signature.
- Signed data is the decompressed byte sequence with only those final 256
  signature bytes removed.
- `SHA256withRSA` is implemented as RSA PKCS#1 v1.5 with SHA-256, the standard
  meaning of that Java signature algorithm name.

The parser preserves the contact hashes as uninterpreted bytes and does not
label them email/mobile: the document disagrees about indicator meanings
(page 4 vs page 6) and about hash ordering (page 5 vs page 6). It also uses
the document's phrase “signature” rather than its inconsistent field label
“Signature HASH”.

## Unresolved specification details and sample result

The document says “Decompress the byte array” but does not name a compression
algorithm, container, or parameters. The diagnostic runner explicitly probes
GZIP, zlib-wrapped DEFLATE, and raw DEFLATE; these are probes, not an asserted
UIDAI rule and not automatic decoder fallbacks. None fully decompresses the
published sample after the stated integer conversion. Consequently, the sample
cannot be parsed into fields/signature under a documented procedure, and
mathematical signature verification against it was not attempted.

The parser's `decompress_payload` requires a caller-selected codec. Its zlib
use in unit tests is a synthetic fixture only; it does not imply that Version 0
uses zlib. No payload alteration or algorithm substitution is used to make the
sample pass.

## Verification versus trust

Unit tests generate a temporary RSA key solely for synthetic fixtures and
verify signatures over synthetic data to exercise the verifier and tamper
rejection. These are not UIDAI keys or signatures. The official sample was not
mathematically verified with
`middleware/certificates/uidai_offline_publickey_2026.cer`.

Reading a certificate's public key and verifying a signature mathematically
does not validate the certificate chain, its trust anchor, revocation status,
or whether UIDAI intended it for this Version 0 sample. This experiment does
not implement those checks. Windows `certutil -verify -urlfetch` built a
certificate chain to CCA India 2022 and listed the Document Signing policy, but
could not check revocation because the revocation server was offline. This is
an environment-specific and incomplete trust result, not production trust
validation. The `.cer` file is PEM encoded despite its extension; the
certificate loader accepts either DER or PEM. Production UIDAI verification
remains unimplemented and registration remains fail-closed.

## Run

From the repository root, install the isolated experiment dependencies and
execute:

```powershell
python -m pip install -r experiments\aadhaar_qr_v0\requirements.txt
python experiments\aadhaar_qr_v0\probe_official_sample.py
python -m pytest experiments\aadhaar_qr_v0\test_v0.py -q
```
