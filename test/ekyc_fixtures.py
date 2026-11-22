"""Synthetic Offline e-KYC fixtures: temporary keys, self-signed test certificates,
fake data. Nothing here is a UIDAI key, certificate, signature or real record."""
import io
from datetime import datetime, timedelta, timezone

import pyzipper
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

IST = timezone(timedelta(hours=5, minutes=30))
SHARE_CODE = "7391"
C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"


def make_signer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Test Signer")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def reference_id(last4, moment):
    return last4 + moment.strftime("%Y%m%d%H%M%S") + "000"


def build_xml(name="Asha Rao", dob="05-03-1990", gender="F", last4="0124", moment=None, naive_ist=False):
    moment = moment or datetime.now(timezone.utc)
    # referenceId carries no timezone, so it is written as wall-clock India time.
    moment = moment.astimezone(IST)
    return (
        f'<OfflinePaperlessKyc referenceId="{reference_id(last4, moment)}">'
        f'<UidData><Poi name="{name}" dob="{dob}" gender="{gender}" e="" m=""/>'
        f'<Poa house="1" street="Fake St" pc="560001"/><Pht>AAAA</Pht></UidData>'
        f"</OfflinePaperlessKyc>"
    ).encode()


def sign_xml(xml_bytes, key, certificate, algorithm="rsa-sha256", digest="sha256"):
    signer = XMLSigner(
        method=methods.enveloped, signature_algorithm=algorithm,
        digest_algorithm=digest, c14n_algorithm=C14N,
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    signed = signer.sign(etree.fromstring(xml_bytes), key=private_pem, cert=cert_pem)
    return etree.tostring(signed)


def _crc_table():
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ 0xEDB88320 if value & 1 else value >> 1
        table.append(value)
    return table


_CRC_TABLE = _crc_table()


def make_zipcrypto_zip(xml_bytes, share_code=SHARE_CODE, entry_name="offlineaadhaar20260101120000000.xml",
                       data_descriptor=False):
    """One DEFLATED entry, general-purpose flag bit 0 set, standard ZipCrypto,
    NO AES extra field: the shape of a real UIDAI Offline e-KYC ZIP."""
    import struct
    import zlib

    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte):
        keys[0] = (keys[0] >> 8) ^ _CRC_TABLE[(keys[0] ^ byte) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = (keys[2] >> 8) ^ _CRC_TABLE[(keys[2] ^ (keys[1] >> 24)) & 0xFF]

    def encrypt(data):
        out = bytearray()
        for byte in data:
            stream = (keys[2] | 2) & 0xFFFF
            out.append(byte ^ (((stream * (stream ^ 1)) >> 8) & 0xFF))
            update(byte)
        return bytes(out)

    for byte in share_code.encode():
        update(byte)
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    deflated = compressor.compress(xml_bytes) + compressor.flush()
    crc = zlib.crc32(xml_bytes) & 0xFFFFFFFF
    mod_time = 0x6000
    # Check byte: high CRC byte, or high mod-time byte when a data descriptor follows (flag bit 3).
    header = bytes(range(11)) + bytes([(mod_time >> 8) if data_descriptor else (crc >> 24)])
    payload = encrypt(header + deflated)
    name = entry_name.encode()
    flags = 1 | (8 if data_descriptor else 0)
    local_crc, local_csize, local_usize = (0, 0, 0) if data_descriptor else (crc, len(payload), len(xml_bytes))
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, 8, mod_time, 0x21, local_crc, local_csize, local_usize, len(name), 0) + name
    descriptor = struct.pack("<IIII", 0x08074B50, crc, len(payload), len(xml_bytes)) if data_descriptor else b""
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 8, mod_time, 0x21, crc, len(payload), len(xml_bytes),
        len(name), 0, 0, 0, 0, 0, 0,
    ) + name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local) + len(payload) + len(descriptor), 0)
    return local + payload + descriptor + central + end


def make_zip(xml_bytes, share_code=SHARE_CODE, entry_name="offlineaadhaar.xml", extra=None):
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(share_code.encode())
        archive.writestr(entry_name, xml_bytes)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


DS = "http://www.w3.org/2000/09/xmldsig#"
C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"


def sign_xml_sha1_real_shape(xml_bytes, key, certificate, digest_uri=None):
    """Reproduce the shape of a real UIDAI Offline e-KYC signature: RSA-SHA1 signature
    method, SHA-256 digest, inclusive C14N 1.0, a single enveloped-signature transform.
    signxml refuses to sign with SHA-1, so sign with SHA-256, patch the method and
    recompute the SignatureValue over the canonical SignedInfo."""
    import base64

    from cryptography.hazmat.primitives.asymmetric import padding

    signed = etree.fromstring(sign_xml(xml_bytes, key, certificate, algorithm="rsa-sha256", digest="sha256"))
    signature = signed.find(f"{{{DS}}}Signature")
    signed_info = signature.find(f"{{{DS}}}SignedInfo")
    signed_info.find(f"{{{DS}}}CanonicalizationMethod").set("Algorithm", C14N10)
    transforms = signed_info.find(f".//{{{DS}}}Transforms")
    for transform in list(transforms)[1:]:  # keep only the enveloped-signature transform
        transforms.remove(transform)
    signed_info.find(f"{{{DS}}}SignatureMethod").set("Algorithm", RSA_SHA1)
    if digest_uri:
        signed_info.find(f".//{{{DS}}}DigestMethod").set("Algorithm", digest_uri)
    canonical = etree.tostring(signed_info, method="c14n")
    value = key.sign(canonical, padding.PKCS1v15(), hashes.SHA1())
    signature.find(f"{{{DS}}}SignatureValue").text = base64.b64encode(value).decode()
    return etree.tostring(signed)
