from io import BytesIO

import fitz
import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from middleware import app as middleware_app, eaadhaar_pdf


@pytest.fixture
def applicant_client(monkeypatch):
    # The PDF path is off by default; these tests exercise it explicitly.
    monkeypatch.setenv("REGISTRATION_ALLOW_PDF", "true")
    accounts = {"applicants": {}, "developers": {}}
    monkeypatch.setattr(middleware_app, "load_accounts", lambda: accounts)
    monkeypatch.setattr(
        middleware_app,
        "save_accounts",
        lambda updated: accounts.update(updated),
    )
    client = TestClient(middleware_app.app)
    response = client.post(
        "/auth/applicant/signup",
        json={
            "name": "Synthetic Test Applicant",
            "email": "synthetic@example.test",
            "password": "test-only-password",
        },
    )
    assert response.status_code == 200
    return client


def make_png():
    output = BytesIO()
    Image.new("RGB", (32, 32), "white").save(output, format="PNG")
    return output.getvalue()


def make_pdf(text="", password=None):
    document = fitz.open()
    page = document.new_page()
    if text:
        page.insert_textbox(fitz.Rect(40, 40, 550, 750), text, fontsize=12)
    options = {}
    if password:
        options = {
            "encryption": fitz.PDF_ENCRYPT_AES_256,
            "owner_pw": "test-owner-password",
            "user_pw": password,
        }
    result = document.tobytes(**options)
    document.close()
    return result


def make_image_only_pdf(password=None):
    image = Image.new("RGB", (800, 600), "white")
    draw = ImageDraw.Draw(image)
    for index, line in enumerate(
        (
            "Kusumitha Swamy",
            "DOB: 08-06-2005",
            "Gender: Female",
            "Aadhaar Number: 2345 6789 0124",
        )
    ):
        draw.text((40, 40 + index * 100), line, fill="black")
    image_bytes = BytesIO()
    image.save(image_bytes, format="PNG")

    document = fitz.open()
    page = document.new_page()
    page.insert_image(page.rect, stream=image_bytes.getvalue())
    options = {}
    if password:
        options = {
            "encryption": fitz.PDF_ENCRYPT_AES_256,
            "owner_pw": "test-owner-password",
            "user_pw": password,
        }
    result = document.tobytes(**options)
    document.close()
    return result


def registration_fields():
    return {
        "name": "KUSUMITHA",
        "dob": "10-05-2004",
        "aadhaar_id": "2345-6789-0124",
        "pin": "1234",
        "mobile": "9876543210",
        "gender": "Female",
    }


def fake_ocr_data(text, confidence="95"):
    lines = text.splitlines()
    return {
        "text": lines,
        "conf": [confidence] * len(lines),
        "block_num": [1] * len(lines),
        "par_num": [1] * len(lines),
        "line_num": list(range(1, len(lines) + 1)),
    }


def matching_pdf(password=None):
    return make_pdf(
        "Name: KUSUMITHA\nDOB: 10/05/2004\nGender: FEMALE\n"
        "Aadhaar Number: 2345 6789 0124",
        password,
    )


def install_blockchain_stub(monkeypatch):
    writes = []

    async def register(
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
        writes.append(
            (name, dob, aadhaar_id, pin, mobile, field_results, processing_status)
        )
        return JSONResponse({
            "success": True,
            "verification_status": "DETAILS_VERIFIED",
            "message": "e-Aadhaar details verified successfully.",
            "field_results": field_results,
            "processing_status": processing_status,
            "document_authenticity": "NOT_VERIFIED",
            "limitation": "UIDAI digital signature authenticity is not verified by this module.",
        })

    monkeypatch.setattr(middleware_app, "_register_verified_citizen", register)
    return writes


def test_unsigned_text_pdf_matching_details_stays_pending_and_off_chain(
    applicant_client, monkeypatch
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    response = applicant_client.post(
        "/aadhaar/register",
        data=registration_fields(),
        files={
            "aadhaar_document": (
                "protected.pdf",
                matching_pdf("KUSU2004"),
                "application/pdf",
            )
        },
    )

    body = response.json()
    assert response.status_code == 202
    assert body["result"] == "pending"
    assert body["success"] is False
    assert body["reason_codes"]["document"] == "QR_MISSING"
    assert body["field_results"] == {
        "name": "MATCH",
        "dob": "MATCH",
        "gender": "MATCH",
        "aadhaar_id": "MATCH",
    }
    assert body["document_authenticity"] == "NOT_VERIFIED"
    assert blockchain_writes == []
    assert "KUSU2004" not in response.text


def test_password_protected_scanned_pdf_uses_ocr_only_as_unsigned_fallback(
    applicant_client, monkeypatch
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: ["eng"],
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "image_to_data",
        lambda image, **kwargs: fake_ocr_data(
            "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
            "Aadhaar Number: 2345 6789 0124"
        ),
    )
    data = {
        **registration_fields(),
        "name": "Kusumitha Swamy",
        "dob": "08-06-2005",
    }
    response = applicant_client.post(
        "/aadhaar/register",
        data=data,
        files={
            "aadhaar_document": (
                "scanned.pdf",
                make_image_only_pdf("KUSU2005"),
                "application/pdf",
            )
        },
    )

    body = response.json()
    assert response.status_code == 202
    assert body["result"] == "pending"
    assert body["processing_status"]["pdf_password"] == "VERIFIED"
    assert body["processing_status"]["text_extraction"] == "NO_TEXT"
    assert body["processing_status"]["extraction_method"] == "OCR"
    assert body["processing_status"]["ocr"] == "COMPLETED"
    assert set(body["field_results"].values()) == {"MATCH"}
    assert blockchain_writes == []


def test_given_name_and_dob_format_match_but_unsigned_document_is_pending(
    applicant_client, monkeypatch
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    data = {
        **registration_fields(),
        "name": "Kusumitha Swamy",
        "dob": "08-06-2005",
    }
    pdf = make_pdf(
        "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
        "Aadhaar Number: 2345 6789 0124",
        "KUSU2005",
    )
    response = applicant_client.post(
        "/aadhaar/register",
        data=data,
        files={"aadhaar_document": ("protected.pdf", pdf, "application/pdf")},
    )

    assert response.status_code == 202
    assert response.json()["field_results"] == {
        "name": "MATCH",
        "dob": "MATCH",
        "gender": "MATCH",
        "aadhaar_id": "MATCH",
    }
    assert blockchain_writes == []
    assert "KUSU2005" not in response.text


def test_mismatching_details_fail_without_blockchain_write(
    applicant_client, monkeypatch, caplog
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    data = registration_fields()
    data["name"] = "KUSUMI"
    response = applicant_client.post(
        "/aadhaar/register",
        data=data,
        files={
            "aadhaar_document": (
                "document.pdf",
                matching_pdf(),
                "application/pdf",
            )
        },
    )

    body = response.json()
    assert response.status_code == 422
    assert body["result"] == "rejected"
    assert body["error"] == (
        "Applicant details could not be verified against the uploaded e-Aadhaar document."
    )
    assert body["field_results"]["name"] == "NO_MATCH"
    assert body["field_results"]["dob"] == "MATCH"
    assert body["field_results"]["gender"] == "MATCH"
    assert body["field_results"]["aadhaar_id"] == "MATCH"
    assert blockchain_writes == []
    assert "rejected" in caplog.text
    assert "KUSUMI" not in caplog.text
    assert "2345-6789-0124" not in caplog.text
    assert "KUSU2004" not in caplog.text


def test_missing_demographic_fields_require_review_and_do_not_write(
    applicant_client, monkeypatch
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: ["eng"],
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "image_to_data",
        lambda image, **kwargs: {
            "text": [],
            "conf": [],
            "block_num": [],
            "par_num": [],
            "line_num": [],
        },
    )
    response = applicant_client.post(
        "/aadhaar/register",
        data=registration_fields(),
        files={
            "aadhaar_document": (
                "document.pdf",
                make_image_only_pdf(),
                "application/pdf",
            )
        },
    )

    body = response.json()
    assert response.status_code == 202
    assert body["result"] == "pending"
    assert set(body["field_results"].values()) == {"REVIEW_REQUIRED"}
    assert body["manual_review_required"] is True
    assert "No UIDAI-signed QR code could be read" in body["review_message"]
    assert body["processing_status"]["ocr"] == "NO_TEXT"
    assert "Name" in body["review_required_fields"]
    assert blockchain_writes == []


def test_wrong_generated_pdf_password_is_reported_without_blockchain_write(
    applicant_client, monkeypatch
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    response = applicant_client.post(
        "/aadhaar/register",
        data=registration_fields(),
        files={
            "aadhaar_document": (
                "protected.pdf",
                matching_pdf("not-the-generated-password"),
                "application/pdf",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "Invalid e-Aadhaar PDF password"
    assert response.json()["processing_status"]["pdf_password"] == "FAILED"
    assert blockchain_writes == []


def test_json_registration_request_is_rejected(applicant_client):
    response = applicant_client.post("/aadhaar/register", json=registration_fields())
    assert response.status_code == 400
    assert response.json()["verification_status"] == "VERIFICATION_FAILED"


@pytest.mark.parametrize(
    ("filename", "content", "mime"),
    [
        ("document.jpg", b"not-pdf", "image/jpeg"),
        ("document.jpeg", b"not-pdf", "image/jpeg"),
        ("document.png", make_png(), "image/png"),
        ("renamed.pdf", make_png(), "application/pdf"),
    ],
)
def test_non_pdf_uploads_are_rejected_without_blockchain_write(
    applicant_client, monkeypatch, filename, content, mime
):
    blockchain_writes = install_blockchain_stub(monkeypatch)
    response = applicant_client.post(
        "/aadhaar/register",
        data=registration_fields(),
        files={"aadhaar_document": (filename, content, mime)},
    )
    assert response.status_code == 400
    assert response.json()["verification_status"] == "VERIFICATION_FAILED"
    assert blockchain_writes == []


def test_oversized_document_fails_before_blockchain_write(
    applicant_client, monkeypatch
):
    monkeypatch.setenv("AADHAAR_DOCUMENT_MAX_BYTES", "8")
    blockchain_writes = install_blockchain_stub(monkeypatch)
    response = applicant_client.post(
        "/aadhaar/register",
        data=registration_fields(),
        files={"aadhaar_document": ("document.pdf", make_pdf(), "application/pdf")},
    )
    assert response.status_code == 413
    assert response.json()["verification_status"] == "VERIFICATION_FAILED"
    assert blockchain_writes == []
