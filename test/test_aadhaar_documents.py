import asyncio
from io import BytesIO

import fitz
import pytest
import cv2
from PIL import Image
from starlette.datastructures import Headers, UploadFile

from middleware.aadhaar_qr import extract_qr_metadata
from middleware.document_upload import (
    DEFAULT_MAX_UPLOAD_BYTES,
    DocumentUploadError,
    configured_max_upload_bytes,
    validated_upload,
)


def make_upload(content, filename="document.png", content_type="image/png"):
    file_object = BytesIO(content)
    return UploadFile(
        filename=filename,
        file=file_object,
        headers=Headers({"content-type": content_type}),
    )


def make_png():
    output = BytesIO()
    Image.new("RGB", (32, 32), "white").save(output, format="PNG")
    return output.getvalue()


def make_jpeg():
    output = BytesIO()
    Image.new("RGB", (32, 32), "white").save(output, format="JPEG")
    return output.getvalue()


def make_pdf():
    document = fitz.open()
    document.new_page()
    result = document.tobytes()
    document.close()
    return result


def make_pdf_with_signature_field():
    document = fitz.open()
    page = document.new_page()
    signature = fitz.Widget()
    signature.field_name = "synthetic-signature"
    signature.field_type = fitz.PDF_WIDGET_TYPE_SIGNATURE
    signature.rect = fitz.Rect(40, 40, 240, 80)
    page.add_widget(signature)
    result = document.tobytes()
    document.close()
    return result


def make_pdf_with_javascript():
    document = fitz.open()
    document.new_page()
    action_xref = document.get_new_xref()
    document.update_object(action_xref, "<< /S /JavaScript /JS (app.alert\\('x'\\)) >>")
    document.xref_set_key(document.pdf_catalog(), "OpenAction", f"{action_xref} 0 R")
    result = document.tobytes()
    document.close()
    return result


def make_synthetic_qr_png():
    qr = cv2.QRCodeEncoder_create().encode("Synthetic QR test payload")
    qr = cv2.copyMakeBorder(qr, 12, 12, 12, 12, cv2.BORDER_CONSTANT, value=255)
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    success, encoded = cv2.imencode(".png", qr)
    assert success
    return encoded.tobytes()


def make_pdf_with_synthetic_qr(password=None):
    document = fitz.open()
    page = document.new_page(width=400, height=400)
    page.insert_image(page.rect, stream=make_synthetic_qr_png())
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


async def _valid_pdf_is_staged_and_removed(tmp_path):
    upload = make_upload(make_pdf(), "document.pdf", "application/pdf")

    async with validated_upload(upload, temp_dir=tmp_path) as path:
        assert path.read_bytes().startswith(b"%PDF-")

    assert list(tmp_path.iterdir()) == []


def test_valid_pdf_is_staged_and_removed(tmp_path):
    asyncio.run(_valid_pdf_is_staged_and_removed(tmp_path))


def test_pdf_with_digital_signature_field_is_accepted(tmp_path):
    async def check_upload():
        upload = make_upload(
            make_pdf_with_signature_field(),
            "signed.pdf",
            "application/pdf",
        )
        async with validated_upload(upload, temp_dir=tmp_path) as path:
            assert path.read_bytes().startswith(b"%PDF-")
        assert list(tmp_path.iterdir()) == []

    asyncio.run(check_upload())


def test_javascript_pdf_is_rejected(tmp_path):
    async def check_upload():
        upload = make_upload(make_pdf_with_javascript(), "active.pdf", "application/pdf")
        with pytest.raises(DocumentUploadError, match="JavaScript or unsafe actions"):
            async with validated_upload(upload, temp_dir=tmp_path):
                pytest.fail("A PDF with JavaScript was accepted")
        assert list(tmp_path.iterdir()) == []

    asyncio.run(check_upload())


def test_configured_limit_cannot_exceed_ten_megabytes(monkeypatch):
    monkeypatch.setenv("AADHAAR_DOCUMENT_MAX_BYTES", str(DEFAULT_MAX_UPLOAD_BYTES * 2))
    assert configured_max_upload_bytes() == DEFAULT_MAX_UPLOAD_BYTES


@pytest.mark.parametrize(
    ("filename", "content", "mime"),
    [
        ("document.jpg", make_jpeg(), "image/jpeg"),
        ("document.jpeg", make_jpeg(), "image/jpeg"),
        ("document.png", make_png(), "image/png"),
    ],
)
def test_image_formats_are_rejected(tmp_path, filename, content, mime):
    async def check_upload():
        upload = make_upload(content, filename, mime)
        with pytest.raises(DocumentUploadError, match="Only PDF"):
            async with validated_upload(upload, temp_dir=tmp_path):
                pytest.fail("An image file was accepted")
        assert list(tmp_path.iterdir()) == []

    asyncio.run(check_upload())


@pytest.mark.parametrize(
    ("content", "mime"),
    [
        (make_jpeg(), "application/pdf"),
        (make_png(), "application/pdf"),
    ],
)
def test_renamed_image_files_are_rejected(tmp_path, content, mime):
    async def check_upload():
        upload = make_upload(content, "renamed.pdf", mime)
        with pytest.raises(DocumentUploadError, match="extension and document content"):
            async with validated_upload(upload, temp_dir=tmp_path):
                pytest.fail("An image renamed to PDF was accepted")
        assert list(tmp_path.iterdir()) == []

    asyncio.run(check_upload())


async def _unsupported_extension_is_rejected(tmp_path):
    upload = make_upload(b"not a document", "document.exe", "application/octet-stream")

    with pytest.raises(DocumentUploadError, match="Only PDF"):
        async with validated_upload(upload, temp_dir=tmp_path):
            pytest.fail("Invalid document was accepted")

    assert list(tmp_path.iterdir()) == []


def test_unsupported_extension_is_rejected(tmp_path):
    asyncio.run(_unsupported_extension_is_rejected(tmp_path))


async def _pdf_with_generic_mime_is_accepted(tmp_path):
    upload = make_upload(make_pdf(), "document.pdf", "application/octet-stream")

    async with validated_upload(upload, temp_dir=tmp_path) as path:
        assert path.read_bytes().startswith(b"%PDF-")

    assert list(tmp_path.iterdir()) == []


def test_pdf_with_generic_mime_is_accepted(tmp_path):
    asyncio.run(_pdf_with_generic_mime_is_accepted(tmp_path))


async def _extension_and_actual_file_format_must_match(tmp_path):
    upload = make_upload(make_png(), "document.pdf", "application/pdf")

    with pytest.raises(DocumentUploadError, match="extension and document content"):
        async with validated_upload(upload, temp_dir=tmp_path):
            pytest.fail("A non-PDF file with a PDF extension was accepted")

    assert list(tmp_path.iterdir()) == []


def test_extension_and_actual_file_format_must_match(tmp_path):
    asyncio.run(_extension_and_actual_file_format_must_match(tmp_path))


async def _corrupted_pdf_is_rejected(tmp_path):
    upload = make_upload(b"%PDF-1.7\nnot a real PDF", "document.pdf", "application/pdf")

    with pytest.raises(DocumentUploadError, match="invalid or corrupted"):
        async with validated_upload(upload, temp_dir=tmp_path):
            pytest.fail("Corrupted PDF was accepted")

    assert list(tmp_path.iterdir()) == []


def test_corrupted_pdf_is_rejected(tmp_path):
    asyncio.run(_corrupted_pdf_is_rejected(tmp_path))


async def _oversized_document_is_rejected_and_removed(tmp_path):
    upload = make_upload(make_pdf(), "document.pdf", "application/pdf")

    with pytest.raises(DocumentUploadError, match="exceeds the size limit") as error:
        async with validated_upload(upload, max_bytes=8, temp_dir=tmp_path):
            pytest.fail("Oversized document was accepted")

    assert error.value.status_code == 413
    assert list(tmp_path.iterdir()) == []


def test_oversized_document_is_rejected_and_removed(tmp_path):
    asyncio.run(_oversized_document_is_rejected_and_removed(tmp_path))


def test_document_over_ten_megabytes_is_rejected(tmp_path):
    async def check_upload():
        payload = make_pdf()
        payload += b" " * (DEFAULT_MAX_UPLOAD_BYTES + 1 - len(payload))
        upload = make_upload(payload, "oversized.pdf", "application/pdf")
        with pytest.raises(DocumentUploadError, match="exceeds the size limit") as error:
            async with validated_upload(upload, temp_dir=tmp_path):
                pytest.fail("A document over 10 MiB was accepted")
        assert error.value.status_code == 413
        assert list(tmp_path.iterdir()) == []

    asyncio.run(check_upload())


def test_password_protected_pdf_authenticates_before_qr_rendering(tmp_path):
    password = "test-pdf-password"
    path = tmp_path / "protected.pdf"
    path.write_bytes(make_pdf_with_synthetic_qr(password))

    result = extract_qr_metadata(path, "application/pdf", password)

    assert result.found is True
    assert result.payload == "Synthetic QR test payload"


async def _incorrect_password_is_rejected_and_removed(tmp_path):
    upload = make_upload(
        make_pdf_with_synthetic_qr("correct-password"),
        "protected.pdf",
        "application/pdf",
    )
    with pytest.raises(DocumentUploadError, match="Invalid e-Aadhaar PDF password"):
        async with validated_upload(
            upload,
            temp_dir=tmp_path,
            password="incorrect-password",
        ):
            pytest.fail("A password-protected PDF accepted an incorrect password")
    assert list(tmp_path.iterdir()) == []


def test_password_protected_pdf_rejects_incorrect_password(tmp_path):
    asyncio.run(_incorrect_password_is_rejected_and_removed(tmp_path))


def test_missing_image_qr_is_reported(monkeypatch, tmp_path):
    path = tmp_path / "empty.png"
    path.write_bytes(make_png())

    class NoQR:
        def detectAndDecodeMulti(self, image):
            return False, (), None, ()

        def detectAndDecode(self, image):
            return "", None, None

    monkeypatch.setattr(cv2, "QRCodeDetector", NoQR)

    result = extract_qr_metadata(path, "image/png")

    assert result.found is False
    assert result.count == 0


def test_qr_detection_reports_symbology_and_encoding_without_payload(monkeypatch, tmp_path):
    path = tmp_path / "qr.png"
    path.write_bytes(make_png())

    class DetectedQR:
        def detectAndDecodeMulti(self, image):
            return True, ("synthetic test payload",), object(), ()

    monkeypatch.setattr(cv2, "QRCodeDetector", DetectedQR)

    result = extract_qr_metadata(path, "image/png")

    assert result.found is True
    assert result.count == 1
    assert result.symbology == "QR_CODE"
    assert result.content_type == "TEXT"
    assert result.payload == "synthetic test payload"


def test_synthetic_image_qr_is_detected_without_exposing_its_contents(tmp_path):
    path = tmp_path / "synthetic-qr.png"
    path.write_bytes(make_synthetic_qr_png())

    result = extract_qr_metadata(path, "image/png")

    assert result.found is True
    assert result.count == 1
    assert result.symbology == "QR_CODE"
    assert result.content_type == "TEXT"
    assert result.payload == "Synthetic QR test payload"


def test_missing_pdf_qr_is_reported(monkeypatch, tmp_path):
    path = tmp_path / "empty.pdf"
    path.write_bytes(make_pdf())

    class NoQR:
        def detectAndDecodeMulti(self, image):
            return False, (), None, ()

        def detectAndDecode(self, image):
            return "", None, None

    monkeypatch.setattr(cv2, "QRCodeDetector", NoQR)

    result = extract_qr_metadata(path, "application/pdf")

    assert result.found is False
    assert result.count == 0


def test_synthetic_pdf_qr_is_detected_on_a_page(tmp_path):
    path = tmp_path / "synthetic-qr.pdf"
    path.write_bytes(make_pdf_with_synthetic_qr())

    result = extract_qr_metadata(path, "application/pdf")

    assert result.found is True
    assert result.count == 1
    assert result.symbology == "QR_CODE"


def test_pdf_signature_field_does_not_block_qr_reading(tmp_path):
    path = tmp_path / "signed.pdf"
    path.write_bytes(make_pdf_with_signature_field())

    result = extract_qr_metadata(path, "application/pdf")

    assert result.found is False
