import os
import re
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path, PureWindowsPath

import fitz
from starlette.datastructures import UploadFile


DEFAULT_MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_PDF_PAGES = 10
UPLOAD_CHUNK_BYTES = 64 * 1024

FILE_TYPES = {".pdf": "application/pdf"}
UNSAFE_PDF_ACTIONS = re.compile(r"/(?:JavaScript|JS|Launch|SubmitForm|ImportData)\b")
EMBEDDED_FILE_REFERENCES = re.compile(r"/(?:EmbeddedFiles|EF)\b")


class DocumentUploadError(ValueError):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


def configured_max_upload_bytes():
    value = os.getenv("AADHAAR_DOCUMENT_MAX_BYTES")
    if value is None:
        return DEFAULT_MAX_UPLOAD_BYTES
    try:
        limit = int(value)
    except ValueError as error:
        raise RuntimeError("AADHAAR_DOCUMENT_MAX_BYTES must be a positive integer") from error
    if limit <= 0:
        raise RuntimeError("AADHAAR_DOCUMENT_MAX_BYTES must be a positive integer")
    return min(limit, DEFAULT_MAX_UPLOAD_BYTES)


def _validate_pdf(path, password=None):
    try:
        with path.open("rb") as document_file:
            if document_file.read(5) != b"%PDF-":
                raise DocumentUploadError("The file extension and document content do not match")
        document = fitz.open(path)
    except DocumentUploadError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise DocumentUploadError("The uploaded PDF is invalid or corrupted") from error

    try:
        try:
            if document.is_encrypted:
                if not password:
                    raise DocumentUploadError("Invalid e-Aadhaar PDF password")
                if not document.authenticate(password):
                    raise DocumentUploadError("Invalid e-Aadhaar PDF password")
            if document.is_repaired:
                raise DocumentUploadError("Repaired or malformed PDF files are not accepted")
            if document.page_count < 1:
                raise DocumentUploadError("The uploaded PDF contains no pages")
            if document.page_count > MAX_PDF_PAGES:
                raise DocumentUploadError(
                    f"PDF files may contain at most {MAX_PDF_PAGES} pages",
                    413,
                )
            if document.embfile_count():
                raise DocumentUploadError("PDF files containing embedded attachments are not accepted")
            for xref in range(1, document.xref_length()):
                object_text = document.xref_object(xref, compressed=False)
                if UNSAFE_PDF_ACTIONS.search(object_text):
                    raise DocumentUploadError(
                        "PDF files containing JavaScript or unsafe actions are not accepted"
                    )
                if EMBEDDED_FILE_REFERENCES.search(object_text):
                    raise DocumentUploadError(
                        "PDF files containing embedded attachments are not accepted"
                    )
            for page in document:
                if page.rect.width <= 0 or page.rect.height <= 0:
                    raise DocumentUploadError("The uploaded PDF contains an invalid page")
        except DocumentUploadError:
            raise
        except (fitz.FileDataError, OSError, RuntimeError, ValueError) as error:
            raise DocumentUploadError("The uploaded PDF is invalid or corrupted") from error
    finally:
        document.close()


def _validate_content(path, extension, password=None):
    if extension != ".pdf":
        raise DocumentUploadError("Only PDF documents are accepted")
    _validate_pdf(path, password)


@asynccontextmanager
async def validated_upload(upload, max_bytes=None, temp_dir=None, password=None):
    if not isinstance(upload, UploadFile):
        raise DocumentUploadError("Upload an Aadhaar document")

    filename = str(upload.filename or "")
    extension = PureWindowsPath(filename).suffix.lower()
    file_type = FILE_TYPES.get(extension)
    if not file_type:
        raise DocumentUploadError("Only PDF documents are accepted")

    expected_mime = file_type
    supplied_mime = (upload.content_type or "").split(";", 1)[0].strip().lower()
    if supplied_mime not in ("", expected_mime, "application/octet-stream"):
        raise DocumentUploadError("The declared file type does not match an allowed document type")

    limit = max_bytes if max_bytes is not None else configured_max_upload_bytes()
    if limit <= 0:
        raise RuntimeError("The document upload limit must be a positive integer")

    try:
        with tempfile.TemporaryDirectory(prefix="aadhaar-upload-", dir=temp_dir) as directory:
            path = Path(directory) / f"document{extension}"
            total_bytes = 0
            await upload.seek(0)
            with path.open("xb") as destination:
                while True:
                    chunk = await upload.read(UPLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > limit:
                        raise DocumentUploadError("The uploaded document exceeds the size limit", 413)
                    destination.write(chunk)

            if total_bytes == 0:
                raise DocumentUploadError("The uploaded document is empty")
            _validate_content(path, extension, password)
            yield path
    finally:
        await upload.close()
