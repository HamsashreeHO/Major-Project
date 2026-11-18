from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import fitz
import cv2
import numpy as np
from PIL import Image

from middleware.document_upload import DocumentUploadError, MAX_PDF_PAGES


MAX_RENDER_DIMENSION = 2048


@dataclass(frozen=True)
class QRDetection:
    found: bool
    count: int
    symbology: str = "QR_CODE"
    content_type: str = "UNKNOWN"
    payload: Optional[str] = None


def _read_qr_codes(image):
    try:
        rgb = np.asarray(image.convert("RGB"))
        detector = cv2.QRCodeDetector()
        found, decoded, points, _ = detector.detectAndDecodeMulti(rgb)
        if found and points is not None:
            return decoded
        decoded, points, _ = detector.detectAndDecode(rgb)
        if points is not None:
            return [decoded]
        return []
    except (cv2.error, RuntimeError, ValueError) as error:
        raise DocumentUploadError("The QR code could not be decoded") from error


def _render_pdf_pages(path, password=None):
    try:
        document = fitz.open(path)
    except (fitz.FileDataError, OSError, RuntimeError, ValueError) as error:
        raise DocumentUploadError("The uploaded PDF is invalid or corrupted") from error
    try:
        try:
            if document.is_encrypted:
                if not password:
                    raise DocumentUploadError(
                        "This PDF is password-protected. Enter its password to continue."
                    )
                if not document.authenticate(password):
                    raise DocumentUploadError(
                        "The PDF password is incorrect. Please check it and try again."
                    )
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
            for page in document:
                width = max(page.rect.width, 1)
                height = max(page.rect.height, 1)
                scale = min(2, MAX_RENDER_DIMENSION / max(width, height))
                pixmap = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
                with Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples) as image:
                    yield image.copy()
        except DocumentUploadError:
            raise
        except (fitz.FileDataError, OSError, RuntimeError, ValueError) as error:
            raise DocumentUploadError("The uploaded PDF is invalid or corrupted") from error
    finally:
        document.close()


def extract_qr_metadata(path, media_type, password=None):
    path = Path(path)
    if media_type == "application/pdf":
        images = _render_pdf_pages(path, password)
    elif media_type in ("image/jpeg", "image/png"):
        images = None
    else:
        raise DocumentUploadError("The document type is not supported for QR extraction")

    detections = []
    if images is None:
        try:
            with Image.open(path) as image:
                detections.extend(_read_qr_codes(image.convert("RGB")))
        except DocumentUploadError:
            raise
        except (OSError, ValueError) as error:
            raise DocumentUploadError("The uploaded image could not be processed") from error
    else:
        for image in images:
            with image:
                detections.extend(_read_qr_codes(image))
                if len(detections) > 1:
                    break

    if not detections:
        return QRDetection(found=False, count=0)

    first = detections[0]
    return QRDetection(
        found=True,
        count=len(detections),
        content_type="TEXT" if first else "UNKNOWN",
        payload=first if len(detections) == 1 and first else None,
    )
