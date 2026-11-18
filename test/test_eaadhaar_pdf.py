from io import BytesIO

import fitz
import pytest
from PIL import Image, ImageDraw

from middleware import eaadhaar_pdf
from middleware.eaadhaar_pdf import (
    compare_applicant_details,
    extract_eaadhaar_details,
    generate_eaadhaar_password,
)


def make_pdf(path, text):
    document = fitz.open()
    page = document.new_page()
    page.insert_textbox(fitz.Rect(40, 40, 550, 750), text, fontsize=12)
    document.save(path)
    document.close()


def make_image_pdf(path, text):
    image = Image.new("RGB", (1200, 800), "white")
    draw = ImageDraw.Draw(image)
    for index, line in enumerate(text.splitlines()):
        draw.text((60, 60 + index * 80), line, fill="black")
    image_stream = BytesIO()
    image.save(image_stream, format="PNG")

    document = fitz.open()
    page = document.new_page()
    page.insert_image(page.rect, stream=image_stream.getvalue())
    document.save(path)
    document.close()


def fake_tesseract_data(text, confidence="95"):
    lines = text.splitlines()
    return {
        "text": lines,
        "conf": [confidence] * len(lines),
        "left": [0] * len(lines),
        "top": [index * 30 for index in range(len(lines))],
        "width": [max(1, len(line) * 8) for line in lines],
        "height": [20] * len(lines),
        "block_num": [1] * len(lines),
        "par_num": [1] * len(lines),
        "line_num": list(range(1, len(lines) + 1)),
    }


@pytest.mark.parametrize(
    ("name", "dob", "expected"),
    [
        ("SURESH KUMAR", "15-08-1990", "SURE1990"),
        ("KUSUMITHA", "10-05-2004", "KUSU2004"),
    ],
)
def test_uidai_password_format(name, dob, expected):
    assert generate_eaadhaar_password(name, dob) == expected


def test_extracts_labelled_demographics_and_matches_exactly(tmp_path):
    path = tmp_path / "aadhaar.pdf"
    make_pdf(
        path,
        "Name: Suresh Kumar\nDOB\n15-08-1990\nGender: MALE\n"
        "Aadhaar Number: 1234 5678 9012",
    )

    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "SURESH   KUMAR",
        "15/08/1990",
        "Male",
        "1234-5678-9012",
    )

    assert results == {
        "name": "MATCH",
        "dob": "MATCH",
        "gender": "MATCH",
        "aadhaar_id": "MATCH",
    }


def test_repeated_layout_name_is_used_but_to_line_is_not_a_name(tmp_path):
    path = tmp_path / "repeated-name.pdf"
    make_pdf(
        path,
        "To\nUnrelated Address\nSample Person\nDOB: 08/06/2005\n"
        "Gender: Female\nSample Person",
    )
    document = fitz.open(path)
    try:
        repeated_name = eaadhaar_pdf._repeated_name_from_document(document)
    finally:
        document.close()

    assert eaadhaar_pdf._details_from_text("To\nUnrelated Address")["name"] is None
    assert eaadhaar_pdf._normalize_name(repeated_name) == "sampleperson"


def test_unique_name_line_above_gender_is_used_when_not_repeated(tmp_path):
    path = tmp_path / "single-layout-name.pdf"
    make_pdf(path, "Vidya\nDOB: 24-12-2004\nGender: Female")
    document = fitz.open(path)
    try:
        extracted_name = eaadhaar_pdf._repeated_name_from_document(document)
    finally:
        document.close()

    assert eaadhaar_pdf._normalize_name(extracted_name) == "vidya"


def test_multiple_names_near_gender_require_manual_review(tmp_path):
    path = tmp_path / "ambiguous-layout-name.pdf"
    make_pdf(path, "Vidya\nAnita\nDOB: 24-12-2004\nGender: Female")
    document = fitz.open(path)
    try:
        extracted_name = eaadhaar_pdf._repeated_name_from_document(document)
    finally:
        document.close()

    assert extracted_name is None


def test_normalizes_spaces_case_date_separators_and_aadhaar_format(tmp_path):
    path = tmp_path / "layout-variation.pdf"
    make_pdf(
        path,
        "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
        "Aadhaar Number: 1234-5678-9012",
    )

    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "Kusumitha Swamy",
        "08-06-2005",
        "Female",
        "1234 5678 9012",
    )

    assert generate_eaadhaar_password("Kusumitha Swamy", "08-06-2005") == "KUSU2005"
    assert results == {
        "name": "MATCH",
        "dob": "MATCH",
        "gender": "MATCH",
        "aadhaar_id": "MATCH",
    }


def test_selectable_text_does_not_invoke_ocr(tmp_path, monkeypatch):
    path = tmp_path / "selectable.pdf"
    make_pdf(
        path,
        "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: Female\n"
        "Aadhaar Number: 1234 5678 9012",
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: pytest.fail("OCR should not run when text contains every field"),
    )

    extracted = extract_eaadhaar_details(path)

    assert extracted["extraction_method"] == "TEXT"
    assert extracted["ocr_status"] == "NOT_NEEDED"
    assert set(extracted["field_sources"].values()) == {"TEXT"}


def test_image_pdf_uses_high_confidence_local_ocr_fallback(tmp_path, monkeypatch):
    path = tmp_path / "scanned.pdf"
    make_image_pdf(
        path,
        "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
        "Aadhaar Number: 1234 5678 9012",
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: ["eng"],
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "image_to_data",
        lambda image, **kwargs: fake_tesseract_data(
            "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
            "Aadhaar Number: 1234 5678 9012"
        ),
    )

    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "Kusumitha Swamy",
        "08-06-2005",
        "Female",
        "1234-5678-9012",
    )

    assert extracted["extraction_method"] == "OCR"
    assert extracted["ocr_status"] == "COMPLETED"
    assert extracted["field_sources"] == {
        "name": "OCR",
        "dob": "OCR",
        "gender": "OCR",
        "aadhaar_id": "OCR",
    }
    assert extracted["ocr_confidence"]["aadhaar_id"] == 95.0
    assert set(results.values()) == {"MATCH"}


def test_low_confidence_ocr_requires_manual_review(tmp_path, monkeypatch):
    path = tmp_path / "low-confidence.pdf"
    make_image_pdf(
        path,
        "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
        "Aadhaar Number: 1234 5678 9012",
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: ["eng"],
    )
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "image_to_data",
        lambda image, **kwargs: fake_tesseract_data(
            "Name: KusumithaSwamy\nDOB: 08/06/2005\nGender: FEMALE\n"
            "Aadhaar Number: 1234 5678 9012",
            confidence="35",
        ),
    )

    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "Kusumitha Swamy",
        "08-06-2005",
        "Female",
        "1234-5678-9012",
    )

    assert extracted["ocr_status"] == "LOW_CONFIDENCE"
    assert set(results.values()) == {"REVIEW_REQUIRED"}


def test_ocr_line_confidence_uses_mean_instead_of_one_weak_word():
    data = {
        "text": ["Name:", "Kusumitha", "Swamy"],
        "conf": ["20", "95", "95"],
        "block_num": [1, 1, 1],
        "par_num": [1, 1, 1],
        "line_num": [1, 1, 1],
    }

    text, line_confidences = eaadhaar_pdf._ocr_data_text(data)
    details, confidences, low_confidence_fields = (
        eaadhaar_pdf._details_from_ocr_text(text, line_confidences)
    )

    assert details["name"] == "Kusumitha Swamy"
    assert confidences["name"] == 70.0
    assert "name" not in low_confidence_fields


def test_ocr_extracts_unique_date_and_gender_without_same_line_labels():
    data = fake_tesseract_data(
        "08/06/2005\nFemale\nAadhaar Number: 1234 5678 9012",
    )

    details, confidences, low_confidence_fields = eaadhaar_pdf._details_from_ocr_data(data)

    assert details["dob"] == "2005-06-08"
    assert details["gender"] == "female"
    assert details["aadhaar_id"] == "123456789012"
    assert confidences["dob"] == 95.0
    assert confidences["gender"] == 95.0
    assert not low_confidence_fields


def test_ocr_extracts_one_name_candidate_near_demographic_fields():
    data = fake_tesseract_data(
        "Vidya Sharma\n08/06/2005\nFemale\nAadhaar Number: 1234 5678 9012",
    )

    details, confidences, _ = eaadhaar_pdf._details_from_ocr_data(data)

    assert details["name"] == "Vidya Sharma"
    assert confidences["name"] == 95.0


def test_ocr_requires_review_when_multiple_names_are_near_demographic_fields():
    data = fake_tesseract_data(
        "Vidya Sharma\nAnita Rao\n08/06/2005\nFemale\n"
        "Aadhaar Number: 1234 5678 9012",
    )

    details, _, _ = eaadhaar_pdf._details_from_ocr_data(data)

    assert details["name"] is None


def test_lower_left_ocr_crop_recovers_layout_fields(tmp_path, monkeypatch):
    path = tmp_path / "layout-scanned.pdf"
    make_image_pdf(path, "Document header")
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: ["eng"],
    )

    def fake_image_to_data(image, **kwargs):
        if image.shape[0] > 1500:
            return fake_tesseract_data("Document header")
        return fake_tesseract_data(
            "Name: Suresh Kumar\nDOB: 15/08/1990\nGender: Male\n"
            "Aadhaar Number: 1234 5678 9012",
        )

    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "image_to_data",
        fake_image_to_data,
    )

    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "Suresh Kumar",
        "15-08-1990",
        "Male",
        "1234-5678-9012",
    )

    assert extracted["ocr_status"] == "COMPLETED"
    assert set(results.values()) == {"MATCH"}


def test_ocr_engine_unavailable_is_reported_without_acceptance(tmp_path, monkeypatch):
    path = tmp_path / "ocr-unavailable.pdf"
    make_image_pdf(path, "Kusumitha Swamy")

    def missing_engine(config):
        raise OSError("test engine unavailable")

    monkeypatch.setattr(eaadhaar_pdf.pytesseract, "get_languages", missing_engine)
    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "Kusumitha Swamy",
        "08-06-2005",
        "Female",
        "1234-5678-9012",
    )

    assert extracted["ocr_status"] == "UNAVAILABLE"
    assert set(results.values()) == {"REVIEW_REQUIRED"}


def test_tesseract_is_found_in_standard_windows_install_path(tmp_path, monkeypatch):
    executable = tmp_path / "Tesseract-OCR" / "tesseract.exe"
    executable.parent.mkdir()
    executable.touch()
    monkeypatch.setattr(eaadhaar_pdf.shutil, "which", lambda _: None)
    monkeypatch.setattr(eaadhaar_pdf.sys, "platform", "win32")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract.pytesseract,
        "tesseract_cmd",
        "tesseract",
    )

    eaadhaar_pdf._configure_tesseract()

    assert eaadhaar_pdf.pytesseract.pytesseract.tesseract_cmd == str(executable)


def test_ocr_runtime_failure_is_reported_as_review(tmp_path, monkeypatch):
    path = tmp_path / "ocr-failed.pdf"
    make_image_pdf(path, "Kusumitha Swamy")
    monkeypatch.setattr(
        eaadhaar_pdf.pytesseract,
        "get_languages",
        lambda config: ["eng"],
    )

    def fail_ocr(image, **kwargs):
        raise RuntimeError("synthetic OCR failure")

    monkeypatch.setattr(eaadhaar_pdf.pytesseract, "image_to_data", fail_ocr)
    extracted = extract_eaadhaar_details(path)

    assert extracted["ocr_status"] == "FAILED"
    assert "synthetic OCR failure" not in extracted["ocr_message"]


def test_year_of_birth_is_compared_without_accepting_name_substrings(tmp_path):
    path = tmp_path / "aadhaar.pdf"
    make_pdf(
        path,
        "Name\nKUSUMITHA\nYear of Birth: 2004\nGender\nFemale\n"
        "Aadhaar: 123456789012",
    )

    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "KUSU",
        "10-05-2004",
        "Female",
        "1234-5678-9012",
    )

    assert results == {
        "name": "NO_MATCH",
        "dob": "MATCH",
        "gender": "MATCH",
        "aadhaar_id": "MATCH",
    }


def test_missing_or_ambiguous_values_require_review(tmp_path):
    path = tmp_path / "ambiguous.pdf"
    make_pdf(
        path,
        "Name: KUSUMITHA\nName: KUSUMI\nDOB: 2004\nGender: Female",
    )
    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "KUSUMITHA",
        "10-05-2004",
        "Female",
        "1234-5678-9012",
    )

    assert results["name"] == "REVIEW_REQUIRED"
    assert results["aadhaar_id"] == "REVIEW_REQUIRED"


def test_invalid_full_dob_is_not_downgraded_to_matching_year(tmp_path):
    path = tmp_path / "invalid-date.pdf"
    make_pdf(path, "Name: KUSUMITHA\nDOB: 31-02-2004\nGender: Female")
    extracted = extract_eaadhaar_details(path)
    results = compare_applicant_details(
        extracted,
        "KUSUMITHA",
        "10-05-2004",
        "Female",
        "1234-5678-9012",
    )

    assert results["dob"] == "REVIEW_REQUIRED"
