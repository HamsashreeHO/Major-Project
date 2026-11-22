import os
import re
import shutil
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

import cv2
import fitz
import numpy as np
import pytesseract

from middleware.document_upload import DocumentUploadError


_DATE_FORMATS = ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d")
_DATE_PATTERN = re.compile(r"(?<!\d)(\d{1,2}[-/]\d{1,2}[-/]\d{4}|\d{4}-\d{2}-\d{2})(?!\d)")
_YEAR_PATTERN = re.compile(r"(?<!\d)(\d{4})(?!\d)")
_FIELD_LABELS = {
    "dob": re.compile(r"^(?:dob|date\s+of\s+birth|year\s+of\s+birth|yob)\s*:?\s*(.*)$", re.I),
    "gender": re.compile(r"^gender\s*:?\s*(.*)$", re.I),
    "name": re.compile(r"^(?:name|applicant\s+name)\s*:?\s*(.*)$", re.I),
}
_AADHAAR_PATTERN = re.compile(r"(?<!\d)(?:\d[\s-]*){11}\d(?!\d)")
_OCR_DPI = 300
_OCR_MAX_DIMENSION = 5000
_MIN_OCR_CONFIDENCE = 60.0
_REQUIRED_FIELDS = ("name", "dob", "gender", "aadhaar_id")
_NAME_LINE_STOP_WORDS = {
    "aadhaar",
    "applicant",
    "authority",
    "birth",
    "date",
    "dob",
    "female",
    "gender",
    "government",
    "india",
    "male",
    "name",
    "number",
    "of",
    "to",
    "uidai",
    "unique",
    "year",
}


def _configure_tesseract():
    if shutil.which("tesseract"):
        return
    if sys.platform != "win32":
        return

    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    install_dirs = [Path(program_files) / "Tesseract-OCR"]
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if program_files_x86:
        install_dirs.append(Path(program_files_x86) / "Tesseract-OCR")

    for install_dir in install_dirs:
        executable = install_dir / "tesseract.exe"
        if executable.is_file():
            pytesseract.pytesseract.tesseract_cmd = str(executable)
            return


_configure_tesseract()


def parse_applicant_dob(value):
    value = str(value or "").strip()
    for date_format in _DATE_FORMATS:
        try:
            return datetime.strptime(value, date_format).date()
        except ValueError:
            pass
    raise ValueError("Enter a valid date of birth")


def generate_eaadhaar_password(name, dob):
    compact_name = "".join(
        character
        for character in unicodedata.normalize("NFKC", str(name or "")).upper()
        if character.isalpha()
    )
    if len(compact_name) < 4:
        raise ValueError("The name must contain at least four characters")
    birth_date = parse_applicant_dob(dob)
    return compact_name[:4] + f"{birth_date.year:04d}"


def _normalized_lines(text):
    return [
        re.sub(r"\s+", " ", line.replace("\u00a0", " ")).strip()
        for line in text.splitlines()
        if line.strip()
    ]


def _field_candidates(lines, field):
    return [value for value, _ in _field_candidate_records(lines, field)]


def _field_candidate_records(lines, field):
    matcher = _FIELD_LABELS[field]
    candidates = []
    for index, line in enumerate(lines):
        match = matcher.match(line)
        if not match:
            continue
        value = match.group(1).strip(" :\t-")
        if value:
            candidates.append((value, index))
        elif index + 1 < len(lines):
            candidates.append((lines[index + 1], index + 1))

    return candidates


def _repeated_name_from_document(document):
    eligible_names = {}
    positioned_names = {}
    for page in document:
        rows = {}
        words = page.get_text("words", sort=True)
        candidates = {}
        to_positions = [
            (word[1] + word[3]) / 2
            for word in words
            if word[4].casefold().strip(" :,-") == "to"
        ]
        gender_positions = [
            (word[1] + word[3]) / 2
            for word in words
            if _canonical_gender(word[4]) is not None
        ]
        gender_points = [
            (
                (word[0] + word[2]) / 2,
                (word[1] + word[3]) / 2,
            )
            for word in words
            if _canonical_gender(word[4]) is not None
        ]
        date_points = [
            (
                (word[0] + word[2]) / 2,
                (word[1] + word[3]) / 2,
            )
            for word in words
            if any(
                _parse_dob_candidate(value) is not None
                for value in _DATE_PATTERN.findall(word[4])
            )
        ]
        for word in words:
            rows.setdefault((word[5], word[6]), []).append(word)
        for words in rows.values():
            row_words = sorted(words, key=lambda item: item[7])
            tokens = [word[4].strip(".,:;()") for word in row_words]
            if (
                not 1 <= len(tokens) <= 4
                or any(not token.isalpha() for token in tokens)
                or any(token.casefold() in _NAME_LINE_STOP_WORDS for token in tokens)
            ):
                continue
            value = " ".join(tokens)
            row_x = (row_words[0][0] + row_words[-1][2]) / 2
            row_y = (row_words[0][1] + row_words[0][3]) / 2
            if len(tokens) >= 2:
                positions = candidates.setdefault(_normalize_name(value), [])
                positions.append((value, row_y))

            near_date = not date_points or any(
                abs(row_x - date_x) <= 80
                and -10 <= date_y - row_y <= 60
                for date_x, date_y in date_points
            )
            if near_date and any(
                abs(row_x - gender_x) <= 80
                and 0 <= gender_y - row_y <= 60
                for gender_x, gender_y in gender_points
            ):
                positioned_names[_normalize_name(value)] = value

        for normalized, occurrences in candidates.items():
            if len(occurrences) < 2:
                continue
            for _, address_y in occurrences:
                follows_to = any(0 <= address_y - to_y <= 60 for to_y in to_positions)
                if not follows_to:
                    continue
                for identity_value, identity_y in occurrences:
                    if address_y == identity_y:
                        continue
                    if any(abs(identity_y - gender_y) <= 60 for gender_y in gender_positions):
                        eligible_names[normalized] = identity_value
                        break

    if len(eligible_names) == 1:
        return next(iter(eligible_names.values()))
    if eligible_names:
        return None
    return next(iter(positioned_names.values())) if len(positioned_names) == 1 else None


def _normalize_name(value):
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return "".join(normalized.split())


def _unique(values, normalize=None):
    if not values:
        return None
    normalized_values = {
        normalize(value) if normalize else value
        for value in values
    }
    return values[0] if len(normalized_values) == 1 else None


def _extract_dob(lines):
    candidates = []
    for value in _field_candidates(lines, "dob"):
        parsed = _parse_dob_candidate(value)
        if parsed is None:
            if _DATE_PATTERN.search(value):
                return None
            continue
        candidates.append(parsed)
    return _unique(candidates)


def _parse_dob_candidate(value):
    full_dates = _DATE_PATTERN.findall(value)
    if full_dates:
        parsed = []
        for full_date in full_dates:
            try:
                parsed.append(parse_applicant_dob(full_date).isoformat())
            except ValueError:
                continue
        if len(parsed) != len(full_dates):
            return None
        return _unique(parsed)
    years = _YEAR_PATTERN.findall(value)
    return years[0] if years else None


def _canonical_gender(value):
    aliases = {
        "m": "male",
        "male": "male",
        "f": "female",
        "female": "female",
        "transgender": "other",
        "trans": "other",
        "other": "other",
    }
    matches = {
        aliases[token]
        for token in re.findall(r"[a-z]+", str(value or "").casefold())
        if token in aliases
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _details_from_text(text):
    lines = _normalized_lines(text)
    gender_candidates = [
        canonical
        for value in _field_candidates(lines, "gender")
        if (canonical := _canonical_gender(value)) is not None
    ]
    aadhaar_candidates = {
        re.sub(r"\D", "", match)
        for match in _AADHAAR_PATTERN.findall(text)
    }
    return {
        "name": _unique(_field_candidates(lines, "name"), _normalize_name),
        "dob": _extract_dob(lines),
        "gender": _unique(gender_candidates),
        "aadhaar_id": (
            next(iter(aadhaar_candidates)) if len(aadhaar_candidates) == 1 else None
        ),
        "text_available": bool(text.strip()),
    }


def _details_from_ocr_text(text, line_confidences):
    lines = _normalized_lines(text)
    confidence_by_field = {}
    low_confidence_fields = set()

    def candidate_confidence(line_index):
        if line_index >= len(line_confidences):
            return 0.0
        return line_confidences[line_index]

    details = {}
    for field in ("name", "dob", "gender"):
        candidate_values = []
        candidate_confidences = []
        for value, line_index in _field_candidate_records(lines, field):
            if field == "name":
                normalized = value.strip()
            elif field == "dob":
                normalized = _parse_dob_candidate(value)
                if normalized is None and _DATE_PATTERN.search(value):
                    low_confidence_fields.add(field)
                    continue
            else:
                normalized = _canonical_gender(value)
                if normalized is None:
                    continue
            if normalized is None:
                continue
            confidence = candidate_confidence(line_index)
            if confidence < _MIN_OCR_CONFIDENCE:
                low_confidence_fields.add(field)
                continue
            candidate_values.append(normalized)
            candidate_confidences.append(confidence)
        details[field] = _unique(candidate_values, _field_normalizer(field))
        confidence_by_field[field] = (
            min(candidate_confidences) if details[field] is not None else None
        )

    line_starts = [0]
    for match in re.finditer("\n", text):
        line_starts.append(match.end())

    def line_for_position(position):
        return max(index for index, start in enumerate(line_starts) if start <= position)

    aadhaar_candidates = []
    aadhaar_confidences = []
    for match in _AADHAAR_PATTERN.finditer(text):
        first_line = line_for_position(match.start())
        last_line = line_for_position(max(match.end() - 1, match.start()))
        confidence = min(
            candidate_confidence(index)
            for index in range(first_line, last_line + 1)
        )
        if confidence < _MIN_OCR_CONFIDENCE:
            low_confidence_fields.add("aadhaar_id")
            continue
        aadhaar_candidates.append(re.sub(r"\D", "", match.group(0)))
        aadhaar_confidences.append(confidence)
    details["aadhaar_id"] = _unique(aadhaar_candidates)
    confidence_by_field["aadhaar_id"] = (
        min(aadhaar_confidences) if details["aadhaar_id"] is not None else None
    )
    details["text_available"] = bool(text.strip())
    return details, confidence_by_field, low_confidence_fields


def _details_from_ocr_data(data):
    text, line_confidences = _ocr_data_text(data)
    details, confidence_by_field, low_confidence_fields = _details_from_ocr_text(
        text,
        line_confidences,
    )

    text_words = data.get("text", [])
    groups = {}
    for index, value in enumerate(text_words):
        if not str(value).strip():
            continue
        key = tuple(
            data.get(name, [index] * len(text_words))[index]
            for name in ("block_num", "par_num", "line_num")
        )
        groups.setdefault(key, []).append(index)

    def word_confidence(index):
        try:
            return float(data.get("conf", [])[index])
        except (IndexError, TypeError, ValueError):
            return -1

    def word_center(index):
        try:
            left = float(data.get("left", [])[index])
            top = float(data.get("top", [])[index])
            width = float(data.get("width", [])[index])
            height = float(data.get("height", [])[index])
            return left + width / 2, top + height / 2
        except (IndexError, TypeError, ValueError):
            return 0.0, float(index * 30)

    line_records = []
    for indices in groups.values():
        line = " ".join(str(text_words[index]).strip() for index in indices)
        confidences = [
            word_confidence(index)
            for index in indices
            if word_confidence(index) >= 0
        ]
        confidence = (
            float(np.mean(confidences)) if confidences else 0.0
        )
        centers = [word_center(index) for index in indices]
        center = (
            sum(point[0] for point in centers) / len(centers),
            sum(point[1] for point in centers) / len(centers),
        )
        line_records.append((line, confidence, center))

    date_records = []
    gender_records = []
    for index, value in enumerate(text_words):
        confidence = word_confidence(index)
        if confidence < _MIN_OCR_CONFIDENCE:
            continue
        center = word_center(index)
        for full_date in _DATE_PATTERN.findall(str(value)):
            parsed = _parse_dob_candidate(full_date)
            if parsed is not None:
                date_records.append((parsed, confidence, center))
        gender = _canonical_gender(value)
        if gender is not None:
            gender_records.append((gender, confidence, center))

    pairs = [
        (dob, dob_confidence, gender, gender_confidence)
        for dob, dob_confidence, dob_center in date_records
        for gender, gender_confidence, gender_center in gender_records
        if (
            (dob_center[0] - gender_center[0]) ** 2
            + (dob_center[1] - gender_center[1]) ** 2
        ) <= 300 ** 2
    ]

    if details["name"] is None:
        positioned_names = []
        demographic_anchors = [
            (
                (dob_center[0] + gender_center[0]) / 2,
                (dob_center[1] + gender_center[1]) / 2,
            )
            for _, _, dob_center in date_records
            for _, _, gender_center in gender_records
            if (
                (dob_center[0] - gender_center[0]) ** 2
                + (dob_center[1] - gender_center[1]) ** 2
            ) <= 300 ** 2
        ]
        for line, confidence, center in line_records:
            if confidence < _MIN_OCR_CONFIDENCE:
                continue
            tokens = [token.strip(".,:;()") for token in line.split()]
            if (
                not 1 <= len(tokens) <= 4
                or any(not token.isalpha() for token in tokens)
                or any(
                    token.casefold() in _NAME_LINE_STOP_WORDS
                    for token in tokens
                )
            ):
                continue
            if any(
                abs(center[0] - anchor_x) <= 500
                and -30 <= anchor_y - center[1] <= 240
                for anchor_x, anchor_y in demographic_anchors
            ):
                positioned_names.append((" ".join(tokens), confidence))
        details["name"] = _unique(
            [value for value, _ in positioned_names],
            _normalize_name,
        )
        if details["name"] is not None:
            confidence_by_field["name"] = min(
                confidence
                for value, confidence in positioned_names
                if _normalize_name(value) == _normalize_name(details["name"])
            )

    if details["dob"] is None:
        dob_candidates = [dob for dob, _, _, _ in pairs]
        details["dob"] = _unique(dob_candidates)
        if details["dob"] is not None:
            confidence_by_field["dob"] = min(
                confidence
                for dob, confidence, _, _ in pairs
                if dob == details["dob"]
            )

    if details["gender"] is None:
        gender_candidates = [gender for _, _, gender, _ in pairs]
        details["gender"] = _unique(gender_candidates)
        if details["gender"] is not None:
            confidence_by_field["gender"] = min(
                confidence
                for _, _, gender, confidence in pairs
                if gender == details["gender"]
            )

    aadhaar_labels = [
        (index, center)
        for index, (line, confidence, center) in enumerate(line_records)
        if confidence >= _MIN_OCR_CONFIDENCE
        and re.search(r"\baadhaar\b", line, re.I)
    ]
    aadhaar_candidates = []
    aadhaar_confidences = []
    for index, (line, confidence, center) in enumerate(line_records):
        if confidence < _MIN_OCR_CONFIDENCE:
            continue
        if not any(
            abs(index - label_index) <= 4
            and (center[0] - label_center[0]) ** 2
            + (center[1] - label_center[1]) ** 2
            <= 350 ** 2
            for label_index, label_center in aadhaar_labels
        ):
            continue
        for value in _AADHAAR_PATTERN.findall(line):
            aadhaar_candidates.append(re.sub(r"\D", "", value))
            aadhaar_confidences.append(confidence)
    details["aadhaar_id"] = _unique(aadhaar_candidates)
    confidence_by_field["aadhaar_id"] = (
        min(aadhaar_confidences) if details["aadhaar_id"] is not None else None
    )

    return details, confidence_by_field, low_confidence_fields


def _field_normalizer(field):
    return {
        "name": _normalize_name,
        "dob": lambda value: str(value).strip(),
        "gender": _canonical_gender,
        "aadhaar_id": lambda value: re.sub(r"\D", "", str(value)),
    }[field]


def _ocr_data_text(data):
    text_words = data.get("text", [])
    groups = {}
    group_confidences = {}
    for index, raw_word in enumerate(text_words):
        word = str(raw_word).strip()
        if not word:
            continue
        try:
            confidence = float(data.get("conf", [])[index])
        except (IndexError, TypeError, ValueError):
            confidence = -1
        group_key = tuple(
            data.get(key, [index] * len(text_words))[index]
            for key in ("block_num", "par_num", "line_num")
        )
        groups.setdefault(group_key, []).append(word)
        if confidence >= 0:
            group_confidences.setdefault(group_key, []).append(confidence)

    text = "\n".join(" ".join(words) for words in groups.values())
    line_confidences = [
        float(np.mean(group_confidences.get(group_key, [0.0])))
        for group_key in groups
    ]
    return text, line_confidences


def _preprocess_page(page):
    width = max(page.rect.width, 1)
    height = max(page.rect.height, 1)
    scale = min(_OCR_DPI / 72, _OCR_MAX_DIMENSION / max(width, height))
    pixmap = page.get_pixmap(
        matrix=fitz.Matrix(scale, scale),
        colorspace=fitz.csRGB,
        alpha=False,
    )
    rgb = np.frombuffer(pixmap.samples, dtype=np.uint8).reshape(
        pixmap.height,
        pixmap.width,
        3,
    )
    grayscale = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    denoised = cv2.medianBlur(grayscale, 3)
    if min(denoised.shape) >= 31:
        return cv2.adaptiveThreshold(
            denoised,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,
            11,
        )
    return cv2.threshold(
        denoised,
        0,
        255,
        cv2.THRESH_BINARY | cv2.THRESH_OTSU,
    )[1]


def _ocr_pdf(path, password):
    try:
        languages = pytesseract.get_languages(config="")
    except pytesseract.TesseractNotFoundError:
        return {}, {}, "UNAVAILABLE", "Local Tesseract OCR is not installed or on PATH."
    except (pytesseract.TesseractError, OSError):
        return {}, {}, "UNAVAILABLE", "Local Tesseract OCR is not available."

    if "eng" not in languages:
        return {}, {}, "UNAVAILABLE", "The Tesseract English language model is unavailable."
    language = "eng+kan" if "kan" in languages else "eng"

    try:
        document = fitz.open(Path(path))
    except (fitz.FileDataError, OSError, RuntimeError, ValueError) as error:
        raise DocumentUploadError("The uploaded PDF could not be read") from error

    try:
        if document.is_encrypted and (
            not password or not document.authenticate(password)
        ):
            raise DocumentUploadError("Invalid e-Aadhaar PDF password")

        candidates = {field: [] for field in _REQUIRED_FIELDS}
        candidate_confidences = {field: [] for field in _REQUIRED_FIELDS}
        low_confidence_fields = set()
        recognized_text = False
        ocr_failed = False

        def add_ocr_data(data):
            nonlocal recognized_text
            page_text, _ = _ocr_data_text(data)
            if page_text.strip():
                recognized_text = True
            page_details, page_confidences, page_low_confidence = (
                _details_from_ocr_data(data)
            )
            low_confidence_fields.update(page_low_confidence)
            for field in _REQUIRED_FIELDS:
                value = page_details.get(field)
                if value is not None:
                    candidates[field].append(value)
                    candidate_confidences[field].append(page_confidences[field])

        def all_fields_extracted():
            return all(
                _unique(candidates[field], _field_normalizer(field))
                for field in _REQUIRED_FIELDS
            )

        try:
            for page in document:
                image = _preprocess_page(page)
                for page_segmentation_mode in (11, 6):
                    data = pytesseract.image_to_data(
                        image,
                        lang=language,
                        config=f"--oem 1 --psm {page_segmentation_mode}",
                        output_type=pytesseract.Output.DICT,
                        timeout=20,
                    )
                    add_ocr_data(data)
                    if all_fields_extracted():
                        break
                if all_fields_extracted():
                    break

            if not all_fields_extracted():
                for page in document:
                    image = _preprocess_page(page)
                    height, width = image.shape[:2]
                    crop = image[int(height * 0.68):, :int(width * 0.62)]
                    if crop.size == 0:
                        continue
                    data = pytesseract.image_to_data(
                        crop,
                        lang=language,
                        config="--oem 1 --psm 11",
                        output_type=pytesseract.Output.DICT,
                        timeout=20,
                    )
                    add_ocr_data(data)
                    if all_fields_extracted():
                        break
        except pytesseract.TesseractNotFoundError:
            return {}, {}, "UNAVAILABLE", "Local Tesseract OCR is not installed or on PATH."
        except (
            pytesseract.TesseractError,
            cv2.error,
            OSError,
            RuntimeError,
            ValueError,
        ):
            ocr_failed = True

        details = {
            field: _unique(candidates[field], _field_normalizer(field))
            for field in _REQUIRED_FIELDS
        }
        confidence_by_field = {
            field: (
                min(candidate_confidences[field])
                if details[field] is not None and candidate_confidences[field]
                else None
            )
            for field in _REQUIRED_FIELDS
        }
        if ocr_failed:
            status = "FAILED"
            message = "Local OCR did not complete; manual review is required."
        elif not recognized_text:
            status = "NO_TEXT"
            message = "OCR found no readable text; manual review is required."
        elif any(
            field in low_confidence_fields and details[field] is None
            for field in _REQUIRED_FIELDS
        ):
            status = "LOW_CONFIDENCE"
            message = "OCR confidence was too low for reliable verification; manual review is required."
        elif not all(details.values()):
            status = "PARTIAL"
            message = (
                "OCR completed, but some required fields remain missing or ambiguous; "
                "manual review is required."
            )
        else:
            status = "COMPLETED"
            message = "Local OCR completed."
        return details, confidence_by_field, status, message
    finally:
        document.close()


def extract_eaadhaar_details(path, password=None):
    try:
        document = fitz.open(Path(path))
    except (fitz.FileDataError, OSError, RuntimeError, ValueError) as error:
        raise DocumentUploadError("The uploaded PDF could not be read") from error

    try:
        password_status = "NOT_REQUIRED"
        if document.is_encrypted:
            if not password or not document.authenticate(password):
                raise DocumentUploadError("Invalid e-Aadhaar PDF password")
            password_status = "VERIFIED"
        text = "\n".join(page.get_text("text", sort=True) for page in document)
        layout_name = _repeated_name_from_document(document)
    except DocumentUploadError:
        raise
    except (fitz.FileDataError, OSError, RuntimeError, ValueError) as error:
        raise DocumentUploadError("The uploaded PDF could not be read") from error
    finally:
        document.close()

    native_details = _details_from_text(text)
    if native_details["name"] is None and layout_name is not None:
        native_details["name"] = layout_name
    field_sources = {
        field: "TEXT" if native_details.get(field) is not None else None
        for field in _REQUIRED_FIELDS
    }
    confidence_by_field = {field: None for field in _REQUIRED_FIELDS}
    ocr_status = "NOT_NEEDED"
    ocr_message = "All required fields were found in selectable PDF text."
    extraction_method = "TEXT"
    details = dict(native_details)

    if not all(native_details.get(field) is not None for field in _REQUIRED_FIELDS):
        ocr_details, ocr_confidences, ocr_status, ocr_message = _ocr_pdf(path, password)
        extraction_method = "TEXT+OCR" if native_details["text_available"] else "OCR"
        for field in _REQUIRED_FIELDS:
            if native_details.get(field) is None and ocr_details.get(field) is not None:
                details[field] = ocr_details[field]
                field_sources[field] = "OCR"
                confidence_by_field[field] = ocr_confidences[field]
        all_fields_extracted = all(
            details.get(field) is not None for field in _REQUIRED_FIELDS
        )
        if all_fields_extracted and ocr_status not in ("UNAVAILABLE", "FAILED"):
            ocr_status = "COMPLETED"
            ocr_message = "All required fields were extracted from PDF text and local OCR."
        elif ocr_status == "COMPLETED" and not all_fields_extracted:
            ocr_status = "PARTIAL"
            ocr_message = (
                "OCR completed, but one or more fields remain missing or ambiguous; "
                "manual review is required."
            )

    return {
        **details,
        "text_available": native_details["text_available"],
        "password_status": password_status,
        "extraction_method": extraction_method,
        "ocr_status": ocr_status,
        "ocr_message": ocr_message,
        "field_sources": field_sources,
        "ocr_confidence": confidence_by_field,
    }


def compare_applicant_details(extracted, name, dob, gender, aadhaar_id):
    try:
        applicant_dob = parse_applicant_dob(dob)
    except ValueError:
        applicant_dob = None

    extracted_name = extracted.get("name")
    if not extracted_name:
        name_result = "REVIEW_REQUIRED"
    else:
        name_result = (
            "MATCH"
            if _normalize_name(extracted_name) == _normalize_name(name)
            else "NO_MATCH"
        )

    extracted_dob = extracted.get("dob")
    if not extracted_dob or applicant_dob is None:
        dob_result = "REVIEW_REQUIRED"
    elif len(extracted_dob) == 4:
        dob_result = "MATCH" if extracted_dob == f"{applicant_dob.year:04d}" else "NO_MATCH"
    else:
        dob_result = "MATCH" if extracted_dob == applicant_dob.isoformat() else "NO_MATCH"

    extracted_gender = extracted.get("gender")
    applicant_gender = _canonical_gender(gender)
    if not extracted_gender or not applicant_gender:
        gender_result = "REVIEW_REQUIRED"
    else:
        gender_result = "MATCH" if extracted_gender == applicant_gender else "NO_MATCH"

    extracted_aadhaar = extracted.get("aadhaar_id")
    applicant_aadhaar = re.sub(r"\D", "", str(aadhaar_id or ""))
    if not extracted_aadhaar or len(applicant_aadhaar) != 12:
        aadhaar_result = "REVIEW_REQUIRED"
    else:
        aadhaar_result = (
            "MATCH" if extracted_aadhaar == applicant_aadhaar else "NO_MATCH"
        )

    return {
        "name": name_result,
        "dob": dob_result,
        "gender": gender_result,
        "aadhaar_id": aadhaar_result,
    }
