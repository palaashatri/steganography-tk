"""Generated-fixture coverage for visible PDF metadata embedding."""

from __future__ import annotations

import base64

import pytest
from PyPDF2 import PdfReader, PdfWriter

from stego.pdf import embed_data_in_pdf, extract_data_from_pdf


PASSWORD = "pdf-metadata-password"
PAYLOAD = b"\x00pdf payload\xfe\xff"
MAX_METADATA_STEGO_BYTES = 1_000_000


@pytest.fixture
def source_pdf(temp_dir):
    path = temp_dir / "source.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as handle:
        writer.write(handle)
    return path


@pytest.fixture
def payload_file(temp_dir):
    path = temp_dir / "payload.bin"
    path.write_bytes(PAYLOAD)
    return path


def test_pdf_metadata_round_trip_preserves_binary_bytes(source_pdf, payload_file, temp_dir):
    output = temp_dir / "stego.pdf"
    extracted = temp_dir / "extracted.bin"

    embed_data_in_pdf(
        str(source_pdf), str(output), password=PASSWORD, in_file=str(payload_file)
    )
    result = extract_data_from_pdf(str(output), str(extracted), password=PASSWORD)

    assert result == PAYLOAD
    assert extracted.read_bytes() == PAYLOAD


def test_pdf_metadata_rejects_wrong_password(source_pdf, payload_file, temp_dir):
    output = temp_dir / "stego.pdf"
    extracted = temp_dir / "must-not-exist.bin"
    embed_data_in_pdf(
        str(source_pdf), str(output), password=PASSWORD, in_file=str(payload_file)
    )

    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_pdf(str(output), str(extracted), password="incorrect")
    assert not extracted.exists()


def test_pdf_metadata_overflow_fails_before_reading_or_writing_pdf(temp_dir):
    invalid_pdf = temp_dir / "invalid.pdf"
    invalid_pdf.write_bytes(b"not a PDF")
    oversized = temp_dir / "oversized.bin"
    oversized.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / "must-not-exist.pdf"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_pdf(str(invalid_pdf), str(output), in_file=str(oversized))
    assert not output.exists()


def _write_stego_metadata(source_pdf, destination, payload: bytes) -> None:
    reader = PdfReader(source_pdf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({"/StegData": base64.b64encode(payload).decode("ascii")})
    with destination.open("wb") as handle:
        writer.write(handle)


def test_pdf_extraction_rejects_invalid_base64(source_pdf, temp_dir):
    malformed = temp_dir / "invalid-base64.pdf"
    reader = PdfReader(source_pdf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({"/StegData": "%%% invalid base64 %%%"})
    with malformed.open("wb") as handle:
        writer.write(handle)

    with pytest.raises(ValueError, match="base64|encoded|payload|stego"):
        extract_data_from_pdf(str(malformed), str(temp_dir / "out.bin"), password=PASSWORD)


def test_pdf_extraction_rejects_truncated_envelope(source_pdf, temp_dir):
    truncated = temp_dir / "truncated.pdf"
    _write_stego_metadata(source_pdf, truncated, b"STG1\x02")

    with pytest.raises(ValueError, match="too short|incomplete|header"):
        extract_data_from_pdf(str(truncated), str(temp_dir / "out.bin"), password=PASSWORD)
