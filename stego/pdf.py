"""PDF steganography operations."""

from __future__ import annotations

import base64
import logging

from PyPDF2 import PdfReader, PdfWriter

from .core import (
    FLAG_PAYLOAD_TEXT,
    build_stego_payload, parse_stego_payload,
)
from .image import read_payload


def embed_data_in_pdf(pdf_path: str, output_path: str, password: str | None = None,
                      message: str | None = None, in_file: str | None = None,
                      compress: bool = False, comment: str | None = None,
                      expires: str | None = None) -> None:
    """Embed data in PDF metadata."""
    payload = read_payload(message, in_file)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, flags, _salt, _nonce = build_stego_payload(payload, flags, password, compress, comment, expires)

    reader = PdfReader(pdf_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    meta = reader.metadata or {}
    meta_dict = {str(k): str(v) for k, v in meta.items() if v is not None}
    meta_dict["/StegData"] = base64.b64encode(stego_data).decode("ascii")
    meta_dict["/StegFlags"] = str(flags)
    writer.add_metadata(meta_dict)

    with open(output_path, "wb") as f:
        writer.write(f)
    logging.info("Embedded data in PDF: %s", output_path)


def extract_data_from_pdf(pdf_path: str, output_path: str | None = None, password: str | None = None) -> bytes:
    """Extract data from PDF metadata."""
    reader = PdfReader(pdf_path)
    meta = reader.metadata or {}
    stego_b64 = meta.get("/StegData")
    if not stego_b64:
        raise ValueError("No embedded data found in PDF")
    stego_data = base64.b64decode(stego_b64)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    if output_path:
        with open(output_path, "wb") as f:
            f.write(plaintext)
        logging.info("Extracted data from PDF: %s", output_path)
    return plaintext
