"""Visible metadata embedding in PDF document properties."""

from __future__ import annotations

import base64
import logging
import os
import tempfile

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject

from .core import (
    FLAG_PAYLOAD_TEXT,
    build_stego_payload,
    decode_stego_base64,
    ensure_metadata_capacity,
    max_input_payload_bytes,
    parse_stego_payload,
)
from .image import read_payload
from .utils import (
    ensure_output_differs_from_input,
    ensure_output_differs_from_payloads,
)


def _is_signature_dictionary(value: object) -> bool:
    """Recognize a PDF signature dictionary stored in a permission entry."""
    get_object = getattr(value, "get_object", None)
    resolved = get_object() if callable(get_object) else value
    if not isinstance(resolved, DictionaryObject):
        return False
    if str(resolved.get("/Type")) == "/Sig":
        return True
    return all(
        resolved.get(key) is not None
        for key in ("/ByteRange", "/Contents", "/Filter", "/SubFilter")
    )


def _contains_digital_signature(reader: PdfReader) -> bool:
    catalog = reader.trailer["/Root"].get_object()
    permissions = catalog.get("/Perms")
    if permissions is not None:
        permissions = permissions.get_object()
        if permissions.get("/DocMDP") is not None:
            return True
        if any(
            _is_signature_dictionary(permissions.get(key)) for key in ("/UR", "/UR3")
        ):
            return True

    try:
        fields = reader.get_fields() or {}
    except Exception as exc:
        raise ValueError("Could not inspect source PDF form fields") from exc

    return any(
        str(field.get("/FT")) == "/Sig" and field.get("/V") is not None
        for field in fields.values()
    )


def embed_data_in_pdf(
    pdf_path: str,
    output_path: str,
    password: str | None = None,
    message: str | None = None,
    in_file: str | None = None,
    compress: bool = False,
    comment: str | None = None,
    expires: str | None = None,
) -> None:
    """Store data in visible PDF metadata while retaining catalog structures."""
    ensure_output_differs_from_input(pdf_path, output_path, "PDF")
    ensure_output_differs_from_payloads(output_path, in_file)
    metadata = (
        {"comment": comment or "", "expires": expires or ""}
        if comment or expires
        else None
    )
    max_bytes = max_input_payload_bytes(compress=compress, metadata=metadata)
    payload = read_payload(message, in_file, max_bytes=max_bytes)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, flags, _salt, _nonce = build_stego_payload(
        payload, flags, password, compress, comment, expires
    )
    ensure_metadata_capacity(stego_data)

    # Capacity is checked before parsing or opening the source PDF for rewrite.
    reader = PdfReader(pdf_path)
    if reader.is_encrypted:
        raise ValueError(
            "Encrypted source PDFs are not supported; provide an unencrypted PDF"
        )
    if _contains_digital_signature(reader):
        raise ValueError(
            "PDFs with digital signatures cannot be rewritten without invalidating "
            "signatures"
        )

    # Clone the source catalog along with its pages, outlines, names, and forms.
    try:
        writer = PdfWriter(clone_from=reader)
    except Exception as exc:
        raise ValueError("Could not preserve source PDF catalog structures") from exc

    meta = reader.metadata or {}
    meta_dict = {str(k): str(v) for k, v in meta.items() if v is not None}
    meta_dict["/StegData"] = base64.b64encode(stego_data).decode("ascii")
    meta_dict["/StegFlags"] = str(flags)
    writer.add_metadata(meta_dict)

    output_parent = os.path.dirname(os.path.abspath(output_path))
    output_name = os.path.basename(output_path)
    temp_fd, temp_path = tempfile.mkstemp(
        prefix=f".{output_name}.", suffix=".tmp", dir=output_parent
    )
    try:
        with os.fdopen(temp_fd, "wb") as output_file:
            writer.write(output_file)
        os.replace(temp_path, output_path)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
    logging.info("Stored visible metadata in PDF: %s", output_path)


def extract_data_from_pdf(
    pdf_path: str,
    output_path: str | None = None,
    password: str | None = None,
) -> bytes:
    """Extract a payload from visible PDF document metadata."""
    if output_path:
        ensure_output_differs_from_input(pdf_path, output_path, "PDF")
    reader = PdfReader(pdf_path)
    meta = reader.metadata or {}
    stego_b64 = meta.get("/StegData")
    if not stego_b64:
        raise ValueError("No embedded data found in PDF")
    stego_data = decode_stego_base64(str(stego_b64))
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    if output_path:
        with open(output_path, "wb") as f:
            f.write(plaintext)
        logging.info("Extracted data from PDF: %s", output_path)
    return plaintext
