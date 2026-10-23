"""Generated-fixture coverage for visible PDF metadata embedding."""

from __future__ import annotations

import base64
import os

import pytest
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import (
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

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
def catalog_rich_pdf(temp_dir):
    path = temp_dir / "catalog-rich.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    page = writer.pages[0]
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    font_ref = writer._add_object(font)
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})}
    )
    content = DecodedStreamObject()
    content.set_data(b"BT /F1 12 Tf 72 720 Td (Catalog preservation text) Tj ET")
    page[NameObject("/Contents")] = writer._add_object(content)

    writer.add_outline_item("Fixture outline", 0)
    writer.add_attachment("fixture.txt", b"embedded attachment bytes")

    field = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/T"): TextStringObject("FixtureField"),
            NameObject("/V"): TextStringObject("form field value"),
            NameObject("/Rect"): ArrayObject(
                [
                    NumberObject(72),
                    NumberObject(650),
                    NumberObject(250),
                    NumberObject(675),
                ]
            ),
            NameObject("/P"): page.indirect_reference,
        }
    )
    field_ref = writer._add_object(field)
    page[NameObject("/Annots")] = ArrayObject([field_ref])
    acro_form = DictionaryObject({NameObject("/Fields"): ArrayObject([field_ref])})
    writer._root_object.update({NameObject("/AcroForm"): writer._add_object(acro_form)})

    with path.open("wb") as handle:
        writer.write(handle)
    return path


@pytest.fixture(
    params=("signature-field", "direct-permission", "indirect-permission"),
    ids=("signature-field", "direct-permission", "indirect-permission"),
)
def signed_pdf(request, temp_dir):
    path = temp_dir / "signed-source.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    signature = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Sig"),
            NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
            NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
            NameObject("/ByteRange"): ArrayObject(
                [NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)]
            ),
            NameObject("/Contents"): ByteStringObject(b"signature bytes"),
        }
    )
    signature_ref = writer._add_object(signature)
    if request.param == "signature-field":
        signature_field = DictionaryObject(
            {
                NameObject("/FT"): NameObject("/Sig"),
                NameObject("/T"): TextStringObject("FixtureSignature"),
                NameObject("/V"): signature_ref,
            }
        )
        field_ref = writer._add_object(signature_field)
        acro_form = DictionaryObject({NameObject("/Fields"): ArrayObject([field_ref])})
        writer._root_object.update(
            {NameObject("/AcroForm"): writer._add_object(acro_form)}
        )
    else:
        permissions = DictionaryObject({NameObject("/DocMDP"): signature_ref})
        if request.param == "indirect-permission":
            permissions = writer._add_object(permissions)
        writer._root_object.update({NameObject("/Perms"): permissions})
    with path.open("wb") as handle:
        writer.write(handle)
    return path


@pytest.fixture
def encrypted_pdf(temp_dir):
    path = temp_dir / "encrypted-source.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt("source-password")
    with path.open("wb") as handle:
        writer.write(handle)
    return path


@pytest.fixture
def usage_rights_pdf(temp_dir):
    path = temp_dir / "usage-rights-source.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    usage_rights = DictionaryObject({NameObject("/Type"): NameObject("/UsageRights")})
    permissions = DictionaryObject({NameObject("/UR"): usage_rights})
    writer._root_object.update({NameObject("/Perms"): permissions})
    with path.open("wb") as handle:
        writer.write(handle)
    return path


@pytest.fixture(params=("/UR", "/UR3"), ids=("UR-signature", "UR3-signature"))
def signed_usage_rights_pdf(request, temp_dir):
    path = temp_dir / f"signed-{request.param[1:]}.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    signature = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Sig"),
            NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
            NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
            NameObject("/ByteRange"): ArrayObject(
                [NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)]
            ),
            NameObject("/Contents"): ByteStringObject(b"signature bytes"),
        }
    )
    permissions = DictionaryObject(
        {NameObject(request.param): writer._add_object(signature)}
    )
    writer._root_object.update({NameObject("/Perms"): permissions})
    with path.open("wb") as handle:
        writer.write(handle)
    return path


@pytest.fixture
def payload_file(temp_dir):
    path = temp_dir / "payload.bin"
    path.write_bytes(PAYLOAD)
    return path


def test_pdf_metadata_round_trip_preserves_binary_bytes(
    source_pdf, payload_file, temp_dir
):
    output = temp_dir / "stego.pdf"
    extracted = temp_dir / "extracted.bin"

    embed_data_in_pdf(
        str(source_pdf), str(output), password=PASSWORD, in_file=str(payload_file)
    )
    result = extract_data_from_pdf(str(output), str(extracted), password=PASSWORD)

    assert result == PAYLOAD
    assert extracted.read_bytes() == PAYLOAD


def test_pdf_metadata_embedding_preserves_document_catalog(catalog_rich_pdf, temp_dir):
    output = temp_dir / "catalog-rich-stego.pdf"
    payload = b"catalog preservation payload"
    source_reader = PdfReader(str(catalog_rich_pdf))

    assert "Catalog preservation text" in source_reader.pages[0].extract_text()
    assert source_reader.outline[0].title == "Fixture outline"
    assert source_reader.get_fields()["FixtureField"]["/V"] == "form field value"
    source_attachments = source_reader.trailer["/Root"]["/Names"]["/EmbeddedFiles"][
        "/Names"
    ]
    source_file_spec = source_attachments[1].get_object()
    assert source_file_spec["/EF"]["/F"].get_object().get_data() == (
        b"embedded attachment bytes"
    )

    embed_data_in_pdf(str(catalog_rich_pdf), str(output), message=payload.decode())
    extracted = extract_data_from_pdf(str(output))

    reader = PdfReader(str(output))
    assert extracted == payload
    assert "Catalog preservation text" in reader.pages[0].extract_text()
    assert reader.outline[0].title == "Fixture outline"
    assert reader.get_destination_page_number(reader.outline[0]) == 0
    embedded_files = reader.trailer["/Root"]["/Names"]["/EmbeddedFiles"]["/Names"]
    file_spec = embedded_files[1].get_object()
    embedded_stream = file_spec["/EF"]["/F"].get_object()
    assert embedded_stream.get_data() == b"embedded attachment bytes"
    assert reader.get_fields()["FixtureField"]["/V"] == "form field value"
    assert reader.pages[0]["/Annots"][0].get_object()["/Subtype"] == "/Widget"


def test_pdf_metadata_embedding_rejects_signed_sources(signed_pdf, temp_dir):
    output = temp_dir / "signed-stego.pdf"

    with pytest.raises(ValueError, match="digital signatures|signature"):
        embed_data_in_pdf(str(signed_pdf), str(output), message="payload")

    assert not output.exists()


def test_pdf_metadata_embedding_rejects_signed_usage_rights_entries(
    signed_usage_rights_pdf, temp_dir
):
    output = temp_dir / "signed-usage-rights-stego.pdf"

    with pytest.raises(ValueError, match="digital signatures|signature"):
        embed_data_in_pdf(str(signed_usage_rights_pdf), str(output), message="payload")

    assert not output.exists()


def test_pdf_metadata_embedding_rejects_encrypted_sources(encrypted_pdf, temp_dir):
    output = temp_dir / "encrypted-stego.pdf"

    with pytest.raises(ValueError, match="encrypted PDF|source PDF password"):
        embed_data_in_pdf(str(encrypted_pdf), str(output), message="payload")

    assert not output.exists()


def test_pdf_metadata_embedding_preserves_unsigned_usage_rights(
    usage_rights_pdf, temp_dir
):
    output = temp_dir / "usage-rights-stego.pdf"
    payload = b"usage rights payload"

    embed_data_in_pdf(str(usage_rights_pdf), str(output), message=payload.decode())

    reader = PdfReader(str(output))
    assert reader.trailer["/Root"]["/Perms"]["/UR"]["/Type"] == "/UsageRights"
    assert extract_data_from_pdf(str(output)) == payload


def test_pdf_metadata_rejects_wrong_password(source_pdf, payload_file, temp_dir):
    output = temp_dir / "stego.pdf"
    extracted = temp_dir / "must-not-exist.bin"
    embed_data_in_pdf(
        str(source_pdf), str(output), password=PASSWORD, in_file=str(payload_file)
    )

    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_pdf(str(output), str(extracted), password="incorrect")
    assert not extracted.exists()


def test_pdf_metadata_overflow_is_bounded_before_opening_source_pdf(
    temp_dir, monkeypatch
):
    import stego.image as image_module

    invalid_pdf = temp_dir / "invalid.pdf"
    invalid_pdf.write_bytes(b"not a PDF")
    oversized = temp_dir / "oversized.bin"
    oversized.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / "must-not-exist.pdf"
    limits = []
    original_bounded_read = image_module.read_bounded_file

    def record_bounded_read(path, max_bytes, **kwargs):
        limits.append(max_bytes)
        return original_bounded_read(path, max_bytes, **kwargs)

    monkeypatch.setattr(image_module, "read_bounded_file", record_bounded_read)

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_pdf(str(invalid_pdf), str(output), in_file=str(oversized))

    assert limits == [MAX_METADATA_STEGO_BYTES]
    assert not output.exists()


def test_pdf_compression_accepts_payload_above_uncompressed_input_limit(
    source_pdf, temp_dir
):
    payload = b"compressed PDF metadata payload " * 40_000
    payload_file = temp_dir / "compressible-payload.bin"
    output = temp_dir / "compressed-stego.pdf"
    payload_file.write_bytes(payload)

    embed_data_in_pdf(
        str(source_pdf), str(output), in_file=str(payload_file), compress=True
    )

    assert extract_data_from_pdf(str(output)) == payload


def test_pdf_embed_refuses_to_overwrite_source_pdf(source_pdf):
    original_bytes = source_pdf.read_bytes()

    with pytest.raises(ValueError, match="paths must differ"):
        embed_data_in_pdf(str(source_pdf), str(source_pdf), message="payload")

    assert source_pdf.read_bytes() == original_bytes


def test_pdf_embed_refuses_hard_link_alias_of_source_pdf(source_pdf, temp_dir):
    hard_link = temp_dir / "source-hard-link.pdf"
    try:
        os.link(source_pdf, hard_link)
    except OSError as exc:
        pytest.skip(f"filesystem does not support creating hard links: {exc}")
    original_bytes = source_pdf.read_bytes()

    with pytest.raises(ValueError, match="paths must differ"):
        embed_data_in_pdf(str(source_pdf), str(hard_link), message="payload")

    assert source_pdf.read_bytes() == original_bytes
    assert hard_link.read_bytes() == original_bytes


def test_pdf_embed_refuses_to_overwrite_payload_source(source_pdf, temp_dir):
    payload_path = temp_dir / "payload.pdf"
    original = b"payload bytes must survive"
    payload_path.write_bytes(original)

    with pytest.raises(ValueError, match="Payload input and output paths must differ"):
        embed_data_in_pdf(str(source_pdf), str(payload_path), in_file=str(payload_path))

    assert payload_path.read_bytes() == original


def test_pdf_embed_write_failure_preserves_output_and_removes_temporary_file(
    source_pdf, temp_dir, monkeypatch
):
    output = temp_dir / "existing-output.pdf"
    previous_output = b"previous output must survive"
    output.write_bytes(previous_output)

    def fail_write(_writer, _stream):
        raise OSError("injected PDF write failure")

    monkeypatch.setattr(PdfWriter, "write", fail_write)
    with pytest.raises(OSError, match="injected PDF write failure"):
        embed_data_in_pdf(str(source_pdf), str(output), message="payload")

    assert output.read_bytes() == previous_output
    assert list(temp_dir.glob(f".{output.name}.*.tmp")) == []


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
        extract_data_from_pdf(
            str(malformed), str(temp_dir / "out.bin"), password=PASSWORD
        )


def test_pdf_extraction_rejects_truncated_envelope(source_pdf, temp_dir):
    truncated = temp_dir / "truncated.pdf"
    _write_stego_metadata(source_pdf, truncated, b"STG1\x02")

    with pytest.raises(ValueError, match="too short|incomplete|header"):
        extract_data_from_pdf(
            str(truncated), str(temp_dir / "out.bin"), password=PASSWORD
        )


def test_pdf_extraction_refuses_to_overwrite_its_carrier(source_pdf, temp_dir):
    carrier = temp_dir / "stego-carrier.pdf"
    embed_data_in_pdf(
        str(source_pdf), str(carrier), message="keep the PDF carrier intact"
    )
    original_bytes = carrier.read_bytes()

    with pytest.raises(ValueError, match="paths must differ"):
        extract_data_from_pdf(str(carrier), str(carrier))

    assert carrier.read_bytes() == original_bytes
