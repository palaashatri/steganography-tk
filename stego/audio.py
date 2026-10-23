"""Visible metadata embedding for MP3, MP4/M4A, and tagged audio files."""

from __future__ import annotations

import base64
import logging
import shutil
from pathlib import Path

from mutagen import File as MutagenFile
from mutagen.id3 import APIC, ID3, TXXX
from mutagen.mp4 import MP4
from PIL import Image

from .core import (
    FLAG_PAYLOAD_IMAGE,
    FLAG_PAYLOAD_MP3,
    FLAG_PAYLOAD_TEXT,
    LEGACY_VERSION,
    MP4_CONTAINER_EXTS,
    TAGGED_AUDIO_EXTS,
    StegoHeader,
    build_stego_payload,
    decode_stego_base64,
    ensure_metadata_capacity,
    parse_header,
    parse_stego_payload,
)
from .image import load_image, read_payload


def load_mp3(path: str) -> None:
    """Check that an MP3 attachment exists and can be opened."""
    try:
        with open(path, "rb"):
            pass
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"MP3 file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not open MP3 file '{path}': {exc}") from exc


def load_mp4(path: str) -> None:
    """Check that an MP4-family carrier exists and can be opened."""
    try:
        with open(path, "rb"):
            pass
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"MP4 file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not open MP4 file '{path}': {exc}") from exc


def _image_bytes(path: str) -> bytes:
    """Validate an image attachment and preserve its original encoded bytes."""
    load_image(path)
    return Path(path).read_bytes()


def _payload_for_mp3(
    message: str | None, in_file: str | None, image_path: str | None
) -> tuple[bytes, int]:
    supplied = sum(value is not None for value in (message, in_file, image_path))
    if supplied != 1:
        if supplied == 0:
            raise ValueError("Provide --message, --in-file, or --image")
        raise ValueError("Provide only one of: --message, --in-file, or --image")
    if image_path is not None:
        return _image_bytes(image_path), FLAG_PAYLOAD_IMAGE
    return read_payload(message, in_file), FLAG_PAYLOAD_TEXT


def _payload_for_mp4(
    message: str | None,
    in_file: str | None,
    image_path: str | None,
    mp3_path: str | None,
) -> tuple[bytes, int]:
    supplied = sum(
        value is not None for value in (message, in_file, image_path, mp3_path)
    )
    if supplied != 1:
        if supplied == 0:
            raise ValueError("Provide --message, --in-file, --image, or --mp3")
        raise ValueError("Provide only one of: --message, --in-file, --image, or --mp3")
    if image_path is not None:
        return _image_bytes(image_path), FLAG_PAYLOAD_IMAGE
    if mp3_path is not None:
        load_mp3(mp3_path)
        return Path(mp3_path).read_bytes(), FLAG_PAYLOAD_MP3
    return read_payload(message, in_file), FLAG_PAYLOAD_TEXT


def _header_from_blob(stego_data: bytes) -> StegoHeader:
    if len(stego_data) < 12:
        raise ValueError("Stego data too short to contain a complete header")
    header_len = 12 + stego_data[6] + stego_data[7]
    if len(stego_data) < header_len:
        raise ValueError("Stego header is incomplete")
    return parse_header(stego_data[:header_len])


def _write_extracted_payload(
    stego_data: bytes, flags: int, plaintext: bytes, output_path: str
) -> None:
    """Write a decoded payload, retaining support for legacy pixel-only images."""
    header = _header_from_blob(stego_data)
    if flags & FLAG_PAYLOAD_IMAGE and header.version == LEGACY_VERSION:
        dimensions_offset = 12 + len(header.salt) + len(header.nonce) + header.payload_len
        dimensions = stego_data[dimensions_offset:dimensions_offset + 8]
        if len(dimensions) != 8:
            raise ValueError("Legacy image payload is missing its dimensions")
        width = int.from_bytes(dimensions[:4], "big")
        height = int.from_bytes(dimensions[4:], "big")
        if width <= 0 or height <= 0 or len(plaintext) != width * height * 3:
            raise ValueError("Legacy image payload has invalid dimensions or pixel data")
        Image.frombytes("RGB", (width, height), plaintext).save(output_path)
        return
    Path(output_path).write_bytes(plaintext)


def embed_data_in_mp3(
    mp3_path: str,
    output_path: str,
    password: str | None = None,
    message: str | None = None,
    in_file: str | None = None,
    image_path: str | None = None,
    compress: bool = False,
    comment: str | None = None,
    expires: str | None = None,
) -> None:
    """Store a versioned envelope in an MP3 ID3 APIC frame."""
    load_mp3(mp3_path)
    plaintext, flags = _payload_for_mp3(message, in_file, image_path)
    stego_data, flags, _salt, _nonce = build_stego_payload(
        plaintext, flags, password, compress, comment, expires
    )
    ensure_metadata_capacity(stego_data)

    try:
        tags = ID3(mp3_path)
    except Exception:
        tags = ID3()
    tags["APIC"] = APIC(
        encoding=3,
        mime="application/octet-stream",
        type=0,
        desc="STEG_DATA",
        data=stego_data,
    )

    shutil.copyfile(mp3_path, output_path)
    tags.save(output_path, v2_version=3)
    kind = "image attachment" if flags & FLAG_PAYLOAD_IMAGE else "file data"
    logging.info("Stored %s in visible MP3 metadata: %s", kind, output_path)


def extract_data_from_mp3(
    mp3_path: str, output_path: str, password: str | None = None
) -> None:
    """Extract an envelope from an MP3 ID3 APIC frame."""
    load_mp3(mp3_path)
    try:
        tags = ID3(mp3_path)
    except Exception as exc:
        raise ValueError("No ID3 tags found in MP3 file") from exc
    frame = next(
        (
            value
            for value in tags.values()
            if isinstance(value, APIC) and value.desc == "STEG_DATA"
        ),
        None,
    )
    if frame is None:
        raise ValueError("No embedded data found in MP3 metadata")
    stego_data = frame.data
    flags, plaintext, _metadata = parse_stego_payload(stego_data, password)
    _write_extracted_payload(stego_data, flags, plaintext, output_path)


def embed_data_in_mp4(
    mp4_path: str,
    output_path: str,
    password: str | None = None,
    message: str | None = None,
    in_file: str | None = None,
    image_path: str | None = None,
    mp3_path: str | None = None,
    compress: bool = False,
    comment: str | None = None,
    expires: str | None = None,
) -> None:
    """Store a versioned envelope in an MP4/M4A custom metadata atom."""
    load_mp4(mp4_path)
    plaintext, flags = _payload_for_mp4(message, in_file, image_path, mp3_path)
    stego_data, _flags, _salt, _nonce = build_stego_payload(
        plaintext, flags, password, compress, comment, expires
    )
    ensure_metadata_capacity(stego_data)

    try:
        tags = MP4(mp4_path)
    except Exception:
        tags = MP4()
    tags["©stg"] = [base64.b64encode(stego_data).decode("ascii")]
    shutil.copyfile(mp4_path, output_path)
    tags.save(output_path)
    logging.info("Stored file data in visible MP4 metadata: %s", output_path)


def extract_data_from_mp4(
    mp4_path: str, output_path: str, password: str | None = None
) -> None:
    """Extract an envelope from an MP4/M4A metadata atom."""
    load_mp4(mp4_path)
    try:
        tags = MP4(mp4_path)
    except Exception as exc:
        raise ValueError("Could not read MP4 metadata") from exc
    if "©stg" not in tags or not tags["©stg"]:
        raise ValueError("No embedded data found in MP4 metadata")
    stego_data = decode_stego_base64(tags["©stg"][0])
    flags, plaintext, _metadata = parse_stego_payload(stego_data, password)
    _write_extracted_payload(stego_data, flags, plaintext, output_path)


def _write_tagged_audio(output_path: str, stego_b64: str) -> None:
    """Write visible metadata to WAV/AAC ID3 tags or Mutagen comments."""
    ext = Path(output_path).suffix.lower()
    if ext in {".wav", ".aac"}:
        try:
            tags = ID3(output_path)
        except Exception:
            tags = ID3()
        tags.add(TXXX(encoding=3, desc="STEGO", text=stego_b64))
        tags.save(output_path, v2_version=3)
        return

    audio = MutagenFile(output_path)
    if audio is None:
        raise ValueError(f"Unsupported audio format for visible metadata: {ext}")
    if audio.tags is None:
        audio.add_tags()
    audio["STEGO"] = [stego_b64]
    audio.save()


def _read_tagged_audio(path: str) -> str:
    """Read the visible metadata value from tagged audio formats."""
    ext = Path(path).suffix.lower()
    if ext in {".wav", ".aac"}:
        try:
            tags = ID3(path)
        except Exception as exc:
            raise ValueError(f"No ID3 metadata found in {ext[1:].upper()} file") from exc
        for frame in tags.getall("TXXX"):
            if frame.desc == "STEGO" and frame.text:
                return frame.text[0]
        raise ValueError(f"No embedded data found in {ext[1:].upper()} metadata")

    audio = MutagenFile(path)
    if audio is None or audio.tags is None:
        raise ValueError("No embedded data found in audio metadata")
    value = audio.tags.get("STEGO")
    if not value:
        raise ValueError("No embedded data found in audio metadata")
    return value[0]


def _audio_metadata_backend(path: str) -> str | None:
    """Return the extractor selected by an audio carrier's extension."""
    ext = Path(path).suffix.lower()
    if ext == ".mp3":
        return "mp3"
    if ext in MP4_CONTAINER_EXTS:
        return "mp4"
    if ext in {".wav", ".aac"}:
        return "id3"
    if ext in TAGGED_AUDIO_EXTS:
        return "mutagen"
    return None


def embed_data_in_audio(
    audio_path: str,
    output_path: str,
    password: str | None = None,
    message: str | None = None,
    in_file: str | None = None,
    image_path: str | None = None,
    compress: bool = False,
    comment: str | None = None,
    expires: str | None = None,
) -> None:
    """Store file data in visible audio metadata supported by this container."""
    input_suffix = Path(audio_path).suffix.casefold()
    output_suffix = Path(output_path).suffix.casefold()
    if input_suffix != output_suffix:
        raise ValueError("Input and output audio carrier suffixes must match")

    backend = _audio_metadata_backend(audio_path)
    if backend is None:
        raise ValueError("Unsupported audio format for visible metadata embedding")
    if _audio_metadata_backend(output_path) != backend:
        raise ValueError(
            "Input and output audio carrier extensions select different metadata backends"
        )

    ext = Path(audio_path).suffix.lower()
    if backend == "mp3":
        embed_data_in_mp3(
            audio_path,
            output_path,
            password=password,
            message=message,
            in_file=in_file,
            image_path=image_path,
            compress=compress,
            comment=comment,
            expires=expires,
        )
        return
    if backend == "mp4":
        embed_data_in_mp4(
            audio_path,
            output_path,
            password=password,
            message=message,
            in_file=in_file,
            image_path=image_path,
            compress=compress,
            comment=comment,
            expires=expires,
        )
        return
    if image_path is not None:
        raise ValueError("Image attachments are supported only in MP3 and MP4-family metadata")

    payload = read_payload(message, in_file)
    stego_data, _flags, _salt, _nonce = build_stego_payload(
        payload, FLAG_PAYLOAD_TEXT, password, compress, comment, expires
    )
    ensure_metadata_capacity(stego_data)
    stego_b64 = base64.b64encode(stego_data).decode("ascii")
    shutil.copyfile(audio_path, output_path)
    _write_tagged_audio(output_path, stego_b64)
    logging.info("Stored file data in visible %s metadata: %s", ext[1:].upper(), output_path)


def extract_data_from_audio(
    audio_path: str, output_path: str, password: str | None = None
) -> None:
    """Extract file data from visible metadata in supported audio formats."""
    backend = _audio_metadata_backend(audio_path)
    if backend == "mp3":
        extract_data_from_mp3(audio_path, output_path, password=password)
        return
    if backend == "mp4":
        extract_data_from_mp4(audio_path, output_path, password=password)
        return
    if backend is None:
        raise ValueError("Unsupported audio format for visible metadata extraction")

    stego_data = decode_stego_base64(_read_tagged_audio(audio_path))
    flags, plaintext, _metadata = parse_stego_payload(stego_data, password)
    _write_extracted_payload(stego_data, flags, plaintext, output_path)
