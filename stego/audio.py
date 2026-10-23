"""Audio steganography operations - MP3, MP4, WAV, FLAC embedding."""

from __future__ import annotations

import os
import base64
import logging
import shutil
from pathlib import Path
from PIL import Image

from mutagen import File as MutagenFile
from mutagen.id3 import ID3, APIC, TXXX
from mutagen.mp4 import MP4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import (
    FLAG_PAYLOAD_IMAGE, FLAG_PAYLOAD_TEXT, FLAG_PAYLOAD_MP3,
    FLAG_ENCRYPTED, FLAG_COMPRESSED, FLAG_META,
    TAGGED_AUDIO_EXTS, MP4_CONTAINER_EXTS,
    DEFAULT_SALT_LEN, DEFAULT_NONCE_LEN,
    StegoHeader, parse_header, derive_key, build_aad,
    apply_metadata, extract_metadata, check_expiration,
    build_stego_payload, parse_stego_payload,
)
from .image import load_image, read_payload


def load_mp3(path: str) -> None:
    """Load and validate MP3 file exists."""
    try:
        with open(path, "rb") as f:
            pass
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"MP3 file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not open MP3 file '{path}': {exc}") from exc


def load_mp4(path: str) -> None:
    """Load and validate MP4 file exists."""
    try:
        with open(path, "rb") as f:
            pass
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"MP4 file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not open MP4 file '{path}': {exc}") from exc


def embed_data_in_mp3(mp3_path: str, output_path: str, password: str | None = None,
                      message: str | None = None, in_file: str | None = None,
                      image_path: str | None = None, compress: bool = False,
                      comment: str | None = None, expires: str | None = None) -> None:
    """Embed text/file data or image into an MP3 file using ID3 tags with optional encryption."""
    load_mp3(mp3_path)

    # Determine payload type
    payload_count = sum([message is not None, in_file is not None, image_path is not None])
    if payload_count == 0:
        raise ValueError("Provide --message, --in-file, or --image")
    if payload_count > 1:
        raise ValueError("Provide only one of: --message, --in-file, or --image")

    flags = 0
    salt = b""
    nonce = b""
    plaintext = b""
    metadata = b""  # Additional metadata after payload

    if image_path:
        # Handle image embedding
        flags |= FLAG_PAYLOAD_IMAGE
        image = load_image(image_path)

        # Convert image to bytes
        image_bytes = bytearray()
        for pixel in image.getdata():
            image_bytes.extend(pixel)
        plaintext = bytes(image_bytes)

        # Store image dimensions in metadata
        metadata = image.size[0].to_bytes(4, byteorder="big") + image.size[1].to_bytes(4, byteorder="big")
    else:
        # Handle text/file embedding
        flags |= FLAG_PAYLOAD_TEXT
        if message:
            plaintext = message.encode("utf-8")
        else:
            assert in_file is not None
            with open(in_file, "rb") as f:
                plaintext = f.read()

    metadata_dict = None
    if comment or expires:
        metadata_dict = {"comment": comment or "", "expires": expires or ""}
    plaintext, meta_flag = apply_metadata(plaintext, metadata_dict)
    if meta_flag:
        flags |= meta_flag

    # Optional compression
    if compress:
        import zlib
        plaintext = zlib.compress(plaintext)
        flags |= FLAG_COMPRESSED

    # Encrypt (optional)
    payload_bytes = plaintext
    if password:
        flags |= FLAG_ENCRYPTED
        salt = os.urandom(DEFAULT_SALT_LEN)
        nonce = os.urandom(DEFAULT_NONCE_LEN)
        key = derive_key(password, salt)
        aad = build_aad(flags, salt, nonce)
        payload_bytes = AESGCM(key).encrypt(nonce, plaintext, aad)

    # Create header
    header = StegoHeader(flags=flags, salt=salt, nonce=nonce, payload_len=len(payload_bytes)).to_bytes()
    stego_data = header + payload_bytes + metadata

    # Load or create ID3 tag
    try:
        tags = ID3(mp3_path)
    except:
        tags = ID3()

    # Store embedded data in APIC (Attached Picture) frame as binary data
    tags["APIC"] = APIC(
        encoding=3,
        mime="application/octet-stream",
        type=0,
        desc="STEG_DATA",
        data=stego_data
    )

    # Save to output file
    shutil.copy(mp3_path, output_path)
    tags.save(output_path, v2_version=3)

    payload_type = "image" if (flags & FLAG_PAYLOAD_IMAGE) else "text/file"
    logging.info("Embedded %s in MP3: %s", payload_type, output_path)


def extract_data_from_mp3(mp3_path: str, output_path: str, password: str | None = None) -> None:
    """Extract text/file data or image from an MP3 file's ID3 tags with optional decryption."""
    load_mp3(mp3_path)

    try:
        tags = ID3(mp3_path)
    except:
        raise ValueError("No ID3 tags found in MP3 file")

    # Extract stego data from APIC frame
    apic_frame = None
    for key in tags.keys():
        if key.startswith("APIC"):
            apic_frame = tags[key]
            break

    if apic_frame is None:
        raise ValueError("No embedded data found in MP3 file")

    stego_data = apic_frame.data

    # Parse header
    cursor = 0

    def read_bytes(num_bytes: int) -> bytes:
        nonlocal cursor
        data = stego_data[cursor:cursor + num_bytes]
        cursor += num_bytes
        return data

    header_prefix = read_bytes(12)
    salt_len = header_prefix[6]
    nonce_len = header_prefix[7]

    extra_header = b""
    if salt_len + nonce_len > 0:
        extra_header = read_bytes(salt_len + nonce_len)

    header = parse_header(header_prefix + extra_header)

    # Read payload
    payload = read_bytes(header.payload_len)

    # Decrypt if needed
    if header.flags & FLAG_ENCRYPTED:
        if not password:
            raise ValueError("Password required to decrypt embedded data")
        key = derive_key(password, header.salt)
        aad = build_aad(header.flags, header.salt, header.nonce)
        plaintext = AESGCM(key).decrypt(header.nonce, payload, aad)
    else:
        plaintext = payload

    if header.flags & FLAG_COMPRESSED:
        import zlib
        try:
            plaintext = zlib.decompress(plaintext)
        except zlib.error as exc:
            raise ValueError("Compressed payload could not be decompressed") from exc

    if header.flags & FLAG_META:
        metadata, plaintext = extract_metadata(plaintext)
        check_expiration(metadata)

    # Determine payload type and extract accordingly
    if header.flags & FLAG_PAYLOAD_IMAGE:
        # Extract image
        img_width = int.from_bytes(read_bytes(4), byteorder="big")
        img_height = int.from_bytes(read_bytes(4), byteorder="big")

        # Reconstruct image
        pixels = []
        for i in range(0, len(plaintext), 3):
            if i + 3 <= len(plaintext):
                pixels.append(tuple(plaintext[i:i+3]))

        image = Image.new("RGB", (img_width, img_height))
        image.putdata(pixels)
        image.save(output_path)
        logging.info("Extracted image from MP3: %s", output_path)
    else:
        # Extract text/file
        with open(output_path, "wb") as f:
            f.write(plaintext)
        logging.info("Extracted text/file from MP3: %s", output_path)


def embed_data_in_mp4(mp4_path: str, output_path: str, password: str | None = None,
                      message: str | None = None, in_file: str | None = None,
                      image_path: str | None = None, mp3_path: str | None = None,
                      compress: bool = False, comment: str | None = None,
                      expires: str | None = None) -> None:
    """Embed text/file data, image, or MP3 into an MP4 file using metadata with optional encryption."""
    load_mp4(mp4_path)

    # Determine payload type
    payload_count = sum([message is not None, in_file is not None, image_path is not None, mp3_path is not None])
    if payload_count == 0:
        raise ValueError("Provide --message, --in-file, --image, or --mp3")
    if payload_count > 1:
        raise ValueError("Provide only one of: --message, --in-file, --image, or --mp3")

    flags = 0
    salt = b""
    nonce = b""
    plaintext = b""
    metadata = b""  # Additional metadata after payload

    if image_path:
        # Handle image embedding
        flags |= FLAG_PAYLOAD_IMAGE
        image = load_image(image_path)

        # Convert image to bytes
        image_bytes = bytearray()
        for pixel in image.getdata():
            image_bytes.extend(pixel)
        plaintext = bytes(image_bytes)

        # Store image dimensions in metadata
        metadata = image.size[0].to_bytes(4, byteorder="big") + image.size[1].to_bytes(4, byteorder="big")
    elif mp3_path:
        # Handle MP3 embedding
        flags |= FLAG_PAYLOAD_MP3
        load_mp3(mp3_path)
        with open(mp3_path, "rb") as f:
            plaintext = f.read()
    else:
        # Handle text/file embedding
        flags |= FLAG_PAYLOAD_TEXT
        if message:
            plaintext = message.encode("utf-8")
        else:
            assert in_file is not None
            with open(in_file, "rb") as f:
                plaintext = f.read()

    metadata_dict = None
    if comment or expires:
        metadata_dict = {"comment": comment or "", "expires": expires or ""}
    plaintext, meta_flag = apply_metadata(plaintext, metadata_dict)
    if meta_flag:
        flags |= meta_flag

    # Optional compression
    if compress:
        import zlib
        plaintext = zlib.compress(plaintext)
        flags |= FLAG_COMPRESSED

    # Encrypt (optional)
    payload_bytes = plaintext
    if password:
        flags |= FLAG_ENCRYPTED
        salt = os.urandom(DEFAULT_SALT_LEN)
        nonce = os.urandom(DEFAULT_NONCE_LEN)
        key = derive_key(password, salt)
        aad = build_aad(flags, salt, nonce)
        payload_bytes = AESGCM(key).encrypt(nonce, plaintext, aad)

    # Create header
    header = StegoHeader(flags=flags, salt=salt, nonce=nonce, payload_len=len(payload_bytes)).to_bytes()
    stego_data = header + payload_bytes + metadata

    # Load or create MP4 metadata
    try:
        tags = MP4(mp4_path)
    except:
        tags = MP4()

    # Store embedded data in custom metadata atom
    # MP4 uses base64-encoded strings for data storage (mutagen limitation)
    stego_b64 = base64.b64encode(stego_data).decode('ascii')
    tags["©stg"] = [stego_b64]

    # Save to output file
    shutil.copy(mp4_path, output_path)
    tags.save(output_path)

    payload_type_map = {
        FLAG_PAYLOAD_IMAGE: "image",
        FLAG_PAYLOAD_TEXT: "text/file",
        FLAG_PAYLOAD_MP3: "MP3 file"
    }
    payload_type = payload_type_map.get(flags & 0x38, "data")
    logging.info("Embedded %s in MP4: %s", payload_type, output_path)


def extract_data_from_mp4(mp4_path: str, output_path: str, password: str | None = None) -> None:
    """Extract text/file data, image, or MP3 from an MP4 file with optional decryption."""
    load_mp4(mp4_path)

    try:
        tags = MP4(mp4_path)
    except:
        raise ValueError("Could not read MP4 metadata")

    # Extract stego data from custom metadata atom
    if "©stg" not in tags:
        raise ValueError("No embedded data found in MP4 file")

    # Decode from base64 (mutagen stores as string)
    stego_b64 = tags["©stg"][0]
    stego_data = base64.b64decode(stego_b64)

    # Parse header
    cursor = 0

    def read_bytes(num_bytes: int) -> bytes:
        nonlocal cursor
        data = stego_data[cursor:cursor + num_bytes]
        cursor += num_bytes
        return data

    header_prefix = read_bytes(12)
    salt_len = header_prefix[6]
    nonce_len = header_prefix[7]

    extra_header = b""
    if salt_len + nonce_len > 0:
        extra_header = read_bytes(salt_len + nonce_len)

    header = parse_header(header_prefix + extra_header)

    # Read payload
    payload = read_bytes(header.payload_len)

    # Decrypt if needed
    if header.flags & FLAG_ENCRYPTED:
        if not password:
            raise ValueError("Password required to decrypt embedded data")
        key = derive_key(password, header.salt)
        aad = build_aad(header.flags, header.salt, header.nonce)
        plaintext = AESGCM(key).decrypt(header.nonce, payload, aad)
    else:
        plaintext = payload

    # Determine payload type and extract accordingly
    if header.flags & FLAG_PAYLOAD_IMAGE:
        # Extract image
        img_width = int.from_bytes(read_bytes(4), byteorder="big")
        img_height = int.from_bytes(read_bytes(4), byteorder="big")

        # Reconstruct image
        pixels = []
        for i in range(0, len(plaintext), 3):
            if i + 3 <= len(plaintext):
                pixels.append(tuple(plaintext[i:i+3]))

        image = Image.new("RGB", (img_width, img_height))
        image.putdata(pixels)
        image.save(output_path)
        logging.info("Extracted image from MP4: %s", output_path)
    elif header.flags & FLAG_PAYLOAD_MP3:
        # Extract MP3
        with open(output_path, "wb") as f:
            f.write(plaintext)
        logging.info("Extracted MP3 from MP4: %s", output_path)
    else:
        # Extract text/file
        with open(output_path, "wb") as f:
            f.write(plaintext)
        logging.info("Extracted text/file from MP4: %s", output_path)


def _write_tagged_audio(output_path: str, stego_b64: str) -> None:
    """Write steganography data to audio file tags (WAV, FLAC, etc.)."""
    ext = Path(output_path).suffix.lower()
    if ext == ".wav":
        try:
            tags = ID3(output_path)
        except Exception:
            tags = ID3()
        tags.add(TXXX(encoding=3, desc="STEGO", text=stego_b64))
        tags.save(output_path, v2_version=3)
        return

    audio = MutagenFile(output_path)
    if audio is None:
        raise ValueError("Unsupported audio format for tagging")
    if audio.tags is None:
        audio.add_tags()
    audio["STEGO"] = [stego_b64]
    audio.save()


def _read_tagged_audio(path: str) -> str:
    """Read steganography data from audio file tags."""
    ext = Path(path).suffix.lower()
    if ext == ".wav":
        try:
            tags = ID3(path)
        except Exception as exc:
            raise ValueError("No ID3 tags found in WAV file") from exc
        for frame in tags.getall("TXXX"):
            if frame.desc == "STEGO" and frame.text:
                return frame.text[0]
        raise ValueError("No embedded data found in WAV file")

    audio = MutagenFile(path)
    if audio is None or audio.tags is None:
        raise ValueError("No embedded data found in audio file")
    value = audio.tags.get("STEGO")
    if not value:
        raise ValueError("No embedded data found in audio file")
    return value[0]


def embed_data_in_audio(audio_path: str, output_path: str, password: str | None = None,
                        message: str | None = None, in_file: str | None = None,
                        image_path: str | None = None, compress: bool = False,
                        comment: str | None = None, expires: str | None = None) -> None:
    """Embed data in audio file - dispatches to appropriate handler based on format."""
    ext = Path(audio_path).suffix.lower()
    if ext == ".mp3":
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
    if ext in MP4_CONTAINER_EXTS:
        embed_data_in_mp4(
            audio_path,
            output_path,
            password=password,
            message=message,
            in_file=in_file,
            image_path=image_path,
            mp3_path=None,
            compress=compress,
            comment=comment,
            expires=expires,
        )
        return
    if ext not in TAGGED_AUDIO_EXTS:
        raise ValueError("Unsupported audio format")

    if image_path:
        raise ValueError("Image payloads are only supported for MP3/M4A/MOV containers")

    payload = read_payload(message, in_file)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, _flags, _salt, _nonce = build_stego_payload(payload, flags, password, compress, comment, expires)
    stego_b64 = base64.b64encode(stego_data).decode("ascii")

    shutil.copy(audio_path, output_path)
    _write_tagged_audio(output_path, stego_b64)
    logging.info("Embedded text/file in audio: %s", output_path)


def extract_data_from_audio(audio_path: str, output_path: str, password: str | None = None) -> None:
    """Extract data from audio file - dispatches to appropriate handler based on format."""
    ext = Path(audio_path).suffix.lower()
    if ext == ".mp3":
        extract_data_from_mp3(audio_path, output_path, password=password)
        return
    if ext in MP4_CONTAINER_EXTS:
        extract_data_from_mp4(audio_path, output_path, password=password)
        return
    if ext not in TAGGED_AUDIO_EXTS:
        raise ValueError("Unsupported audio format")

    stego_b64 = _read_tagged_audio(audio_path)
    stego_data = base64.b64decode(stego_b64)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    logging.info("Extracted text/file from audio: %s", output_path)
