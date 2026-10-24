"""Core steganography operations - headers, encryption, bits, PRNG."""

from __future__ import annotations

import os
import random
import json
import hashlib
import zlib
import base64
import binascii
from array import array
from typing import Iterator, List, Sequence
from datetime import datetime, timezone
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

# Constants
MAGIC = b"STG1"
LEGACY_VERSION = 1
VERSION = 2
STREAMING_PRNG_VERSION = 3
FLAG_ENCRYPTED = 0b0000_0001
FLAG_PRNG = 0b0000_0010
FLAG_LSB_MATCH = 0b0000_0100
FLAG_PAYLOAD_IMAGE = 0b0000_1000  # Payload is image data (MP3/MP4 only)
FLAG_PAYLOAD_TEXT = 0b0001_0000  # Payload is text/file data (MP3/MP4 only)
FLAG_PAYLOAD_MP3 = 0b0010_0000  # Payload is MP3 file (MP4 only)
FLAG_COMPRESSED = 0b0100_0000  # Payload is zlib-compressed
FLAG_META = 0b1000_0000  # Payload contains metadata header

AUDIO_EXT_LIST = [".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".opus"]
VIDEO_EXT_LIST = [".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v"]
AUDIO_EXTS = set(AUDIO_EXT_LIST)
VIDEO_EXTS = set(VIDEO_EXT_LIST)
MP4_CONTAINER_EXTS = {".mp4", ".m4a", ".m4b", ".m4p", ".m4v", ".mov"}
TAGGED_AUDIO_EXTS = {".wav", ".flac", ".ogg", ".opus", ".aac"}
FFMPEG_VIDEO_EXTS = {".mkv", ".avi", ".webm"}

DEFAULT_SALT_LEN = 16
DEFAULT_NONCE_LEN = 12
PBKDF2_ITERATIONS = 200_000
KEY_LEN = 32  # AES-256
MAX_METADATA_STEGO_BYTES = 1_000_000
MAX_DECOMPRESSED_PAYLOAD_BYTES = 64 * 1024 * 1024


def ensure_metadata_capacity(stego_data: bytes) -> None:
    """Reject metadata envelopes larger than the shared encoded-blob limit."""
    if len(stego_data) > MAX_METADATA_STEGO_BYTES:
        raise ValueError(
            "Visible metadata payload exceeds the 1,000,000-byte encoded limit"
        )


def decode_stego_base64(encoded: str | bytes) -> bytes:
    """Decode a metadata tag strictly, with a stable public error type."""
    max_encoded_len = 4 * ((MAX_METADATA_STEGO_BYTES + 2) // 3)
    if len(encoded) > max_encoded_len:
        raise ValueError("Embedded metadata payload exceeds the 1,000,000-byte limit")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Embedded metadata is not valid base64") from exc
    if len(decoded) > MAX_METADATA_STEGO_BYTES:
        raise ValueError("Embedded metadata payload exceeds the 1,000,000-byte limit")
    return decoded


@dataclass
class StegoHeader:
    flags: int
    salt: bytes
    nonce: bytes
    payload_len: int
    version: int = VERSION

    def to_bytes(self) -> bytes:
        salt_len = len(self.salt)
        nonce_len = len(self.nonce)
        header = bytearray()
        header += MAGIC
        header.append(self.version)
        header.append(self.flags)
        header.append(salt_len)
        header.append(nonce_len)
        header += self.payload_len.to_bytes(4, byteorder="big", signed=False)
        header += self.salt
        header += self.nonce
        return bytes(header)


def parse_header(raw: bytes) -> StegoHeader:
    if len(raw) < 12:
        raise ValueError("Header too short; not a valid stego payload")

    magic = raw[0:4]
    if magic != MAGIC:
        raise ValueError("Magic bytes mismatch; not a supported stego image")

    version = raw[4]
    if version not in (LEGACY_VERSION, VERSION, STREAMING_PRNG_VERSION):
        raise ValueError(
            f"Unsupported version {version}; expected {LEGACY_VERSION}, {VERSION}, "
            f"or {STREAMING_PRNG_VERSION}"
        )

    flags = raw[5]
    salt_len = raw[6]
    nonce_len = raw[7]
    payload_len = int.from_bytes(raw[8:12], byteorder="big", signed=False)

    expected_len = 12 + salt_len + nonce_len
    if len(raw) < expected_len:
        raise ValueError("Header incomplete; missing salt or nonce bytes")

    salt = raw[12 : 12 + salt_len]
    nonce = raw[12 + salt_len : 12 + salt_len + nonce_len]
    if flags & FLAG_ENCRYPTED and version >= VERSION:
        if salt_len != DEFAULT_SALT_LEN or nonce_len != DEFAULT_NONCE_LEN:
            raise ValueError(
                "Version 2 encrypted headers require a 16-byte salt and 12-byte nonce"
            )
    elif not flags & FLAG_ENCRYPTED and (salt_len or nonce_len):
        raise ValueError("Unencrypted headers must not contain salt or nonce bytes")
    return StegoHeader(
        flags=flags, salt=salt, nonce=nonce, payload_len=payload_len, version=version
    )


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def bytes_to_bits(data: bytes) -> List[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for shift, bit in enumerate(bits[i : i + 8]):
            byte |= (bit & 1) << (7 - shift)
        out.append(byte)
    return bytes(out)


def flatten_channels(image: Image.Image) -> List[int]:
    channels: List[int] = []
    for r, g, b in image.getdata():
        channels.extend((r, g, b))
    return channels


def rebuild_image(channels: Sequence[int], size: tuple[int, int]) -> Image.Image:
    pixels = [tuple(channels[i : i + 3]) for i in range(0, len(channels), 3)]
    new_img = Image.new("RGB", size)
    new_img.putdata(pixels)
    return new_img


def embed_bits(base_image: Image.Image, bits: Sequence[int]) -> Image.Image:
    channels = flatten_channels(base_image)
    if len(bits) > len(channels):
        raise ValueError(
            f"Payload too large: need {len(bits)} bits but image only has {len(channels)} LSBs"
        )

    updated = channels.copy()
    for idx, bit in enumerate(bits):
        value = updated[idx]
        if (value & 1) != bit:
            updated[idx] = value ^ 1 if value != 0 else 1
    return rebuild_image(updated, base_image.size)


def _iter_bytes_bits(data: bytes) -> Iterator[int]:
    """Yield a byte string's bits in the format's most-significant-first order."""
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def embed_bytes_lsb(base_image: Image.Image, data: bytes) -> Image.Image:
    """Embed bytes directly without materializing a Python integer per bit."""
    image = base_image if base_image.mode == "RGB" else base_image.convert("RGB")
    bit_count = len(data) * 8
    channel_count = image.width * image.height * 3
    if bit_count > channel_count:
        raise ValueError(
            f"Payload too large: need {bit_count} bits but image only has "
            f"{channel_count} LSBs"
        )

    result = image.copy()
    pixels = result.load()
    for bit_index, bit in enumerate(_iter_bytes_bits(data)):
        pixel_index, channel_index = divmod(bit_index, 3)
        x = pixel_index % image.width
        y = pixel_index // image.width
        pixel = pixels[x, y]
        value = pixel[channel_index]
        if (value & 1) != bit:
            channels = list(pixel)
            channels[channel_index] = value ^ 1 if value != 0 else 1
            pixels[x, y] = tuple(channels)
    return result


def _new_index_array(length: int) -> array:
    index_type = "I"
    if length > 1 << (8 * array(index_type).itemsize):
        index_type = "Q"
    return array(index_type, range(length))


def _permute_indices(length: int, rng: random.Random) -> array:
    """Return the legacy shuffle order in compact native storage."""
    idxs = _new_index_array(length)
    rng.shuffle(idxs)
    return idxs


def iter_prng_indices(
    length: int, rng: random.Random, count: int | None = None
) -> Iterator[int]:
    """Yield a deterministic permutation prefix with bounded auxiliary memory."""
    if length < 0:
        raise ValueError("Permutation length must not be negative")
    if count is None:
        count = length
    if count < 0 or count > length:
        raise ValueError("Permutation prefix length is outside the permutation")

    if count * 16 > length:
        indices = _new_index_array(length)
        for position in range(count):
            selected = position + rng.randrange(length - position)
            indices[position], indices[selected] = indices[selected], indices[position]
            yield indices[position]
        return

    substitutions: dict[int, int] = {}
    for position in range(count):
        remaining = length - position
        selected_position = position + rng.randrange(remaining)
        selected_index = substitutions.get(selected_position, selected_position)
        if selected_position != position:
            current_index = substitutions.get(position, position)
            substitutions[selected_position] = current_index
        substitutions.pop(position, None)
        yield selected_index


def make_rng(key: str) -> random.Random:
    # Deterministic seed from key using SHA-256
    seed = int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:8], "big")
    return random.Random(seed)


def _make_streaming_prng_rng(key: str, purpose: str) -> random.Random:
    """Use domain-separated deterministic streams for the v3 index permutation."""
    material = f"stego-image-v3\0{purpose}\0{key}".encode("utf-8")
    seed = int.from_bytes(hashlib.sha256(material).digest(), "big")
    return random.Random(seed)


def embed_bits_prng_streaming(
    base_image: Image.Image,
    bits: Sequence[int],
    key: str,
    lsb_match: bool = False,
) -> Image.Image:
    """Embed bits using a partial Fisher-Yates permutation and bounded state."""
    if not key:
        raise ValueError("PRNG key required for PRNG methods")
    image = base_image if base_image.mode == "RGB" else base_image.convert("RGB")
    channel_count = image.width * image.height * 3
    if len(bits) > channel_count:
        raise ValueError(
            f"Payload too large: need {len(bits)} bits but image only has "
            f"{channel_count} LSBs"
        )

    result = image.copy()
    pixels = result.load()
    index_rng = _make_streaming_prng_rng(key, "indices")
    adjustment_rng = _make_streaming_prng_rng(key, "lsb-match")
    indices = iter_prng_indices(channel_count, index_rng, count=len(bits))
    for bit, index in zip(bits, indices):
        pixel_index, channel_index = divmod(index, 3)
        x = pixel_index % image.width
        y = pixel_index // image.width
        pixel = pixels[x, y]
        value = pixel[channel_index]
        if (value & 1) == (bit & 1):
            continue
        if lsb_match:
            if value == 0:
                updated = 1
            elif value == 255:
                updated = 254
            else:
                updated = value + (1 if adjustment_rng.random() < 0.5 else -1)
        else:
            updated = value ^ 1 if value != 0 else 1
        channels = list(pixel)
        channels[channel_index] = updated
        pixels[x, y] = tuple(channels)
    return result


def embed_bytes_prng_streaming(
    base_image: Image.Image,
    data: bytes,
    key: str,
    lsb_match: bool = False,
) -> Image.Image:
    """Embed bytes with a partial Fisher-Yates permutation and bounded state."""
    if not key:
        raise ValueError("PRNG key required for PRNG methods")
    image = base_image if base_image.mode == "RGB" else base_image.convert("RGB")
    bit_count = len(data) * 8
    channel_count = image.width * image.height * 3
    if bit_count > channel_count:
        raise ValueError(
            f"Payload too large: need {bit_count} bits but image only has "
            f"{channel_count} LSBs"
        )

    result = image.copy()
    pixels = result.load()
    index_rng = _make_streaming_prng_rng(key, "indices")
    adjustment_rng = _make_streaming_prng_rng(key, "lsb-match")
    indices = iter_prng_indices(channel_count, index_rng, count=bit_count)
    for bit, index in zip(_iter_bytes_bits(data), indices):
        pixel_index, channel_index = divmod(index, 3)
        x = pixel_index % image.width
        y = pixel_index // image.width
        pixel = pixels[x, y]
        value = pixel[channel_index]
        if (value & 1) == bit:
            continue
        if lsb_match:
            if value == 0:
                updated = 1
            elif value == 255:
                updated = 254
            else:
                updated = value + (1 if adjustment_rng.random() < 0.5 else -1)
        else:
            updated = value ^ 1 if value != 0 else 1
        channels = list(pixel)
        channels[channel_index] = updated
        pixels[x, y] = tuple(channels)
    return result


def embed_bits_prng(
    base_image: Image.Image,
    bits: Sequence[int],
    rng: random.Random,
    lsb_match: bool = False,
) -> Image.Image:
    channels = flatten_channels(base_image)
    if len(bits) > len(channels):
        raise ValueError(
            f"Payload too large: need {len(bits)} bits but image only has {len(channels)} LSBs"
        )

    updated = channels.copy()
    indices = _permute_indices(len(channels), rng)
    for i, bit in enumerate(bits):
        idx = indices[i]
        value = updated[idx]
        if (value & 1) != bit:
            if lsb_match:
                if value == 0:
                    updated[idx] = 1
                elif value == 255:
                    updated[idx] = 254
                else:
                    updated[idx] = value + (1 if rng.random() < 0.5 else -1)
            else:
                updated[idx] = value ^ 1 if value != 0 else 1
    return rebuild_image(updated, base_image.size)


def extract_bits(image: Image.Image, count: int) -> List[int]:
    channels = flatten_channels(image)
    if count > len(channels):
        raise ValueError(
            f"Requested {count} bits but image only has {len(channels)} LSBs"
        )
    return [(value & 1) for value in channels[:count]]


def extract_bits_prng(image: Image.Image, count: int, rng: random.Random) -> List[int]:
    channels = flatten_channels(image)
    if count > len(channels):
        raise ValueError(
            f"Requested {count} bits but image only has {len(channels)} LSBs"
        )
    indices = _permute_indices(len(channels), rng)
    return [(channels[idx] & 1) for idx in indices[:count]]


def max_payload_bytes(image: Image.Image) -> int:
    total_bits = image.size[0] * image.size[1] * 3
    return total_bits // 8


def build_aad(header: StegoHeader) -> bytes:
    """Return the complete serialized header used as v2 AES-GCM AAD."""
    return header.to_bytes()


def apply_metadata(plaintext: bytes, metadata: dict | None) -> tuple[bytes, int]:
    if not metadata:
        return plaintext, 0
    meta_bytes = json.dumps(metadata).encode("utf-8")
    if len(meta_bytes) > 1_000_000:
        raise ValueError("Metadata too large")
    payload = len(meta_bytes).to_bytes(4, byteorder="big") + meta_bytes + plaintext
    return payload, FLAG_META


def extract_metadata(plaintext: bytes) -> tuple[dict | None, bytes]:
    if len(plaintext) < 4:
        raise ValueError("Payload too short for metadata header")
    meta_len = int.from_bytes(plaintext[:4], byteorder="big")
    if meta_len < 0 or meta_len > len(plaintext) - 4:
        raise ValueError("Invalid metadata length")
    meta_bytes = plaintext[4 : 4 + meta_len]
    if meta_len:
        try:
            metadata = json.loads(meta_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Metadata must contain valid JSON") from exc
        if not isinstance(metadata, dict):
            raise ValueError("Metadata JSON must be an object")
    else:
        metadata = None
    return metadata, plaintext[4 + meta_len :]


def check_expiration(metadata: dict | None) -> None:
    if not metadata:
        return
    expires = metadata.get("expires")
    if not expires:
        return

    # Skip invalid/placeholder expiration dates
    if not isinstance(expires, str):
        return
    if expires.startswith("e.g.,") or expires.startswith("Optional"):
        return

    try:
        exp = datetime.fromisoformat(expires)
    except ValueError:
        # Ignore invalid expiration formats instead of crashing
        # This allows decoding of data encoded with placeholder text
        return

    if exp.tzinfo is None:
        expired = datetime.now() > exp
    else:
        expired = datetime.now(timezone.utc) > exp.astimezone(timezone.utc)
    if expired:
        raise ValueError("Payload has expired")


def _prepare_plaintext(
    plaintext: bytes, *, compress: bool, metadata: dict | None
) -> tuple[bytes, int]:
    """Apply metadata and compression in the same order used by encoding."""
    prepared, flags = apply_metadata(plaintext, metadata)
    if compress:
        if len(prepared) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
            raise ValueError("Payload exceeds the 64 MiB compressed payload limit")
        prepared = zlib.compress(prepared)
        flags |= FLAG_COMPRESSED
    return prepared, flags


def max_input_payload_bytes(*, compress: bool, metadata: dict | None) -> int:
    """Bound source reads before compression and metadata envelope checks."""
    prepared_empty, _flags = apply_metadata(b"", metadata)
    if not compress:
        return MAX_METADATA_STEGO_BYTES
    return MAX_DECOMPRESSED_PAYLOAD_BYTES - len(prepared_empty)


def estimate_stego_payload_size(
    plaintext: bytes,
    *,
    encrypted: bool,
    compress: bool,
    metadata: dict | None,
) -> int:
    """Estimate the exact serialized envelope size without generating a key."""
    prepared, _flags = _prepare_plaintext(
        plaintext, compress=compress, metadata=metadata
    )
    header_size = 12 + (DEFAULT_SALT_LEN + DEFAULT_NONCE_LEN if encrypted else 0)
    encrypted_payload_size = 16 if encrypted else 0  # AES-GCM authentication tag
    return header_size + len(prepared) + encrypted_payload_size


def build_stego_payload(
    plaintext: bytes,
    flags: int,
    password: str | None,
    compress: bool,
    comment: str | None,
    expires: str | None,
    *,
    version: int = VERSION,
) -> tuple[bytes, int, bytes, bytes]:
    if version not in (VERSION, STREAMING_PRNG_VERSION):
        raise ValueError(f"Unsupported output version: {version}")
    metadata = None
    if comment or expires:
        metadata = {"comment": comment or "", "expires": expires or ""}
    plaintext, payload_flags = _prepare_plaintext(
        plaintext, compress=compress, metadata=metadata
    )
    flags |= payload_flags

    salt = b""
    nonce = b""
    payload_bytes = plaintext
    if password:
        flags |= FLAG_ENCRYPTED
        salt = os.urandom(DEFAULT_SALT_LEN)
        nonce = os.urandom(DEFAULT_NONCE_LEN)
        key = derive_key(password, salt)
        header = StegoHeader(
            flags=flags,
            salt=salt,
            nonce=nonce,
            payload_len=len(plaintext) + 16,
            version=version,
        )
        payload_bytes = AESGCM(key).encrypt(nonce, plaintext, build_aad(header))
    else:
        header = StegoHeader(
            flags=flags,
            salt=salt,
            nonce=nonce,
            payload_len=len(payload_bytes),
            version=version,
        )

    return header.to_bytes() + payload_bytes, flags, salt, nonce


def parse_stego_payload(
    stego_data: bytes, password: str | None
) -> tuple[int, bytes, dict | None]:
    if len(stego_data) < 12:
        raise ValueError("Stego data too short")
    header_prefix = stego_data[:12]
    salt_len = header_prefix[6]
    nonce_len = header_prefix[7]
    extra_len = salt_len + nonce_len
    if len(stego_data) < 12 + extra_len:
        raise ValueError("Incomplete stego header")
    header = parse_header(stego_data[: 12 + extra_len])
    payload_start = 12 + extra_len
    payload_end = payload_start + header.payload_len
    if payload_end > len(stego_data):
        raise ValueError("Stego payload length is invalid")
    trailing = len(stego_data) - payload_end
    legacy_image_dimensions = (
        header.version == LEGACY_VERSION
        and bool(header.flags & FLAG_PAYLOAD_IMAGE)
        and trailing == 8
    )
    if trailing and not legacy_image_dimensions:
        raise ValueError("Stego payload length does not match serialized data")
    payload = stego_data[payload_start:payload_end]

    if header.flags & FLAG_ENCRYPTED:
        if not password:
            raise ValueError("Password required to decrypt payload")
        key = derive_key(password, header.salt)
        if header.version == LEGACY_VERSION:
            aad = (
                MAGIC
                + bytes([LEGACY_VERSION, header.flags])
                + header.salt
                + header.nonce
            )
        else:
            aad = build_aad(header)
        try:
            plaintext = AESGCM(key).decrypt(header.nonce, payload, aad)
        except InvalidTag as exc:
            raise ValueError(
                "Password is incorrect or the embedded payload was modified"
            ) from exc
    else:
        plaintext = payload

    if header.flags & FLAG_COMPRESSED:
        try:
            decompressor = zlib.decompressobj()
            plaintext = decompressor.decompress(
                plaintext, MAX_DECOMPRESSED_PAYLOAD_BYTES + 1
            )
            if len(plaintext) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
                raise ValueError("Decompressed payload exceeds the 64 MiB limit")
            if decompressor.unconsumed_tail:
                raise ValueError("Decompressed payload exceeds the 64 MiB limit")
            if not decompressor.eof or decompressor.unused_data:
                raise ValueError("Compressed payload is incomplete or invalid")
        except zlib.error as exc:
            raise ValueError("Compressed payload could not be decompressed") from exc

    metadata = None
    if header.flags & FLAG_META:
        metadata, plaintext = extract_metadata(plaintext)
        check_expiration(metadata)

    return header.flags, plaintext, metadata
