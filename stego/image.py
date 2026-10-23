"""Image and lossless video-frame LSB embedding operations."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from PIL import Image
import imageio.v2 as imageio
import numpy as np

from .core import (
    bytes_to_bits, bits_to_bytes, embed_bits, extract_bits,
    embed_bits_prng, extract_bits_prng, flatten_channels, make_rng,
    parse_header, build_stego_payload, parse_stego_payload,
    FLAG_PAYLOAD_TEXT,
)


def load_image(path: str) -> Image.Image:
    try:
        img = Image.open(path).convert("RGB")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Image not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not open image '{path}': {exc}") from exc
    return img


def image_capacity_bytes(image: Image.Image) -> int:
    """Return whole bytes available in the image's RGB least significant bits."""
    return image.width * image.height * 3 // 8


def _require_output_suffix(path: str, suffix: str, mode: str) -> None:
    if Path(path).suffix.lower() != suffix:
        raise ValueError(f"{mode} output must use the {suffix.upper()} format")


def embed_stego_data_in_image(image: Image.Image, stego_data: bytes, method: str, prng_key: str | None) -> Image.Image:
    if len(stego_data) > image_capacity_bytes(image):
        raise ValueError(
            f"Payload too large: need {len(stego_data)} bytes but image can store "
            f"{image_capacity_bytes(image)} bytes"
        )
    bits = bytes_to_bits(stego_data)
    if method == "lsb":
        return embed_bits(image, bits)
    if method in ("lsb-prng", "lsb-match-prng"):
        if not prng_key:
            raise ValueError("PRNG key required for PRNG methods")
        rng = make_rng(prng_key)
        return embed_bits_prng(image, bits, rng, lsb_match=(method == "lsb-match-prng"))
    raise ValueError(f"Unknown method: {method}")


def extract_stego_data_from_image(image: Image.Image, method: str, prng_key: str | None) -> bytes:
    channels_len = len(flatten_channels(image))
    if method == "lsb":
        all_bits = extract_bits(image, channels_len)
    elif method in ("lsb-prng", "lsb-match-prng"):
        if not prng_key:
            raise ValueError("PRNG key required for PRNG methods")
        rng = make_rng(prng_key)
        all_bits = extract_bits_prng(image, channels_len, rng)
    else:
        raise ValueError(f"Unknown method: {method}")

    def read_bytes_from_bits(offset_bits: int, num_bytes: int) -> bytes:
        bit_slice = all_bits[offset_bits: offset_bits + num_bytes * 8]
        if len(bit_slice) < num_bytes * 8:
            raise ValueError("Unexpected end of data while decoding")
        return bits_to_bytes(bit_slice)

    header_prefix = read_bytes_from_bits(0, 12)
    salt_len = header_prefix[6]
    nonce_len = header_prefix[7]
    extra_len = salt_len + nonce_len
    header = parse_header(header_prefix + read_bytes_from_bits(12 * 8, extra_len))
    header_len = 12 + extra_len
    payload_bits = all_bits[header_len * 8: (header_len + header.payload_len) * 8]
    if len(payload_bits) < header.payload_len * 8:
        raise ValueError("Image does not contain the full payload")
    payload = bits_to_bytes(payload_bits)
    return header.to_bytes() + payload


def read_payload(message: str | None, in_file: str | None) -> bytes:
    """Read payload data from message string or input file."""
    if message is not None and in_file is not None:
        raise ValueError("Cannot specify both --message and --in-file")
    if message is None and in_file is None:
        raise ValueError("Must specify either --message or --in-file")
    if message:
        return message.encode("utf-8")
    assert in_file is not None
    with open(in_file, "rb") as f:
        return f.read()


def embed_data_in_video_frame(video_path: str, output_path: str, frame_index: int,
                              message: str | None = None, in_file: str | None = None,
                              password: str | None = None, method: str = "lsb",
                              prng_key: str | None = None, compress: bool = False,
                              comment: str | None = None, expires: str | None = None) -> None:
    _require_output_suffix(output_path, ".mkv", "Video-frame")
    if Path(video_path).resolve() == Path(output_path).resolve():
        raise ValueError("Video-frame input and output paths must differ")
    if frame_index < 0:
        raise ValueError("Frame index out of range")
    payload = read_payload(message, in_file)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, _flags, _salt, _nonce = build_stego_payload(payload, flags, password, compress, comment, expires)

    probe = imageio.get_reader(video_path)
    try:
        meta = probe.get_meta_data()
        try:
            selected_frame = probe.get_data(frame_index)
        except IndexError as exc:
            raise ValueError("Frame index out of range") from exc
        selected_image = Image.fromarray(selected_frame).convert("RGB")
        if len(stego_data) > image_capacity_bytes(selected_image):
            raise ValueError("Payload too large for selected frame")
        fps = meta.get("fps") or 24
    finally:
        probe.close()

    temporary_output = None
    try:
        output = Path(output_path)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{output.stem}.", suffix=output.suffix, dir=output.parent
        )
        temporary_output = Path(temporary_name)
        os.close(fd)

        reader = imageio.get_reader(video_path)
        try:
            writer = imageio.get_writer(
                str(temporary_output),
                fps=fps,
                codec="ffv1",
                pixelformat="bgr0",
                macro_block_size=1,
                format="FFMPEG",
            )
            try:
                for idx, frame in enumerate(reader):
                    if idx == frame_index:
                        pil = Image.fromarray(frame).convert("RGB")
                        frame = np.asarray(
                            embed_stego_data_in_image(pil, stego_data, method, prng_key)
                        )
                    else:
                        frame = np.asarray(Image.fromarray(frame).convert("RGB"))
                    writer.append_data(frame)
            finally:
                writer.close()
        finally:
            reader.close()

        os.replace(temporary_output, output)
    except BaseException:
        if temporary_output is not None:
            try:
                temporary_output.unlink()
            except FileNotFoundError:
                pass
        raise


def extract_data_from_video_frame(video_path: str, frame_index: int, password: str | None = None,
                                  method: str = "lsb", prng_key: str | None = None) -> bytes:
    if frame_index < 0:
        raise ValueError("Frame index out of range")
    reader = imageio.get_reader(video_path)
    try:
        frame = reader.get_data(frame_index)
    except IndexError as exc:
        raise ValueError("Frame index out of range") from exc
    finally:
        reader.close()
    pil = Image.fromarray(frame).convert("RGB")
    stego_data = extract_stego_data_from_image(pil, method, prng_key)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    return plaintext
