"""Image steganography operations - LSB embedding in images, GIFs, and video frames."""

from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageSequence
import imageio.v2 as imageio
import numpy as np

from .core import (
    bytes_to_bits, bits_to_bytes, embed_bits, extract_bits,
    embed_bits_prng, extract_bits_prng, flatten_channels, make_rng,
    max_payload_bytes, parse_header, build_stego_payload, parse_stego_payload,
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


def embed_stego_data_in_image(image: Image.Image, stego_data: bytes, method: str, prng_key: str | None) -> Image.Image:
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


def embed_data_in_gif(gif_path: str, output_path: str, frame_index: int,
                      message: str | None = None, in_file: str | None = None,
                      password: str | None = None, method: str = "lsb",
                      prng_key: str | None = None, compress: bool = False,
                      comment: str | None = None, expires: str | None = None) -> None:
    payload = read_payload(message, in_file)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, _flags, _salt, _nonce = build_stego_payload(payload, flags, password, compress, comment, expires)

    image = Image.open(gif_path)
    frames = [frame.copy().convert("RGB") for frame in ImageSequence.Iterator(image)]
    if frame_index < 0 or frame_index >= len(frames):
        raise ValueError("Frame index out of range")

    max_bytes = max_payload_bytes(frames[frame_index])
    if len(stego_data) > max_bytes:
        raise ValueError("Payload too large for selected frame")

    frames[frame_index] = embed_stego_data_in_image(frames[frame_index], stego_data, method, prng_key)
    frames[0].save(output_path, save_all=True, append_images=frames[1:], loop=0, duration=image.info.get("duration", 100))


def extract_data_from_gif(gif_path: str, frame_index: int, password: str | None = None,
                          method: str = "lsb", prng_key: str | None = None) -> bytes:
    image = Image.open(gif_path)
    frames = [frame.copy().convert("RGB") for frame in ImageSequence.Iterator(image)]
    if frame_index < 0 or frame_index >= len(frames):
        raise ValueError("Frame index out of range")
    stego_data = extract_stego_data_from_image(frames[frame_index], method, prng_key)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    return plaintext


def embed_data_in_video_frame(video_path: str, output_path: str, frame_index: int,
                              message: str | None = None, in_file: str | None = None,
                              password: str | None = None, method: str = "lsb",
                              prng_key: str | None = None, compress: bool = False,
                              comment: str | None = None, expires: str | None = None) -> None:
    payload = read_payload(message, in_file)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, _flags, _salt, _nonce = build_stego_payload(payload, flags, password, compress, comment, expires)

    reader = imageio.get_reader(video_path)
    meta = reader.get_meta_data()
    fps = meta.get("fps", 24)
    writer = imageio.get_writer(output_path, fps=fps)

    embedded = False
    for idx, frame in enumerate(reader):
        if idx == frame_index:
            pil = Image.fromarray(frame).convert("RGB")
            max_bytes_val = max_payload_bytes(pil)
            if len(stego_data) > max_bytes_val:
                reader.close()
                writer.close()
                raise ValueError("Payload too large for selected frame")
            stego_frame = embed_stego_data_in_image(pil, stego_data, method, prng_key)
            writer.append_data(np.asarray(stego_frame))
            embedded = True
        else:
            writer.append_data(frame)
    reader.close()
    writer.close()
    if not embedded:
        raise ValueError("Frame index out of range")


def extract_data_from_video_frame(video_path: str, frame_index: int, password: str | None = None,
                                  method: str = "lsb", prng_key: str | None = None) -> bytes:
    reader = imageio.get_reader(video_path)
    try:
        frame = reader.get_data(frame_index)
    except IndexError as exc:
        reader.close()
        raise ValueError("Frame index out of range") from exc
    reader.close()
    pil = Image.fromarray(frame).convert("RGB")
    stego_data = extract_stego_data_from_image(pil, method, prng_key)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    return plaintext
