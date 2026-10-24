"""Image and lossless video-frame LSB embedding operations."""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from PIL import Image
import imageio.v2 as imageio
import imageio_ffmpeg
import numpy as np

from .core import (
    FLAG_LSB_MATCH,
    FLAG_PRNG,
    STREAMING_PRNG_VERSION,
    VERSION,
    StegoHeader,
    _make_streaming_prng_rng,
    _permute_indices,
    bytes_to_bits,
    embed_bytes_lsb,
    embed_bits_prng,
    embed_bytes_prng_streaming,
    iter_prng_indices,
    make_rng,
    parse_header,
    build_stego_payload,
    parse_stego_payload,
    estimate_stego_payload_size,
    FLAG_PAYLOAD_TEXT,
    max_input_payload_bytes,
)
from .utils import (
    ensure_output_differs_from_input,
    ensure_output_differs_from_payloads,
    read_bounded_file,
)

MAX_LEGACY_PRNG_CHANNELS = 32 * 1024 * 1024


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


def embed_stego_data_in_image(
    image: Image.Image, stego_data: bytes, method: str, prng_key: str | None
) -> Image.Image:
    rgb_image = image if image.mode == "RGB" else image.convert("RGB")
    if len(stego_data) > image_capacity_bytes(rgb_image):
        raise ValueError(
            f"Payload too large: need {len(stego_data)} bytes but image can store "
            f"{image_capacity_bytes(rgb_image)} bytes"
        )
    if method not in ("lsb", "lsb-prng", "lsb-match-prng"):
        raise ValueError(f"Unknown method: {method}")
    header = None
    if len(stego_data) >= 12:
        header_len = 12 + stego_data[6] + stego_data[7]
        if len(stego_data) >= header_len:
            header = parse_header(stego_data[:header_len])
    if header is not None and header.version == STREAMING_PRNG_VERSION:
        if method == "lsb" or not header.flags & FLAG_PRNG:
            raise ValueError("Version 3 image envelopes require a PRNG method")
        if bool(header.flags & FLAG_LSB_MATCH) != (method == "lsb-match-prng"):
            raise ValueError("Image method does not match the version 3 envelope flags")
        if not prng_key:
            raise ValueError("PRNG key required for PRNG methods")
        return embed_bytes_prng_streaming(
            rgb_image, stego_data, prng_key, lsb_match=(method == "lsb-match-prng")
        )
    if method == "lsb":
        return embed_bytes_lsb(rgb_image, stego_data)
    if method in ("lsb-prng", "lsb-match-prng"):
        if not prng_key:
            raise ValueError("PRNG key required for PRNG methods")
        bits = bytes_to_bits(stego_data)
        rng = make_rng(prng_key)
        return embed_bits_prng(
            rgb_image, bits, rng, lsb_match=(method == "lsb-match-prng")
        )
    raise ValueError(f"Unknown method: {method}")


def _iter_image_bits(
    image: Image.Image,
    method: str,
    prng_key: str | None,
    *,
    streaming_prng: bool = False,
    prng_count: int | None = None,
) -> Iterator[int]:
    rgb_image = image if image.mode == "RGB" else image.convert("RGB")
    if method == "lsb":
        for y in range(rgb_image.height):
            for x in range(rgb_image.width):
                for channel in rgb_image.getpixel((x, y)):
                    yield channel & 1
    elif method in ("lsb-prng", "lsb-match-prng"):
        if not prng_key:
            raise ValueError("PRNG key required for PRNG methods")
        channel_count = rgb_image.width * rgb_image.height * 3
        if streaming_prng:
            pixels = rgb_image.load()
            indices = iter_prng_indices(
                channel_count,
                _make_streaming_prng_rng(prng_key, "indices"),
                count=prng_count,
            )
            for index in indices:
                pixel_index, channel_index = divmod(index, 3)
                x = pixel_index % rgb_image.width
                y = pixel_index // rgb_image.width
                yield pixels[x, y][channel_index] & 1
        else:
            channels = rgb_image.tobytes()
            indices = _permute_indices(len(channels), make_rng(prng_key))
            for index in indices:
                yield channels[index] & 1
    else:
        raise ValueError(f"Unknown method: {method}")


def _read_image_bytes(bit_stream: Iterator[int], count: int, error: str) -> bytes:
    result = bytearray()
    try:
        for _ in range(count):
            byte = 0
            for _ in range(8):
                byte = (byte << 1) | next(bit_stream)
            result.append(byte)
    except StopIteration as exc:
        raise ValueError(error) from exc
    return bytes(result)


def _read_image_header_once(
    image: Image.Image,
    method: str,
    prng_key: str | None,
    *,
    streaming_prng: bool = False,
    prng_count: int | None = None,
) -> tuple[StegoHeader, bytes, Iterator[int]]:
    capacity = image_capacity_bytes(image)
    bit_stream = _iter_image_bits(
        image,
        method,
        prng_key,
        streaming_prng=streaming_prng,
        prng_count=prng_count,
    )
    prefix = _read_image_bytes(
        bit_stream, 12, "Header too short; not a valid stego payload"
    )
    header_extra_len = prefix[6] + prefix[7]
    header_bytes = prefix + _read_image_bytes(
        bit_stream, header_extra_len, "Header incomplete; missing salt or nonce bytes"
    )
    header = parse_header(header_bytes)
    if len(header_bytes) + header.payload_len > capacity:
        raise ValueError("Image does not contain the full payload")
    return header, header_bytes, bit_stream


def _read_image_header(
    image: Image.Image, method: str, prng_key: str | None
) -> tuple[StegoHeader, bytes, Iterator[int]]:
    if method not in {"lsb", "lsb-prng", "lsb-match-prng"}:
        raise ValueError(f"Unknown method: {method}")
    is_prng = method != "lsb"
    if is_prng and not prng_key:
        raise ValueError("PRNG key required for PRNG methods")
    if not is_prng:
        result = _read_image_header_once(image, method, prng_key)
        if result[0].version == STREAMING_PRNG_VERSION:
            raise ValueError("Version 3 image envelope requires a PRNG method")
        return result

    try:
        streaming_result = _read_image_header_once(
            image,
            method,
            prng_key,
            streaming_prng=True,
            prng_count=min(
                image.width * image.height * 3,
                (12 + 255 + 255) * 8,
            ),
        )
    except ValueError:
        streaming_result = None
    if streaming_result is not None:
        streaming_header = streaming_result[0]
        if streaming_header.version == STREAMING_PRNG_VERSION:
            if not streaming_header.flags & FLAG_PRNG:
                raise ValueError("Unsupported version 3 PRNG image envelope")
            expected_lsb_match = method == "lsb-match-prng"
            if bool(streaming_header.flags & FLAG_LSB_MATCH) != expected_lsb_match:
                raise ValueError(
                    "Image method does not match the version 3 envelope flags"
                )
            expected_header = streaming_result[1]
            streaming_result = None
            full_result = _read_image_header_once(
                image,
                method,
                prng_key,
                streaming_prng=True,
                prng_count=(len(expected_header) + streaming_header.payload_len) * 8,
            )
            if full_result[1] != expected_header:
                raise ValueError("Version 3 image header changed during extraction")
            return full_result

    channel_count = image.width * image.height * 3
    if channel_count > MAX_LEGACY_PRNG_CHANNELS:
        raise ValueError(
            "Legacy version 1 and 2 PRNG images are limited to "
            f"{MAX_LEGACY_PRNG_CHANNELS:,} channel positions; this carrier has "
            f"{channel_count:,}. Version 3 PRNG images do not have this limit."
        )

    legacy_result = _read_image_header_once(image, method, prng_key)
    if legacy_result[0].version == STREAMING_PRNG_VERSION:
        raise ValueError("Unsupported version 3 PRNG image envelope")
    return legacy_result


def extract_image_header(
    image: Image.Image, method: str, prng_key: str | None
) -> StegoHeader:
    """Read and validate the image envelope header without loading its payload."""
    header, _header_bytes, _bit_stream = _read_image_header(image, method, prng_key)
    return header


def extract_stego_data_from_image(
    image: Image.Image, method: str, prng_key: str | None
) -> bytes:
    header, header_bytes, bit_stream = _read_image_header(image, method, prng_key)
    payload = _read_image_bytes(
        bit_stream, header.payload_len, "Image does not contain the full payload"
    )
    return header_bytes + payload


def max_image_payload_bytes(
    image: Image.Image,
    *,
    password: str | None,
    compress: bool,
    comment: str | None,
    expires: str | None,
) -> int:
    """Return the input limit that an image envelope can accept before embedding."""
    metadata = None
    if comment or expires:
        metadata = {"comment": comment or "", "expires": expires or ""}

    if compress:
        return max_input_payload_bytes(compress=True, metadata=metadata)

    empty_envelope_size = estimate_stego_payload_size(
        b"",
        encrypted=bool(password),
        compress=False,
        metadata=metadata,
    )
    return image_capacity_bytes(image) - empty_envelope_size


def read_payload(
    message: str | None,
    in_file: str | None,
    *,
    max_bytes: int | None = None,
) -> bytes:
    """Read payload data from message string or input file."""
    if message is not None and in_file is not None:
        raise ValueError("Cannot specify both --message and --in-file")
    if message is None and in_file is None:
        raise ValueError("Must specify either --message or --in-file")
    if message is not None:
        payload = message.encode("utf-8")
        if max_bytes is not None and len(payload) > max_bytes:
            if max_bytes < 0:
                raise ValueError("Payload too large: exceeds the available capacity")
            raise ValueError(
                f"Payload too large: exceeds the {max_bytes:,}-byte input limit"
            )
        return payload
    assert in_file is not None
    if max_bytes is not None:
        return read_bounded_file(in_file, max_bytes)
    with open(in_file, "rb") as f:
        return f.read()


def _remux_video_frame_audio(
    source_path: str, encoded_video_path: Path, remuxed_output_path: Path
) -> None:
    """Remux the encoded frames with all source audio streams, if any."""
    command = [
        imageio_ffmpeg.get_ffmpeg_exe(),
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-copyts",
        "-start_at_zero",
        "-i",
        str(encoded_video_path),
        "-i",
        source_path,
        "-map",
        "0:v:0",
        "-map",
        "1:a?",
        "-c",
        "copy",
        "-map_metadata",
        "1",
        "-avoid_negative_ts",
        "make_zero",
        str(remuxed_output_path),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except OSError as exc:
        raise ValueError("Could not run FFmpeg to preserve source audio") from exc
    if result.returncode != 0:
        details = result.stderr.strip()
        message = "FFmpeg could not remux source audio into the lossless MKV output"
        if details:
            message = f"{message}: {details[-1000:]}"
        raise ValueError(message)
    if not remuxed_output_path.is_file() or remuxed_output_path.stat().st_size == 0:
        raise ValueError("FFmpeg produced no lossless MKV output")


def embed_data_in_video_frame(
    video_path: str,
    output_path: str,
    frame_index: int,
    message: str | None = None,
    in_file: str | None = None,
    password: str | None = None,
    method: str = "lsb",
    prng_key: str | None = None,
    compress: bool = False,
    comment: str | None = None,
    expires: str | None = None,
) -> None:
    _require_output_suffix(output_path, ".mkv", "Video-frame")
    ensure_output_differs_from_input(video_path, output_path, "Video-frame")
    ensure_output_differs_from_payloads(output_path, in_file)
    if frame_index < 0:
        raise ValueError("Frame index out of range")

    probe = imageio.get_reader(video_path)
    try:
        meta = probe.get_meta_data()
        try:
            selected_frame = probe.get_data(frame_index)
        except IndexError as exc:
            raise ValueError("Frame index out of range") from exc
        selected_image = Image.fromarray(selected_frame).convert("RGB")
        payload_limit = max_image_payload_bytes(
            selected_image,
            password=password,
            compress=compress,
            comment=comment,
            expires=expires,
        )
        payload = read_payload(message, in_file, max_bytes=payload_limit)
        flags = FLAG_PAYLOAD_TEXT
        version = VERSION
        if method in {"lsb-prng", "lsb-match-prng"}:
            flags |= FLAG_PRNG
            if method == "lsb-match-prng":
                flags |= FLAG_LSB_MATCH
            version = STREAMING_PRNG_VERSION
        stego_data, _flags, _salt, _nonce = build_stego_payload(
            payload, flags, password, compress, comment, expires, version=version
        )
        if len(stego_data) > image_capacity_bytes(selected_image):
            raise ValueError("Payload too large for selected frame")
        fps = meta.get("fps") or 24
    finally:
        probe.close()

    temporary_outputs: list[Path] = []
    try:
        output = Path(output_path)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{output.stem}.frames.", suffix=".mkv", dir=output.parent
        )
        temporary_output = Path(temporary_name)
        temporary_outputs.append(temporary_output)
        os.close(fd)

        fd, remuxed_name = tempfile.mkstemp(
            prefix=f".{output.stem}.remux.", suffix=".mkv", dir=output.parent
        )
        remuxed_output = Path(remuxed_name)
        temporary_outputs.append(remuxed_output)
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

        _remux_video_frame_audio(video_path, temporary_output, remuxed_output)
        temporary_output.unlink()
        os.replace(remuxed_output, output)
    except BaseException:
        for temporary_output in temporary_outputs:
            try:
                temporary_output.unlink()
            except FileNotFoundError:
                pass
        raise


def extract_data_from_video_frame(
    video_path: str,
    frame_index: int,
    password: str | None = None,
    method: str = "lsb",
    prng_key: str | None = None,
) -> bytes:
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
