"""Visible metadata embedding in MP4, MKV, AVI, and WebM containers."""

from __future__ import annotations

import base64
import logging
import os
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

import imageio_ffmpeg

from .core import (
    FLAG_PAYLOAD_TEXT,
    FFMPEG_VIDEO_EXTS,
    MP4_CONTAINER_EXTS,
    MAX_METADATA_STEGO_BYTES,
    build_stego_payload,
    decode_stego_base64,
    ensure_metadata_capacity,
    max_input_payload_bytes,
    parse_stego_payload,
)
from .audio import embed_data_in_mp4, extract_data_from_mp4
from .image import read_payload
from .utils import (
    ensure_output_differs_from_input,
    ensure_output_differs_from_payloads,
)

MAX_STEGO_BASE64_LENGTH = 4 * ((MAX_METADATA_STEGO_BYTES + 2) // 3)
MAX_ESCAPED_COMMENT_VALUE_LENGTH = MAX_STEGO_BASE64_LENGTH + 2
MAX_FFMETADATA_LINE_LENGTH = len(b"comment=") + MAX_ESCAPED_COMMENT_VALUE_LENGTH + 2
MAX_FFMETADATA_OUTPUT_BYTES = 4_000_000


def _escape_ffmetadata(value: str) -> str:
    """Escape a value for FFmpeg's ffmetadata input format."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace(";", "\\;")
        .replace("#", "\\#")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _ffmetadata_with_comment(metadata: str, comment: str) -> str:
    """Replace the global comment while retaining other FFmetadata fields."""
    lines = metadata.splitlines()
    if not lines or lines[0] != ";FFMETADATA1":
        raise ValueError("ffmpeg did not return valid carrier metadata")

    comment_line = f"comment={_escape_ffmetadata(comment)}"
    merged = [lines[0]]
    inserted_comment = False
    in_global_section = True
    for line in lines[1:]:
        if line.startswith("["):
            if not inserted_comment:
                merged.append(comment_line)
                inserted_comment = True
            in_global_section = False
        if in_global_section:
            key, separator, _value = line.partition("=")
            if separator and key.casefold() == "comment":
                continue
        merged.append(line)
    if not inserted_comment:
        merged.append(comment_line)
    return "\n".join(merged) + "\n"


def _iter_bounded_ffmetadata_lines(
    stdout: BinaryIO,
    *,
    max_line_length: int,
    max_output_bytes: int,
) -> Iterator[bytes]:
    """Yield FFmetadata lines while enforcing per-line and aggregate limits."""
    total_output_bytes = 0
    while True:
        line = stdout.readline(max_line_length + 1)
        if not line:
            return
        total_output_bytes += len(line)
        if total_output_bytes > max_output_bytes:
            raise ValueError(
                f"Video metadata output exceeds the {max_output_bytes:,}-byte limit"
            )
        if len(line) > max_line_length:
            raise ValueError("Video metadata contains an oversized field")
        yield line


def _capture_ffmetadata(command: list[str]) -> str:
    """Capture carrier FFmetadata with a strict aggregate output bound."""
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
    except OSError as exc:
        raise ValueError("Could not run FFmpeg to read carrier metadata") from exc

    if process.stdout is None:
        process.kill()
        process.wait()
        raise ValueError("Could not read FFmpeg metadata output")

    try:
        lines = list(
            _iter_bounded_ffmetadata_lines(
                process.stdout,
                max_line_length=MAX_FFMETADATA_OUTPUT_BYTES,
                max_output_bytes=MAX_FFMETADATA_OUTPUT_BYTES,
            )
        )
        return_code = process.wait()
    except BaseException:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        process.wait()
        raise
    finally:
        process.stdout.close()

    if return_code != 0:
        raise ValueError("Could not read carrier video metadata")
    return b"".join(lines).decode("utf-8", errors="replace")


def _same_file_path(input_path: Path, output_path: Path) -> bool:
    """Detect identical paths and existing hard-link aliases."""
    if input_path.resolve() == output_path.resolve():
        return True
    if input_path.exists() and output_path.exists():
        try:
            return os.path.samefile(input_path, output_path)
        except OSError:
            return False
    return False


def _ffmpeg_embed_comment(input_path: str, output_path: str, comment: str) -> None:
    """Store the encoded envelope in a visible FFmpeg container comment."""
    source = Path(input_path)
    output = Path(output_path)
    if _same_file_path(source, output):
        raise ValueError("Input and output video paths must be different")

    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    read_metadata_cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(source),
        "-f",
        "ffmetadata",
        "-",
    ]
    try:
        metadata_text = _capture_ffmetadata(read_metadata_cmd)
    except OSError as exc:
        raise ValueError("Could not run FFmpeg to read carrier metadata") from exc

    temporary_output: Path | None = None
    temporary_paths: list[Path] = []
    try:
        metadata_fd, metadata_name = tempfile.mkstemp(
            prefix=f".{output.stem}.", suffix=".ffmeta", dir=output.parent
        )
        metadata_path = Path(metadata_name)
        temporary_paths.append(metadata_path)
        os.close(metadata_fd)
        with open(metadata_path, "w", encoding="utf-8", newline="\n") as metadata_file:
            metadata_file.write(_ffmetadata_with_comment(metadata_text, comment))

        output_fd, output_name = tempfile.mkstemp(
            prefix=f".{output.stem}.", suffix=output.suffix, dir=output.parent
        )
        temporary_output = Path(output_name)
        temporary_paths.append(temporary_output)
        os.close(output_fd)

        command = [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-i",
            str(source),
            "-f",
            "ffmetadata",
            "-i",
            str(metadata_path),
            "-map",
            "0",
            "-map_metadata",
            "1",
            "-c",
            "copy",
            str(temporary_output),
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise ValueError("Could not run FFmpeg to write video metadata") from exc
        if result.returncode != 0:
            details = result.stderr.strip()
            message = "ffmpeg failed to write metadata"
            if details:
                message = f"{message}: {details[-1000:]}"
            raise ValueError(message)
        if not temporary_output.is_file() or temporary_output.stat().st_size == 0:
            raise ValueError("ffmpeg produced no video output")

        os.replace(temporary_output, output)
    finally:
        for temporary_path in temporary_paths:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _ffmpeg_extract_comment(path: str) -> str:
    """Read the visible comment containing an encoded envelope."""
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    command = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        path,
        "-f",
        "ffmetadata",
        "-",
    ]
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
    except OSError as exc:
        raise ValueError("Could not run FFmpeg to read video metadata") from exc

    if process.stdout is None:
        process.kill()
        process.wait()
        raise ValueError("Could not read FFmpeg metadata output")

    comment_value: str | None = None
    in_global_section = True
    try:
        for line in _iter_bounded_ffmetadata_lines(
            process.stdout,
            max_line_length=MAX_FFMETADATA_LINE_LENGTH,
            max_output_bytes=MAX_FFMETADATA_OUTPUT_BYTES,
        ):
            if line.lstrip().startswith(b"["):
                in_global_section = False
                continue
            if not in_global_section:
                continue
            key, separator, value = line.rstrip(b"\r\n").partition(b"=")
            if not separator or key.strip().lower() != b"comment":
                continue
            if len(value) > MAX_ESCAPED_COMMENT_VALUE_LENGTH:
                raise ValueError(
                    "Embedded video comment exceeds the 1,000,000-byte limit"
                )
            try:
                encoded = value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("Embedded video comment is not valid base64") from exc
            comment_value = _unescape_ffmetadata(encoded)
            if len(comment_value) > MAX_STEGO_BASE64_LENGTH:
                raise ValueError(
                    "Embedded video comment exceeds the 1,000,000-byte limit"
                )

        return_code = process.wait()
    except BaseException:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        process.wait()
        raise
    finally:
        process.stdout.close()

    if return_code != 0:
        raise ValueError("Could not read video metadata")
    if comment_value is None:
        raise ValueError("No embedded data found in video metadata comment")
    return comment_value


def _unescape_ffmetadata(value: str) -> str:
    """Unescape FFmpeg's ffmetadata value encoding."""
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            index += 1
            escaped = value[index]
            result.append({"n": "\n", "r": "\r"}.get(escaped, escaped))
        else:
            result.append(value[index])
        index += 1
    return "".join(result)


def _video_metadata_backend(path: str) -> str | None:
    """Return the extractor selected by a video carrier's extension."""
    ext = Path(path).suffix.lower()
    if ext in MP4_CONTAINER_EXTS:
        return "mp4"
    if ext in FFMPEG_VIDEO_EXTS:
        return "ffmpeg-comment"
    return None


def embed_data_in_video(
    video_path: str,
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
    """Store a payload in visible video metadata for the selected container."""
    ensure_output_differs_from_payloads(output_path, in_file, image_path, mp3_path)
    input_suffix = Path(video_path).suffix.casefold()
    output_suffix = Path(output_path).suffix.casefold()
    if input_suffix != output_suffix:
        raise ValueError("Input and output video carrier suffixes must match")

    backend = _video_metadata_backend(video_path)
    if backend is None:
        raise ValueError("Unsupported video format")
    if _video_metadata_backend(output_path) != backend:
        raise ValueError(
            "Input and output video carrier extensions select different metadata backends"
        )

    if backend == "mp4":
        embed_data_in_mp4(
            video_path,
            output_path,
            password=password,
            message=message,
            in_file=in_file,
            image_path=image_path,
            mp3_path=mp3_path,
            compress=compress,
            comment=comment,
            expires=expires,
        )
        return
    if image_path or mp3_path:
        raise ValueError(
            "Image/MP3 payloads are only supported for MP4-family containers"
        )

    metadata = (
        {"comment": comment or "", "expires": expires or ""}
        if comment or expires
        else None
    )
    max_bytes = max_input_payload_bytes(compress=compress, metadata=metadata)
    payload = read_payload(message, in_file, max_bytes=max_bytes)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, _flags, _salt, _nonce = build_stego_payload(
        payload, flags, password, compress, comment, expires
    )
    ensure_metadata_capacity(stego_data)
    stego_b64 = base64.b64encode(stego_data).decode("ascii")
    _ffmpeg_embed_comment(video_path, output_path, stego_b64)
    logging.info("Embedded visible metadata in video: %s", output_path)


def extract_data_from_video(
    video_path: str, output_path: str, password: str | None = None
) -> None:
    """Extract a payload from visible video metadata."""
    ensure_output_differs_from_input(video_path, output_path, "Video")
    backend = _video_metadata_backend(video_path)
    if backend == "mp4":
        extract_data_from_mp4(video_path, output_path, password=password)
        return
    if backend is None:
        raise ValueError("Unsupported video format")

    stego_b64 = _ffmpeg_extract_comment(video_path)
    stego_data = decode_stego_base64(stego_b64)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    logging.info("Extracted text/file from video: %s", output_path)
