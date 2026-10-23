"""Visible metadata embedding in MP4, MKV, AVI, and WebM containers."""

from __future__ import annotations

import base64
import logging
import subprocess
from pathlib import Path

import imageio_ffmpeg

from .core import (
    FLAG_PAYLOAD_TEXT,
    FFMPEG_VIDEO_EXTS, MP4_CONTAINER_EXTS,
    build_stego_payload, decode_stego_base64, ensure_metadata_capacity,
    parse_stego_payload,
)
from .audio import embed_data_in_mp4, extract_data_from_mp4
from .image import read_payload


def _ffmpeg_embed_comment(input_path: str, output_path: str, comment: str) -> None:
    """Store the encoded envelope in a visible FFmpeg container comment."""
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    cmd = [ffmpeg, "-y", "-i", input_path, "-c", "copy", "-metadata", f"comment={comment}", output_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError("ffmpeg failed to write metadata")


def _ffmpeg_extract_comment(path: str) -> str:
    """Read the visible comment containing an encoded envelope."""
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    cmd = [ffmpeg, "-i", path, "-f", "ffmetadata", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    meta = result.stdout.splitlines()
    for line in meta:
        key, separator, value = line.partition("=")
        if separator and key.casefold() == "comment":
            return value
    raise ValueError("No embedded data found in video metadata comment")


def embed_data_in_video(video_path: str, output_path: str, password: str | None = None,
                        message: str | None = None, in_file: str | None = None,
                        image_path: str | None = None, mp3_path: str | None = None,
                        compress: bool = False, comment: str | None = None,
                        expires: str | None = None) -> None:
    """Store a payload in visible video metadata for the selected container."""
    ext = Path(video_path).suffix.lower()
    if ext in MP4_CONTAINER_EXTS:
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
    if ext not in FFMPEG_VIDEO_EXTS:
        raise ValueError("Unsupported video format")
    if image_path or mp3_path:
        raise ValueError("Image/MP3 payloads are only supported for MP4/MOV containers")

    payload = read_payload(message, in_file)
    flags = FLAG_PAYLOAD_TEXT
    stego_data, _flags, _salt, _nonce = build_stego_payload(
        payload, flags, password, compress, comment, expires
    )
    ensure_metadata_capacity(stego_data)
    stego_b64 = base64.b64encode(stego_data).decode("ascii")
    _ffmpeg_embed_comment(video_path, output_path, stego_b64)
    logging.info("Embedded visible metadata in video: %s", output_path)


def extract_data_from_video(video_path: str, output_path: str, password: str | None = None) -> None:
    """Extract a payload from visible video metadata."""
    ext = Path(video_path).suffix.lower()
    if ext in MP4_CONTAINER_EXTS:
        extract_data_from_mp4(video_path, output_path, password=password)
        return
    if ext not in FFMPEG_VIDEO_EXTS:
        raise ValueError("Unsupported video format")

    stego_b64 = _ffmpeg_extract_comment(video_path)
    stego_data = decode_stego_base64(stego_b64)
    _flags, plaintext, _meta = parse_stego_payload(stego_data, password)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    logging.info("Extracted text/file from video: %s", output_path)
