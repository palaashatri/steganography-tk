"""Generated-fixture coverage for visible video-comment embedding."""

from __future__ import annotations

import os
import subprocess

import pytest
from PIL import Image

from stego.video import _ffmpeg_embed_comment, embed_data_in_video, extract_data_from_video


VIDEO_FORMATS = (
    ".mp4", ".m4a", ".m4b", ".m4p", ".m4v", ".mov",
    ".mkv", ".avi", ".webm",
)
VIDEO_COMMENT_FORMATS = (".mkv", ".avi", ".webm")
PASSWORD = "video-metadata-password"
PAYLOAD = b"\x00video payload\x7f\xff"
MAX_METADATA_STEGO_BYTES = 1_000_000


def _make_video(path, extension: str) -> None:
    if extension in {".m4a", ".m4b", ".m4p"}:
        output_format = "ipod" if extension in {".m4b", ".m4p"} else None
        format_args = ["-f", output_format] if output_format else []
        subprocess.run(
            [
                "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                "-f", "lavfi", "-i", "sine=frequency=880:sample_rate=44100:duration=0.25",
                "-vn", "-c:a", "aac", *format_args, str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    if extension in {".mp4", ".m4v", ".mov"}:
        codec = "mpeg4"
        output_format = {".m4v": "mp4", ".mov": "mov"}.get(extension)
        format_args = ["-f", output_format] if output_format else []
        subprocess.run(
            [
                "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                "-f", "lavfi", "-i", "testsrc=size=64x64:rate=2:duration=1",
                "-an", "-c:v", codec, *format_args, str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    codec = {".mkv": "ffv1", ".avi": "mpeg4", ".webm": "libvpx-vp9"}[extension]
    subprocess.run(
        [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", "testsrc=size=64x64:rate=2:duration=1",
            "-an", "-c:v", codec, str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(params=VIDEO_FORMATS, ids=lambda ext: ext.lstrip("."))
def video_source(request, tmp_path_factory):
    extension = request.param
    directory = tmp_path_factory.mktemp(f"video-{extension[1:]}")
    path = directory / f"source{extension}"
    _make_video(path, extension)
    return path


@pytest.fixture(params=VIDEO_COMMENT_FORMATS, ids=lambda ext: ext.lstrip("."))
def video_comment_source(request, tmp_path_factory):
    extension = request.param
    directory = tmp_path_factory.mktemp(f"comment-video-{extension[1:]}")
    path = directory / f"source{extension}"
    _make_video(path, extension)
    return path


@pytest.fixture
def mp4_source(tmp_path_factory):
    path = tmp_path_factory.mktemp("video-mp4") / "source.mp4"
    subprocess.run(
        [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", "testsrc=size=64x64:rate=2:duration=1",
            "-an", "-c:v", "mpeg4", str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return path


@pytest.fixture
def payload_file(temp_dir):
    path = temp_dir / "payload.bin"
    path.write_bytes(PAYLOAD)
    return path


def test_video_metadata_round_trip_preserves_binary_bytes(video_source, payload_file, temp_dir):
    extension = video_source.suffix
    output = temp_dir / f"stego{extension}"
    extracted = temp_dir / "extracted.bin"

    embed_data_in_video(
        str(video_source), str(output), password=PASSWORD, in_file=str(payload_file)
    )
    extract_data_from_video(str(output), str(extracted), password=PASSWORD)

    assert extracted.read_bytes() == PAYLOAD


def test_video_metadata_rejects_wrong_password(video_source, payload_file, temp_dir):
    extension = video_source.suffix
    output = temp_dir / f"stego{extension}"
    extracted = temp_dir / "must-not-exist.bin"
    embed_data_in_video(
        str(video_source), str(output), password=PASSWORD, in_file=str(payload_file)
    )

    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_video(str(output), str(extracted), password="incorrect")
    assert not extracted.exists()


def test_video_metadata_overflow_fails_before_ffmpeg_output(video_source, temp_dir):
    extension = video_source.suffix
    oversized = temp_dir / "oversized.bin"
    oversized.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / f"must-not-exist{extension}"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_video(str(video_source), str(output), in_file=str(oversized))
    assert not output.exists()


def test_video_comment_extraction_rejects_invalid_base64(video_comment_source, temp_dir):
    extension = video_comment_source.suffix
    malformed = temp_dir / f"invalid{extension}"
    _ffmpeg_embed_comment(
        str(video_comment_source), str(malformed), "%%% invalid base64 %%%"
    )

    with pytest.raises(ValueError, match="base64|encoded|payload|stego"):
        extract_data_from_video(str(malformed), str(temp_dir / "out.bin"), password=PASSWORD)


@pytest.mark.parametrize("preexisting", (False, True), ids=("new", "existing"))
def test_video_backend_mismatch_preserves_output(
    temp_dir, preexisting
):
    source = temp_dir / "source.avi"
    _make_video(source, ".avi")
    output = temp_dir / "wrong-backend.mp4"
    original = b"existing destination must survive"
    if preexisting:
        output.write_bytes(original)

    with pytest.raises(ValueError, match="backend|extension|carrier"):
        embed_data_in_video(str(source), str(output), message="payload")

    if preexisting:
        assert output.read_bytes() == original
    else:
        assert not output.exists()


def test_mp4_video_image_attachment_preserves_original_bytes_and_checks_password(
    mp4_source, temp_dir
):
    image_path = temp_dir / "attached.png"
    Image.new("RGB", (4, 3), (43, 101, 207)).save(image_path)
    output = temp_dir / "stego.mp4"
    restored = temp_dir / "restored.png"

    embed_data_in_video(
        str(mp4_source), str(output), password=PASSWORD, image_path=str(image_path)
    )
    extract_data_from_video(str(output), str(restored), password=PASSWORD)

    assert restored.read_bytes() == image_path.read_bytes()
    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_video(
            str(output), str(temp_dir / "wrong.png"), password="incorrect"
        )


def test_mp4_video_image_attachment_overflow_does_not_create_output(mp4_source, temp_dir):
    image_path = temp_dir / "large.png"
    Image.frombytes("RGB", (600, 600), os.urandom(600 * 600 * 3)).save(image_path)
    output = temp_dir / "must-not-exist.mp4"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_video(
            str(mp4_source), str(output), image_path=str(image_path)
        )
    assert not output.exists()
