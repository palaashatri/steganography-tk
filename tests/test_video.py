"""Generated-fixture coverage for visible video-comment embedding."""

from __future__ import annotations

import builtins
import os
import subprocess
from pathlib import Path

import pytest
from PIL import Image

from stego.core import build_stego_payload
from stego.video import (
    _ffmpeg_embed_comment,
    embed_data_in_video,
    extract_data_from_video,
)


VIDEO_FORMATS = (
    ".mp4",
    ".m4a",
    ".m4b",
    ".m4p",
    ".m4v",
    ".mov",
    ".mkv",
    ".avi",
    ".webm",
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
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=880:sample_rate=44100:duration=0.25",
                "-vn",
                "-c:a",
                "aac",
                *format_args,
                str(path),
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
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=64x64:rate=2:duration=1",
                "-an",
                "-c:v",
                codec,
                *format_args,
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    codec = {".mkv": "ffv1", ".avi": "mpeg4", ".webm": "libvpx-vp9"}[extension]
    subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=64x64:rate=2:duration=1",
            "-an",
            "-c:v",
            codec,
            str(path),
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
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=64x64:rate=2:duration=1",
            "-an",
            "-c:v",
            "mpeg4",
            str(path),
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


def test_video_metadata_round_trip_preserves_binary_bytes(
    video_source, payload_file, temp_dir
):
    extension = video_source.suffix
    output = temp_dir / f"stego{extension}"
    extracted = temp_dir / "extracted.bin"

    embed_data_in_video(
        str(video_source), str(output), password=PASSWORD, in_file=str(payload_file)
    )
    extract_data_from_video(str(output), str(extracted), password=PASSWORD)

    assert extracted.read_bytes() == PAYLOAD


def test_compressed_video_metadata_accepts_bounded_payload_above_one_megabyte(
    video_comment_source, temp_dir
):
    payload = b"compressed visible video metadata " * 40_000
    payload_file = temp_dir / "compressible-payload.bin"
    output = temp_dir / f"compressed-stego{video_comment_source.suffix}"
    extracted = temp_dir / "compressed-extracted.bin"
    payload_file.write_bytes(payload)

    embed_data_in_video(
        str(video_comment_source),
        str(output),
        in_file=str(payload_file),
        compress=True,
    )
    extract_data_from_video(str(output), str(extracted))

    assert extracted.read_bytes() == payload


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


def test_video_comment_rejects_oversized_input_before_reading_it(temp_dir, monkeypatch):
    source = temp_dir / "source.mkv"
    source.write_bytes(b"fake video carrier")
    payload_path = temp_dir / "oversized-payload.bin"
    payload_path.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / "stego.mkv"
    original_open = builtins.open
    original_path_open = Path.open

    def reject_payload_open(path, *args, **kwargs):
        try:
            is_payload = Path(path).resolve() == payload_path.resolve()
        except (TypeError, ValueError, OSError):
            is_payload = False
        if is_payload:
            raise AssertionError("oversized payload was opened for reading")
        return original_open(path, *args, **kwargs)

    def reject_payload_path_open(path, *args, **kwargs):
        if path.resolve() == payload_path.resolve():
            raise AssertionError("oversized payload was opened for reading")
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", reject_payload_open)
    monkeypatch.setattr(Path, "open", reject_payload_path_open)

    with pytest.raises(ValueError, match="1,000,000"):
        embed_data_in_video(str(source), str(output), in_file=str(payload_path))

    assert not output.exists()


def test_video_comment_round_trips_one_megabyte_envelope(tmp_path):
    source = tmp_path / "source.mkv"
    payload_file = tmp_path / "payload.bin"
    output = tmp_path / "stego.mkv"
    extracted = tmp_path / "extracted.bin"
    payload = b"x" * (MAX_METADATA_STEGO_BYTES - 12)
    _make_video(source, ".mkv")
    payload_file.write_bytes(payload)

    expected_envelope, *_ = build_stego_payload(
        payload, flags=0, password=None, compress=False, comment=None, expires=None
    )
    assert len(expected_envelope) == MAX_METADATA_STEGO_BYTES

    embed_data_in_video(str(source), str(output), in_file=str(payload_file))
    extract_data_from_video(str(output), str(extracted))

    assert extracted.read_bytes() == payload


def test_video_comment_embedding_rejects_same_input_and_output_path(tmp_path):
    source = tmp_path / "source.mkv"
    source.write_bytes(b"keep the original carrier")
    original = source.read_bytes()

    with pytest.raises(ValueError, match="same|different"):
        embed_data_in_video(str(source), str(source), message="payload")

    assert source.read_bytes() == original


def test_ffmetadata_replaces_only_global_comment():
    from stego.video import _ffmetadata_with_comment

    metadata = (
        ";FFMETADATA1\n"
        "comment=original global comment\n"
        "[CHAPTER]\n"
        "TIMEBASE=1/1000\n"
        "comment=chapter comment\n"
    )

    merged = _ffmetadata_with_comment(metadata, "replacement")
    global_metadata, _, chapter_metadata = merged.partition("[CHAPTER]")

    assert "comment=replacement" in global_metadata
    assert "comment=original global comment" not in global_metadata
    assert "comment=chapter comment" in chapter_metadata


def test_ffmpeg_comment_extraction_uses_global_comment_before_chapter_comment(
    monkeypatch,
):
    from io import BytesIO

    from stego import video

    class FakeProcess:
        def __init__(self):
            self.stdout = BytesIO(
                b";FFMETADATA1\n"
                b"comment=aGVsbG8=\n"
                b"[CHAPTER]\n"
                b"TIMEBASE=1/1000\n"
                b"comment=Y2hhcHRlcg==\n"
            )
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self):
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(video.imageio_ffmpeg, "get_ffmpeg_exe", lambda: "ffmpeg")
    monkeypatch.setattr(video.subprocess, "Popen", lambda *_args, **_kwargs: process)

    assert video._ffmpeg_extract_comment("carrier.mkv") == "aGVsbG8="


def test_ffmpeg_metadata_export_stops_at_aggregate_output_limit(monkeypatch, tmp_path):
    from stego import video

    source = tmp_path / "source.mkv"
    source.write_bytes(b"source")

    class FakeStdout:
        def __init__(self):
            self.line = b"title=" + b"x" * 994 + b"\n"
            self.line_count = 0
            self.bytes_read = 0

        def readline(self, size=-1):
            if self.line_count == 0:
                result = b";FFMETADATA1\n"
            elif self.line_count < 5_000:
                result = self.line
            else:
                return b""
            self.line_count += 1
            if size >= 0:
                result = result[:size]
            self.bytes_read += len(result)
            return result

        def close(self):
            pass

    class FakeProcess:
        def __init__(self):
            self.stdout = FakeStdout()
            self.returncode = None
            self.was_killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.was_killed = True
            self.returncode = -9

        def wait(self):
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(video.imageio_ffmpeg, "get_ffmpeg_exe", lambda: "ffmpeg")
    monkeypatch.setattr(video.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        video.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("metadata export must be bounded"),
    )

    with pytest.raises(ValueError, match="metadata|output|limit|large"):
        video._ffmpeg_embed_comment(
            str(source), str(tmp_path / "stego.mkv"), "encoded payload"
        )

    assert process.was_killed
    assert process.stdout.bytes_read <= video.MAX_FFMETADATA_OUTPUT_BYTES + len(
        process.stdout.line
    )
    assert {path.name for path in tmp_path.iterdir()} == {"source.mkv"}


def test_ffmpeg_comment_failure_preserves_destination_and_cleans_temp_files(
    monkeypatch, tmp_path
):
    from io import BytesIO

    from stego import video

    source = tmp_path / "source.mkv"
    source.write_bytes(b"source")
    output = tmp_path / "existing.mkv"
    original = b"preserve me"
    output.write_bytes(original)

    def fail_output_command(command, **_kwargs):
        Path(command[-1]).write_bytes(b"partial output")
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="forced mux failure"
        )

    class MetadataProcess:
        def __init__(self):
            self.stdout = BytesIO(b";FFMETADATA1\ntitle=source title\n")
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self):
            self.returncode = 0
            return self.returncode

    monkeypatch.setattr(
        video.subprocess, "Popen", lambda *_args, **_kwargs: MetadataProcess()
    )
    monkeypatch.setattr(video.imageio_ffmpeg, "get_ffmpeg_exe", lambda: "ffmpeg")
    monkeypatch.setattr(video.subprocess, "run", fail_output_command)

    with pytest.raises(ValueError, match="ffmpeg|metadata|mux"):
        _ffmpeg_embed_comment(str(source), str(output), "encoded payload")

    assert output.read_bytes() == original
    assert {path.name for path in tmp_path.iterdir()} == {"source.mkv", "existing.mkv"}


def test_video_comment_embedding_preserves_other_carrier_metadata(tmp_path):
    source = tmp_path / "source.mkv"
    _make_video(source, ".mkv")
    tagged_source = tmp_path / "tagged.mkv"
    subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-i",
            str(source),
            "-map",
            "0",
            "-c",
            "copy",
            "-metadata",
            "title=source title",
            str(tagged_source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    output = tmp_path / "stego.mkv"

    embed_data_in_video(str(tagged_source), str(output), message="payload")

    metadata_result = subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(output),
            "-f",
            "ffmetadata",
            "-",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "title=source title" in metadata_result.stdout


def test_video_comment_extraction_rejects_invalid_base64(
    video_comment_source, temp_dir
):
    extension = video_comment_source.suffix
    malformed = temp_dir / f"invalid{extension}"
    _ffmpeg_embed_comment(
        str(video_comment_source), str(malformed), "%%% invalid base64 %%%"
    )

    with pytest.raises(ValueError, match="base64|encoded|payload|stego"):
        extract_data_from_video(
            str(malformed), str(temp_dir / "out.bin"), password=PASSWORD
        )


def test_ffmpeg_comment_extraction_stops_on_oversized_comment(monkeypatch):
    from stego import video

    class FakeStdout:
        def __init__(self):
            self.content = b";FFMETADATA1\ncomment=" + b"A" * 2_000_000 + b"\n"
            self.offset = 0
            self.bytes_read = 0

        def readline(self, size=-1):
            if size < 0:
                size = len(self.content) - self.offset
            chunk = self.content[self.offset : self.offset + size]
            self.offset += len(chunk)
            self.bytes_read += len(chunk)
            return chunk

        def close(self):
            pass

    class FakeProcess:
        def __init__(self):
            self.stdout = FakeStdout()
            self.returncode = None
            self.was_killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.was_killed = True
            self.returncode = -9

        def wait(self):
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(video.imageio_ffmpeg, "get_ffmpeg_exe", lambda: "ffmpeg")
    monkeypatch.setattr(
        video.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("metadata extraction must stream"),
    )
    monkeypatch.setattr(video.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(ValueError, match="metadata|comment|limit|large"):
        video._ffmpeg_extract_comment("carrier.mkv")

    assert process.was_killed
    assert process.stdout.bytes_read < 2_000_000


def test_ffmpeg_comment_extraction_caps_aggregate_metadata_output(monkeypatch):
    from stego import video

    class FakeStdout:
        def __init__(self):
            self.line = b"title=" + b"x" * 994 + b"\n"
            self.line_count = 0
            self.bytes_read = 0

        def readline(self, size=-1):
            if self.line_count == 0:
                result = b";FFMETADATA1\n"
            elif self.line_count < 5_000:
                result = self.line
            else:
                return b""
            self.line_count += 1
            if size >= 0:
                result = result[:size]
            self.bytes_read += len(result)
            return result

        def close(self):
            pass

    class FakeProcess:
        def __init__(self):
            self.stdout = FakeStdout()
            self.returncode = None
            self.was_killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.was_killed = True
            self.returncode = -9

        def wait(self):
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(video.imageio_ffmpeg, "get_ffmpeg_exe", lambda: "ffmpeg")
    monkeypatch.setattr(
        video.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("metadata extraction must stream"),
    )
    monkeypatch.setattr(video.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(ValueError, match="metadata|output|limit|large"):
        video._ffmpeg_extract_comment("carrier.mkv")

    assert process.was_killed
    assert process.stdout.bytes_read < 5_000_000


@pytest.mark.parametrize("preexisting", (False, True), ids=("new", "existing"))
def test_video_backend_mismatch_preserves_output(temp_dir, preexisting):
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


@pytest.mark.parametrize("preexisting", (False, True), ids=("new", "existing"))
def test_video_same_backend_suffix_change_preserves_output(temp_dir, preexisting):
    source = temp_dir / "source.mkv"
    subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=64x64:rate=2:duration=1",
            "-an",
            "-c:v",
            "libvpx-vp9",
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    output = temp_dir / "different-suffix.webm"
    original = b"existing destination must survive"
    if preexisting:
        output.write_bytes(original)

    with pytest.raises(ValueError, match="suffix|extension"):
        embed_data_in_video(str(source), str(output), message="payload")

    if preexisting:
        assert output.read_bytes() == original
    else:
        assert not output.exists()


def test_video_matching_suffix_is_case_insensitive(temp_dir):
    source = temp_dir / "source.mkv"
    _make_video(source, ".mkv")
    output = temp_dir / "carrier.MKV"

    embed_data_in_video(str(source), str(output), message="payload")

    assert output.exists()


def test_video_metadata_extraction_refuses_to_overwrite_its_carrier(temp_dir):
    carrier = temp_dir / "carrier.mkv"
    original = b"preserve video carrier bytes"
    carrier.write_bytes(original)

    with pytest.raises(ValueError, match="Video input and output paths must differ"):
        extract_data_from_video(str(carrier), str(carrier))

    assert carrier.read_bytes() == original


@pytest.mark.parametrize("suffix", (".mkv", ".mp4"))
def test_video_embed_refuses_to_overwrite_payload_source(temp_dir, suffix):
    carrier = temp_dir / f"source{suffix}"
    payload = temp_dir / f"payload{suffix}"
    original = b"payload bytes must survive"
    payload.write_bytes(original)

    with pytest.raises(ValueError, match="Payload input and output paths must differ"):
        embed_data_in_video(str(carrier), str(payload), in_file=str(payload))

    assert payload.read_bytes() == original


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


def test_mp4_video_image_attachment_overflow_does_not_create_output(
    mp4_source, temp_dir
):
    image_path = temp_dir / "large.png"
    Image.frombytes("RGB", (600, 600), os.urandom(600 * 600 * 3)).save(image_path)
    output = temp_dir / "must-not-exist.mp4"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_video(str(mp4_source), str(output), image_path=str(image_path))
    assert not output.exists()
