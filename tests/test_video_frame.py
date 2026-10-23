"""Tests for lossless video-frame embedding."""

from argparse import Namespace
import builtins
from pathlib import Path
import subprocess

import imageio.v2 as imageio
import imageio_ffmpeg
import numpy as np
import pytest
from PIL import Image

import app
from stego.image import (
    embed_data_in_video_frame,
    extract_data_from_video_frame,
    extract_image_header,
)
from stego.core import FLAG_LSB_MATCH, FLAG_PRNG, STREAMING_PRNG_VERSION


def make_ffv1_video(path, *, width=32, height=32, frame_count=3):
    """Create a deterministic lossless RGB video fixture with FFV1."""
    writer = imageio.get_writer(
        str(path), fps=2, codec="ffv1", pixelformat="bgr0", format="FFMPEG"
    )
    try:
        for index in range(frame_count):
            frame = np.empty((height, width, 3), dtype=np.uint8)
            frame[:, :, 0] = 20 + index
            frame[:, :, 1] = 80 + index
            frame[:, :, 2] = 160 + index
            writer.append_data(frame)
    finally:
        writer.close()


def make_ffv1_video_with_audio(path):
    """Create a generated FFV1 Matroska fixture with PCM audio."""
    subprocess.run(
        [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=32x32:rate=2:duration=1.5",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100:duration=1.5",
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-c:v",
            "ffv1",
            "-pix_fmt",
            "bgr0",
            "-c:a",
            "pcm_s16le",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def extract_pcm_audio(path):
    """Decode the first audio stream to raw PCM, failing if it is absent."""
    result = subprocess.run(
        [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(path),
            "-map",
            "0:a:0",
            "-vn",
            "-c:a",
            "pcm_s16le",
            "-f",
            "s16le",
            "-",
        ],
        check=True,
        capture_output=True,
    )
    return result.stdout


def test_ffv1_frame_round_trip_and_wrong_password(temp_dir):
    source = temp_dir / "source.mkv"
    output = temp_dir / "stego.mkv"
    payload_path = temp_dir / "binary payload.bin"
    payload = bytes(range(256)) + b"\x00\xff\x10"
    payload_path.write_bytes(payload)
    make_ffv1_video(source)

    embed_data_in_video_frame(
        str(source),
        str(output),
        1,
        in_file=str(payload_path),
        password="correct",
    )

    assert extract_data_from_video_frame(str(output), 1, password="correct") == payload
    with pytest.raises(
        ValueError,
        match="Password is incorrect or the embedded payload was modified",
    ):
        extract_data_from_video_frame(str(output), 1, password="wrong")


@pytest.mark.parametrize(
    ("method", "flags"),
    [
        ("lsb-prng", FLAG_PRNG),
        ("lsb-match-prng", FLAG_PRNG | FLAG_LSB_MATCH),
    ],
)
def test_video_frame_prng_v3_round_trip_and_wrong_password(temp_dir, method, flags):
    source = temp_dir / "prng-source.mkv"
    output = temp_dir / "prng-stego.mkv"
    payload = b"version three frame payload\x00\xff"
    payload_path = temp_dir / "frame payload.bin"
    payload_path.write_bytes(payload)
    key = "frame-stream-key"
    make_ffv1_video(source)

    embed_data_in_video_frame(
        str(source),
        str(output),
        1,
        in_file=str(payload_path),
        password="correct",
        method=method,
        prng_key=key,
    )

    reader = imageio.get_reader(str(output))
    try:
        frame = Image.fromarray(reader.get_data(1)).convert("RGB")
    finally:
        reader.close()
    header = extract_image_header(frame, method, key)
    assert header.version == STREAMING_PRNG_VERSION
    assert header.flags & (FLAG_PRNG | FLAG_LSB_MATCH) == flags
    assert (
        extract_data_from_video_frame(
            str(output), 1, password="correct", method=method, prng_key=key
        )
        == payload
    )
    with pytest.raises(ValueError, match="Password is incorrect"):
        extract_data_from_video_frame(
            str(output), 1, password="wrong", method=method, prng_key=key
        )


def test_frame_round_trip_preserves_source_audio(temp_dir):
    source = temp_dir / "source-with-audio.mkv"
    output = temp_dir / "stego-with-audio.mkv"
    make_ffv1_video_with_audio(source)
    source_audio = extract_pcm_audio(source)

    embed_data_in_video_frame(str(source), str(output), 1, message="frame payload")

    assert extract_pcm_audio(output) == source_audio
    assert extract_data_from_video_frame(str(output), 1) == b"frame payload"


@pytest.mark.parametrize("preexisting", (False, True), ids=("new", "existing"))
def test_audio_remux_failure_preserves_destination_and_cleans_temps(
    temp_dir, monkeypatch, preexisting
):
    source = temp_dir / "source-with-audio.mkv"
    output = temp_dir / "stego-with-audio.mkv"
    make_ffv1_video_with_audio(source)
    original = b"existing destination contents"
    if preexisting:
        output.write_bytes(original)
    existing_files = {path.name for path in temp_dir.iterdir()}

    def fail_remux(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="injected timestamp or codec remux failure",
        )

    monkeypatch.setattr(subprocess, "run", fail_remux)

    with pytest.raises(ValueError, match="remux|audio|FFmpeg"):
        embed_data_in_video_frame(str(source), str(output), 1, message="payload")

    if preexisting:
        assert output.read_bytes() == original
    else:
        assert not output.exists()
    assert {path.name for path in temp_dir.iterdir()} == existing_files


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
def test_frame_capacity_overflow_does_not_create_output(temp_dir, method):
    source = temp_dir / "small.mkv"
    output = temp_dir / "too-large.mkv"
    payload_path = temp_dir / "large.bin"
    payload_path.write_bytes(b"x" * 100)
    make_ffv1_video(source, width=16, height=16, frame_count=1)

    with pytest.raises(ValueError, match="too large"):
        embed_data_in_video_frame(
            str(source),
            str(output),
            0,
            in_file=str(payload_path),
            password="pw",
            method=method,
            prng_key="capacity-key" if method != "lsb" else None,
        )
    assert not output.exists()


def test_cli_rejects_non_mkv_frame_output_before_opening_input(temp_dir):
    args = Namespace(
        video=str(temp_dir / "missing.mkv"),
        out=str(temp_dir / "stego.mp4"),
        frame=0,
        message="payload",
        in_file=None,
        password=None,
        method="lsb",
        prng_key=None,
        compress=False,
        comment=None,
        expires=None,
    )

    with pytest.raises(ValueError, match="MKV"):
        app.encode_video_frame(args)


def test_video_frame_decode_refuses_to_overwrite_its_carrier(temp_dir):
    carrier = temp_dir / "carrier.mkv"
    original = b"preserve video frame carrier bytes"
    carrier.write_bytes(original)
    args = Namespace(
        video=str(carrier),
        out=str(carrier),
        frame=0,
        password=None,
        method="lsb",
        prng_key=None,
    )

    with pytest.raises(ValueError, match="Video input and output paths must differ"):
        app.decode_video_frame(args)

    assert carrier.read_bytes() == original


def test_frame_embedding_rejects_overwriting_input_video(temp_dir):
    source = temp_dir / "source.mkv"
    make_ffv1_video(source, frame_count=1)

    with pytest.raises(ValueError, match="paths must differ"):
        embed_data_in_video_frame(str(source), str(source), 0, message="payload")


def test_writer_failure_preserves_destination_and_cleans_temporary_output(
    temp_dir, monkeypatch
):
    source = temp_dir / "source.mkv"
    output = temp_dir / "stego.mkv"
    previous_output = b"existing destination contents"
    output.write_bytes(previous_output)
    make_ffv1_video(source, frame_count=1)
    existing_files = {path.name for path in temp_dir.iterdir()}
    writer_paths = []

    class FailingWriter:
        def __init__(self, path):
            self.path = path
            Path(path).write_bytes(b"partial FFmpeg output")

        def append_data(self, frame):
            raise RuntimeError("injected append failure")

        def close(self):
            pass

    def get_failing_writer(path, **kwargs):
        writer_paths.append(Path(path))
        return FailingWriter(path)

    monkeypatch.setattr(imageio, "get_writer", get_failing_writer)

    with pytest.raises(RuntimeError, match="injected append failure"):
        embed_data_in_video_frame(str(source), str(output), 0, message="payload")

    assert output.read_bytes() == previous_output
    assert writer_paths and writer_paths[0] != output
    assert {path.name for path in temp_dir.iterdir()} == existing_files


def test_frame_embedding_rejects_uncompressed_payload_before_reading_it(
    temp_dir, monkeypatch
):
    source = temp_dir / "source.mkv"
    source.write_bytes(b"fake video carrier")
    output = temp_dir / "stego.mkv"
    payload_path = temp_dir / "oversized-payload.bin"
    payload_path.write_bytes(b"x" * (16 * 16 * 3 // 8 - 12 + 1))
    open_attempts = []
    original_builtin_open = builtins.open
    original_path_open = Path.open

    class FakeReader:
        def get_meta_data(self):
            return {"fps": 24}

        def get_data(self, frame_index):
            assert frame_index == 0
            return np.zeros((16, 16, 3), dtype=np.uint8)

        def close(self):
            pass

    def tracks_payload(path):
        try:
            return Path(path).resolve() == payload_path.resolve()
        except (TypeError, ValueError, OSError):
            return False

    def tracked_builtin_open(path, *args, **kwargs):
        if tracks_payload(path):
            open_attempts.append("builtins.open")
        return original_builtin_open(path, *args, **kwargs)

    def tracked_path_open(path, *args, **kwargs):
        if tracks_payload(path):
            open_attempts.append("Path.open")
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(imageio, "get_reader", lambda _path: FakeReader())
    monkeypatch.setattr(builtins, "open", tracked_builtin_open)
    monkeypatch.setattr(Path, "open", tracked_path_open)

    with pytest.raises(ValueError):
        embed_data_in_video_frame(
            str(source), str(output), 0, in_file=str(payload_path)
        )

    assert open_attempts == []
    assert not output.exists()


def test_frame_embedding_refuses_to_overwrite_payload_source(temp_dir):
    payload = temp_dir / "payload.mkv"
    original = b"payload bytes must survive"
    payload.write_bytes(original)

    with pytest.raises(ValueError, match="Payload input and output paths must differ"):
        embed_data_in_video_frame(
            str(temp_dir / "unused-source.mkv"),
            str(payload),
            0,
            in_file=str(payload),
        )

    assert payload.read_bytes() == original
