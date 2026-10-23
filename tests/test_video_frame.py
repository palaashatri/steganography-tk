"""Tests for lossless video-frame embedding."""

from argparse import Namespace
from pathlib import Path

import imageio.v2 as imageio
import numpy as np
import pytest
from cryptography.exceptions import InvalidTag

import app
from stego.image import (
    embed_data_in_video_frame,
    extract_data_from_video_frame,
)


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


def test_ffv1_frame_round_trip_and_wrong_password(temp_dir):
    source = temp_dir / "source.mkv"
    output = temp_dir / "stego.mkv"
    payload_path = temp_dir / "binary payload.bin"
    payload = bytes(range(256)) + b"\x00\xff\x10"
    payload_path.write_bytes(payload)
    make_ffv1_video(source)

    embed_data_in_video_frame(
        str(source), str(output), 1, in_file=str(payload_path), password="correct",
    )

    assert extract_data_from_video_frame(str(output), 1, password="correct") == payload
    with pytest.raises(InvalidTag):
        extract_data_from_video_frame(str(output), 1, password="wrong")


def test_frame_capacity_overflow_does_not_create_output(temp_dir):
    source = temp_dir / "small.mkv"
    output = temp_dir / "too-large.mkv"
    payload_path = temp_dir / "large.bin"
    payload_path.write_bytes(b"x" * 100)
    make_ffv1_video(source, width=16, height=16, frame_count=1)

    with pytest.raises(ValueError, match="too large"):
        embed_data_in_video_frame(
            str(source), str(output), 0, in_file=str(payload_path), password="pw",
        )
    assert not output.exists()


def test_cli_rejects_non_mkv_frame_output_before_opening_input(temp_dir):
    args = Namespace(
        video=str(temp_dir / "missing.mkv"), out=str(temp_dir / "stego.mp4"),
        frame=0, message="payload", in_file=None, password=None, method="lsb",
        prng_key=None, compress=False, comment=None, expires=None,
    )

    with pytest.raises(ValueError, match="MKV"):
        app.encode_video_frame(args)


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
