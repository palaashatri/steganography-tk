from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import pytest

import app


def test_image_cli_refuses_to_overwrite_cover_image(tmp_path: Path) -> None:
    cover_path = tmp_path / "cover.png"
    original = b"cover image must survive"
    cover_path.write_bytes(original)

    with pytest.raises(ValueError, match="Image input and output paths must differ"):
        app.encode_image(
            argparse.Namespace(
                image=str(cover_path),
                out=str(cover_path),
                message="secret",
                in_file=None,
                password=None,
                compress=False,
                comment=None,
                expires=None,
                method="lsb",
                prng_key=None,
            )
        )

    assert cover_path.read_bytes() == original


@pytest.mark.parametrize(
    "arguments",
    [
        ["encode", "--image", "unused.png", "--out", "out.jpg", "--message", "hi"],
        ["decode", "--image", "missing.png", "--out", "decoded.bin"],
    ],
)
def test_cli_reports_expected_input_errors_without_tracebacks(arguments: list[str]):
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = subprocess.run(
        [sys.executable, str(app_path), *arguments],
        cwd=app_path.parent,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "error:" in result.stderr.lower()
    assert "Traceback" not in result.stderr


def test_cli_keeps_unexpected_exceptions_visible(monkeypatch: pytest.MonkeyPatch):
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", default="INFO")

    def unexpected_error(_args: argparse.Namespace) -> None:
        raise RuntimeError("unexpected programming error")

    parser.set_defaults(func=unexpected_error)
    monkeypatch.setattr(app, "build_parser", lambda: parser)

    with pytest.raises(RuntimeError, match="unexpected programming error"):
        app.main([])
