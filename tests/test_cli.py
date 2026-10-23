"""Tests for CLI functionality."""

import subprocess
import sys
import wave
from pathlib import Path

import pytest
from PIL import Image
import numpy as np
from PyPDF2 import PdfWriter


MAX_METADATA_STEGO_BYTES = 1_000_000


class TestCLI:
    """Test command-line interface."""

    @pytest.fixture
    def cli_runner(self):
        """Get path to app.py."""
        return [sys.executable, "app.py"]

    def test_help_command(self, cli_runner):
        """Test --help flag."""
        result = subprocess.run(
            cli_runner + ["--help"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "LSB steganography" in result.stdout
        assert "encode" in result.stdout
        assert "decode" in result.stdout

    def test_encode_help(self, cli_runner):
        """Test encode --help."""
        result = subprocess.run(
            cli_runner + ["encode", "--help"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "--image" in result.stdout
        assert "--out" in result.stdout
        assert "--password" in result.stdout

    def test_encode_decode_message(self, cli_runner, temp_dir, sample_image):
        """Test encoding and decoding a message."""
        output_img = temp_dir / "stego.png"
        message = "Secret CLI test message"

        # Encode
        encode_result = subprocess.run(
            cli_runner + [
                "encode",
                "--image", str(sample_image),
                "--out", str(output_img),
                "--message", message
            ],
            capture_output=True,
            text=True
        )
        assert encode_result.returncode == 0
        assert output_img.exists()

        # Decode
        decode_result = subprocess.run(
            cli_runner + [
                "decode",
                "--image", str(output_img)
            ],
            capture_output=True,
            text=True
        )
        assert decode_result.returncode == 0
        assert message in decode_result.stdout

    def test_encode_decode_with_password(self, cli_runner, temp_dir, sample_image, password):
        """Test encoding and decoding with password."""
        output_img = temp_dir / "stego_encrypted.png"
        message = "Encrypted message"

        # Encode with password
        subprocess.run(
            cli_runner + [
                "encode",
                "--image", str(sample_image),
                "--out", str(output_img),
                "--message", message,
                "--password", password
            ],
            check=True
        )

        # Decode with password
        result = subprocess.run(
            cli_runner + [
                "decode",
                "--image", str(output_img),
                "--password", password
            ],
            capture_output=True,
            text=True,
            check=True
        )
        assert message in result.stdout

    def test_encode_decode_file(self, cli_runner, temp_dir, sample_image, sample_file):
        """Test encoding and decoding a file."""
        output_img = temp_dir / "stego_file.png"
        output_file = temp_dir / "decoded.txt"

        # Encode file
        subprocess.run(
            cli_runner + [
                "encode",
                "--image", str(sample_image),
                "--out", str(output_img),
                "--in-file", str(sample_file)
            ],
            check=True
        )

        # Decode to file
        subprocess.run(
            cli_runner + [
                "decode",
                "--image", str(output_img),
                "--out", str(output_file)
            ],
            check=True
        )

        # Verify content
        assert output_file.read_text() == sample_file.read_text()

    def test_qr_generation(self, cli_runner, temp_dir):
        """Test QR code generation."""
        output_qr = temp_dir / "test_qr.png"

        result = subprocess.run(
            cli_runner + [
                "qr",
                "--text", "https://example.com",
                "--out", str(output_qr)
            ],
            check=True,
            capture_output=True
        )

        assert output_qr.exists()
        # Verify it's a valid image
        img = Image.open(output_qr)
        assert img is not None

    @pytest.mark.parametrize("command", ("audio-encode", "video-encode", "pdf-encode"))
    def test_metadata_encode_help_discloses_visible_storage_and_capacity(
        self, cli_runner, command
    ):
        result = subprocess.run(
            cli_runner + [command, "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "visible metadata" in result.stdout.lower()
        assert "1,000,000" in result.stdout

    def test_removed_gif_commands_are_not_registered(self, cli_runner):
        result = subprocess.run(
            cli_runner + ["gif-encode", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "invalid choice" in result.stderr.lower()

    def test_pdf_cli_overflow_returns_nonzero_without_output(self, cli_runner, temp_dir):
        source_pdf = temp_dir / "source.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        with source_pdf.open("wb") as handle:
            writer.write(handle)
        oversized = temp_dir / "oversized.bin"
        oversized.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
        output = temp_dir / "must-not-exist.pdf"

        result = subprocess.run(
            cli_runner
            + [
                "pdf-encode",
                "--pdf",
                str(source_pdf),
                "--out",
                str(output),
                "--in-file",
                str(oversized),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "capacity" in result.stderr.lower() or "too large" in result.stderr.lower()
        assert not output.exists()
