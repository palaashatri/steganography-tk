"""Tests for CLI functionality."""

import builtins
import subprocess
import sys
from pathlib import Path
import pytest
from PIL import Image
from PyPDF2 import PdfWriter


MAX_METADATA_STEGO_BYTES = 1_000_000


def _track_payload_reads(monkeypatch, payload_path):
    """Record reads from one path, including reads made through Path.open."""
    payload_path = payload_path.resolve()
    read_sizes = []

    class ReadTrackingFile:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __enter__(self):
            self._wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self._wrapped.__exit__(*args)

        def read(self, size=-1):
            read_sizes.append(size)
            return self._wrapped.read(size)

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    original_open = builtins.open
    original_path_open = Path.open

    def tracked_open(file, *args, **kwargs):
        wrapped = original_open(file, *args, **kwargs)
        try:
            matches = Path(file).resolve() == payload_path
        except (TypeError, ValueError, OSError):
            matches = False
        return ReadTrackingFile(wrapped) if matches else wrapped

    def tracked_path_open(path, *args, **kwargs):
        wrapped = original_path_open(path, *args, **kwargs)
        return ReadTrackingFile(wrapped) if path.resolve() == payload_path else wrapped

    monkeypatch.setattr(builtins, "open", tracked_open)
    monkeypatch.setattr(Path, "open", tracked_path_open)
    return read_sizes


def test_image_cli_rejects_uncompressed_input_before_reading_it(
    sample_image, temp_dir, monkeypatch
):
    from argparse import Namespace

    import app

    payload_path = temp_dir / "oversized-payload.bin"
    with Image.open(sample_image) as image:
        capacity = image.width * image.height * 3 // 8
    payload_path.write_bytes(b"x" * (capacity - 12 + 1))
    read_sizes = _track_payload_reads(monkeypatch, payload_path)
    output_path = temp_dir / "must-not-exist.png"

    args = Namespace(
        image=str(sample_image),
        out=str(output_path),
        message=None,
        in_file=str(payload_path),
        password=None,
        compress=False,
        comment=None,
        expires=None,
        method="lsb",
        prng_key=None,
    )

    with pytest.raises(ValueError):
        app.encode_image(args)

    assert read_sizes == []
    assert not output_path.exists()


def test_image_cli_refuses_to_overwrite_payload_source(temp_dir):
    from argparse import Namespace

    import app

    payload_path = temp_dir / "payload.png"
    original = b"payload bytes must survive"
    payload_path.write_bytes(original)

    with pytest.raises(ValueError, match="Payload input and output paths must differ"):
        app.encode_image(
            Namespace(
                image=str(temp_dir / "unused-cover.png"),
                out=str(payload_path),
                message=None,
                in_file=str(payload_path),
                password=None,
                compress=False,
                comment=None,
                expires=None,
                method="lsb",
                prng_key=None,
            )
        )

    assert payload_path.read_bytes() == original


def test_image_cli_pre_read_limit_accounts_for_encryption_and_metadata(
    temp_dir,
):
    from argparse import Namespace

    import app
    from stego.core import estimate_stego_payload_size, parse_stego_payload
    from stego.image import extract_stego_data_from_image

    image_path = temp_dir / "cover.png"
    output_path = temp_dir / "stego.png"
    payload_path = temp_dir / "payload.bin"
    Image.new("RGB", (64, 64), (80, 120, 160)).save(image_path)
    capacity = 64 * 64 * 3 // 8
    password = "bounded-capacity-password"
    comment = "visible note"
    expires = "2099-12-31T23:59:59"
    metadata = {"comment": comment, "expires": expires}
    max_plaintext = capacity - estimate_stego_payload_size(
        b"", encrypted=True, compress=False, metadata=metadata
    )
    payload = b"x" * max_plaintext
    payload_path.write_bytes(payload)

    app.encode_image(
        Namespace(
            image=str(image_path),
            out=str(output_path),
            message=None,
            in_file=str(payload_path),
            password=password,
            compress=False,
            comment=comment,
            expires=expires,
            method="lsb",
            prng_key=None,
        )
    )

    with Image.open(output_path) as encoded_image:
        envelope = extract_stego_data_from_image(encoded_image, "lsb", None)
    assert len(envelope) == capacity
    assert parse_stego_payload(envelope, password)[1] == payload


def test_image_cli_compression_keeps_compressible_payloads_above_capacity(
    temp_dir,
):
    from argparse import Namespace

    import app
    from stego.core import parse_stego_payload
    from stego.image import extract_stego_data_from_image

    image_path = temp_dir / "cover.png"
    output_path = temp_dir / "stego.png"
    payload_path = temp_dir / "payload.bin"
    payload = b"compressible payload " * 400
    payload_path.write_bytes(payload)
    Image.new("RGB", (32, 32), (80, 120, 160)).save(image_path)

    app.encode_image(
        Namespace(
            image=str(image_path),
            out=str(output_path),
            message=None,
            in_file=str(payload_path),
            password=None,
            compress=True,
            comment=None,
            expires=None,
            method="lsb",
            prng_key=None,
        )
    )

    with Image.open(output_path) as encoded_image:
        envelope = extract_stego_data_from_image(encoded_image, "lsb", None)
    assert parse_stego_payload(envelope, None)[1] == payload


class TestCLI:
    """Test command-line interface."""

    @pytest.fixture
    def cli_runner(self):
        """Get path to app.py."""
        return [sys.executable, "app.py"]

    def test_help_command(self, cli_runner):
        """Test --help flag."""
        result = subprocess.run(cli_runner + ["--help"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "LSB steganography" in result.stdout
        assert "encode" in result.stdout
        assert "decode" in result.stdout

    def test_encode_help(self, cli_runner):
        """Test encode --help."""
        result = subprocess.run(
            cli_runner + ["encode", "--help"], capture_output=True, text=True
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
            cli_runner
            + [
                "encode",
                "--image",
                str(sample_image),
                "--out",
                str(output_img),
                "--message",
                message,
            ],
            capture_output=True,
            text=True,
        )
        assert encode_result.returncode == 0
        assert output_img.exists()

        # Decode
        decode_result = subprocess.run(
            cli_runner + ["decode", "--image", str(output_img)],
            capture_output=True,
            text=True,
        )
        assert decode_result.returncode == 0
        assert message in decode_result.stdout

    def test_encode_decode_with_password(
        self, cli_runner, temp_dir, sample_image, password
    ):
        """Test encoding and decoding with password."""
        output_img = temp_dir / "stego_encrypted.png"
        message = "Encrypted message"

        # Encode with password
        subprocess.run(
            cli_runner
            + [
                "encode",
                "--image",
                str(sample_image),
                "--out",
                str(output_img),
                "--message",
                message,
                "--password",
                password,
            ],
            check=True,
        )

        # Decode with password
        result = subprocess.run(
            cli_runner + ["decode", "--image", str(output_img), "--password", password],
            capture_output=True,
            text=True,
            check=True,
        )
        assert message in result.stdout

    def test_encode_decode_file(self, cli_runner, temp_dir, sample_image, sample_file):
        """Test encoding and decoding a file."""
        output_img = temp_dir / "stego_file.png"
        output_file = temp_dir / "decoded.txt"

        # Encode file
        subprocess.run(
            cli_runner
            + [
                "encode",
                "--image",
                str(sample_image),
                "--out",
                str(output_img),
                "--in-file",
                str(sample_file),
            ],
            check=True,
        )

        # Decode to file
        subprocess.run(
            cli_runner
            + ["decode", "--image", str(output_img), "--out", str(output_file)],
            check=True,
        )

        # Verify content
        assert output_file.read_text() == sample_file.read_text()

    def test_qr_generation(self, cli_runner, temp_dir):
        """Test QR code generation."""
        output_qr = temp_dir / "test_qr.png"

        subprocess.run(
            cli_runner
            + ["qr", "--text", "https://example.com", "--out", str(output_qr)],
            check=True,
            capture_output=True,
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
        help_text = " ".join(result.stdout.lower().split())
        assert "visible metadata" in help_text
        assert "1,000,000" in help_text
        assert "contents are readable unless" in help_text
        assert "encryption was enabled with a password" in help_text

    def test_image_decode_refuses_to_overwrite_its_carrier(
        self, sample_image, tmp_path
    ):
        from argparse import Namespace

        import app

        original = sample_image.read_bytes()
        args = Namespace(
            image=str(sample_image),
            out=str(sample_image),
            method="lsb",
            prng_key=None,
            password=None,
        )

        with pytest.raises(
            ValueError, match="Image input and output paths must differ"
        ):
            app.decode_image(args)

        assert sample_image.read_bytes() == original

    def test_removed_gif_commands_are_not_registered(self, cli_runner):
        result = subprocess.run(
            cli_runner + ["gif-encode", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "invalid choice" in result.stderr.lower()

    def test_pdf_cli_overflow_returns_nonzero_without_output(
        self, cli_runner, temp_dir
    ):
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
        assert (
            "capacity" in result.stderr.lower() or "too large" in result.stderr.lower()
        )
        assert not output.exists()
