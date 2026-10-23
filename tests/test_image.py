"""Tests for stego.image module."""

import pytest
from PIL import Image
from cryptography.exceptions import InvalidTag
from stego.image import (
    embed_stego_data_in_image,
    extract_stego_data_from_image,
    image_capacity_bytes,
    load_image,
)
from stego.core import build_stego_payload, parse_stego_payload


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
@pytest.mark.parametrize("password", [None, "capacity-password"])
def test_each_image_method_accepts_exact_envelope_capacity(method, password):
    image = Image.new("RGB", (16, 16), (100, 120, 140))
    capacity = image_capacity_bytes(image)
    header_size = 40 if password else 12
    tag_size = 16 if password else 0
    payload = b"x" * (capacity - header_size - tag_size)
    stego_data, _, _, _ = build_stego_payload(
        payload, flags=0, password=password, compress=False,
        comment=None, expires=None,
    )
    key = "capacity-test-key" if method != "lsb" else None

    assert len(stego_data) == capacity
    stego_image = embed_stego_data_in_image(image, stego_data, method, key)
    assert extract_stego_data_from_image(stego_image, method, key) == stego_data


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
@pytest.mark.parametrize("password", [None, "capacity-password"])
def test_each_image_method_rejects_one_byte_over_capacity(method, password):
    image = Image.new("RGB", (16, 16), (100, 120, 140))
    capacity = image_capacity_bytes(image)
    header_size = 40 if password else 12
    tag_size = 16 if password else 0
    payload = b"x" * (capacity - header_size - tag_size + 1)
    stego_data, _, _, _ = build_stego_payload(
        payload, flags=0, password=password, compress=False,
        comment=None, expires=None,
    )
    key = "capacity-test-key" if method != "lsb" else None

    assert len(stego_data) == capacity + 1
    with pytest.raises(ValueError, match="too large"):
        embed_stego_data_in_image(image, stego_data, method, key)


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
def test_each_image_method_round_trips_encrypted_payload_and_rejects_wrong_password(
    method,
):
    image = Image.new("RGB", (32, 32), (100, 120, 140))
    payload = b"binary\x00payload\xff"
    stego_data, _, _, _ = build_stego_payload(
        payload, flags=0, password="correct", compress=False,
        comment=None, expires=None,
    )
    key = "round-trip-key" if method != "lsb" else None
    stego_image = embed_stego_data_in_image(image, stego_data, method, key)
    extracted = extract_stego_data_from_image(stego_image, method, key)

    assert parse_stego_payload(extracted, password="correct")[1] == payload
    with pytest.raises(InvalidTag):
        parse_stego_payload(extracted, password="wrong")


@pytest.mark.parametrize("suffix", ["jpg", "jpeg"])
def test_cli_rejects_lossy_image_output(sample_image, temp_dir, suffix):
    from argparse import Namespace

    import app

    output_path = temp_dir / f"stego.{suffix}"
    args = Namespace(
        image=str(sample_image), out=str(output_path), message="payload",
        in_file=None, password=None, compress=False, comment=None, expires=None,
        method="lsb", prng_key=None,
    )

    with pytest.raises(ValueError, match="PNG"):
        app.encode_image(args)
    assert not output_path.exists()


@pytest.mark.parametrize("command", ["gif-encode", "gif-decode"])
def test_gif_commands_are_not_registered(command):
    from app import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args([command])


def test_gui_has_no_gif_frame_entry_point():
    from pathlib import Path

    gui_source = Path(__file__).resolve().parents[1] / "gui" / "main.py"
    source = gui_source.read_text(encoding="utf-8")

    assert "_build_gif_tab" not in source
    assert "_encode_gif" not in source
    assert "_decode_gif" not in source
    assert "gif-encode" not in source
    assert "gif-decode" not in source


def test_gif_frame_api_is_not_exported():
    import stego

    assert not hasattr(stego, "embed_data_in_gif")
    assert not hasattr(stego, "extract_data_from_gif")


class TestImageOperations:
    """Test image steganography operations."""

    def test_load_image(self, sample_image):
        """Test loading an image."""
        img = load_image(str(sample_image))
        assert img is not None
        assert img.mode == 'RGB'

    def test_embed_and_extract_lsb(self, sample_image, sample_text, temp_dir):
        """Test LSB embedding and extraction."""
        # Prepare payload
        payload = sample_text.encode('utf-8')
        stego_data, _, _, _ = build_stego_payload(payload, flags=0, password=None, compress=False, comment=None, expires=None)

        # Load image and embed
        img = load_image(str(sample_image))
        stego_img = embed_stego_data_in_image(img, stego_data, method='lsb', prng_key=None)

        # Save and reload
        output_path = temp_dir / "stego_output.png"
        stego_img.save(output_path)
        stego_img = load_image(str(output_path))

        # Extract and verify
        extracted_data = extract_stego_data_from_image(stego_img, method='lsb', prng_key=None)
        header, plaintext, metadata = parse_stego_payload(extracted_data, password=None)

        assert plaintext == payload

    def test_embed_and_extract_with_password(self, sample_image, sample_text, password, temp_dir):
        """Test embedding and extraction with password."""
        payload = sample_text.encode('utf-8')
        stego_data, _, _, _ = build_stego_payload(payload, flags=0, password=password, compress=False, comment=None, expires=None)

        img = load_image(str(sample_image))
        stego_img = embed_stego_data_in_image(img, stego_data, method='lsb', prng_key=None)

        output_path = temp_dir / "stego_encrypted.png"
        stego_img.save(output_path)
        stego_img = load_image(str(output_path))

        extracted_data = extract_stego_data_from_image(stego_img, method='lsb', prng_key=None)
        header, plaintext, metadata = parse_stego_payload(extracted_data, password=password)

        assert plaintext == payload

    def test_capacity_check(self, sample_image, temp_dir):
        """Test that too much data raises an error."""
        # Create data larger than image capacity
        img = load_image(str(sample_image))
        total_pixels = img.width * img.height
        # Each pixel can store 3 bits (RGB), need 8 bits per byte
        max_bytes = (total_pixels * 3) // 8

        large_data = b'X' * (max_bytes + 1000)  # Larger than capacity
        stego_data, _, _, _ = build_stego_payload(large_data, flags=0, password=None, compress=False, comment=None, expires=None)

        with pytest.raises(ValueError, match="too large"):
            embed_stego_data_in_image(img, stego_data, method='lsb', prng_key=None)
