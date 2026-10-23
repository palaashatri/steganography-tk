"""Tests for stego.image module."""

import pytest
from PIL import Image
from stego.image import (
    load_image,
    embed_stego_data_in_image,
    extract_stego_data_from_image,
)
from stego.core import build_stego_payload, parse_stego_payload


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
