"""Tests for stego.core module."""

import pytest
from stego.core import (
    StegoHeader,
    build_stego_payload,
    parse_stego_payload,
    embed_bits,
    extract_bits,
    make_rng,
)


class TestStegoHeader:
    """Test StegoHeader dataclass."""

    def test_header_creation(self):
        """Test creating a StegoHeader."""
        header = StegoHeader(
            flags=0,
            salt=b'12345678',
            nonce=b'123456789012',
            payload_len=100
        )
        assert header.flags == 0
        assert header.payload_len == 100
        assert len(header.salt) == 8
        assert len(header.nonce) == 12


class TestPayloadOperations:
    """Test payload building and parsing."""

    def test_build_and_parse_payload_no_encryption(self, sample_text):
        """Test building and parsing unencrypted payload."""
        payload = sample_text.encode('utf-8')
        stego_data, size, salt, nonce = build_stego_payload(
            payload, flags=0, password=None, compress=False, comment=None, expires=None
        )

        assert len(stego_data) > 0
        header, plaintext, metadata = parse_stego_payload(stego_data, password=None)
        assert plaintext == payload

    def test_build_and_parse_payload_with_encryption(self, sample_text, password):
        """Test building and parsing encrypted payload."""
        payload = sample_text.encode('utf-8')
        stego_data, size, salt, nonce = build_stego_payload(
            payload, flags=0, password=password, compress=False, comment=None, expires=None
        )

        header, plaintext, metadata = parse_stego_payload(stego_data, password=password)
        assert plaintext == payload

    def test_build_and_parse_payload_with_compression(self, sample_text):
        """Test building and parsing compressed payload."""
        payload = sample_text.encode('utf-8')
        stego_data, size, salt, nonce = build_stego_payload(
            payload, flags=0, password=None, compress=True, comment=None, expires=None
        )

        header, plaintext, metadata = parse_stego_payload(stego_data, password=None)
        assert plaintext == payload

    def test_wrong_password_fails(self, sample_text, password):
        """Test that wrong password fails decryption."""
        payload = sample_text.encode('utf-8')
        stego_data, _, _, _ = build_stego_payload(
            payload, flags=0, password=password, compress=False, comment=None, expires=None
        )

        with pytest.raises(Exception):
            parse_stego_payload(stego_data, password="wrong_password")


class TestBitOperations:
    """Test bit embedding and extraction."""

    def test_embed_and_extract_bits(self):
        """Test embedding and extracting bits."""
        from PIL import Image
        import numpy as np

        # Create a small test image
        img_array = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
        img = Image.fromarray(img_array, 'RGB')

        # Embed some bits
        test_bits = [0, 1, 1, 0, 1, 0, 1, 1] * 10
        result_img = embed_bits(img, test_bits)

        # This is a basic smoke test
        assert result_img is not None
        assert result_img.size == img.size

    def test_prng_deterministic(self):
        """Test that PRNG is deterministic with same key."""
        key = "test_key"
        rng1 = make_rng(key)
        rng2 = make_rng(key)

        # Generate same sequence using random() method
        seq1 = [rng1.random() for _ in range(100)]
        seq2 = [rng2.random() for _ in range(100)]

        assert seq1 == seq2
