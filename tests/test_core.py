"""Tests for stego.core module."""

import pytest
from cryptography.exceptions import InvalidTag
from stego.core import (
    FLAG_COMPRESSED,
    FLAG_ENCRYPTED,
    VERSION,
    StegoHeader,
    build_aad,
    build_stego_payload,
    estimate_stego_payload_size,
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

    def test_new_headers_use_version_two_and_aad_is_full_serialized_header(self):
        stego_data, _, _, _ = build_stego_payload(
            b"authenticated", flags=0, password="pw", compress=False,
            comment=None, expires=None,
        )
        header = StegoHeader(
            flags=stego_data[5],
            salt=stego_data[12:28],
            nonce=stego_data[28:40],
            payload_len=int.from_bytes(stego_data[8:12], "big"),
            version=stego_data[4],
        )

        assert VERSION == 2
        assert header.version == 2
        assert build_aad(header) == stego_data[:40]

    @pytest.mark.parametrize(
        ("offset", "replacement", "structural_error"),
        [
            (0, b"X", True),  # magic
            (4, b"\x01", False),  # supported legacy version, but wrong AAD
            (5, bytes([FLAG_ENCRYPTED | FLAG_COMPRESSED]), False),  # flags
            (6, b"\x0f", False),  # salt length
            (7, b"\x0b", False),  # nonce length
            (8, None, False),  # payload length is decremented below
            (12, b"X", False),  # salt
            (28, b"X", False),  # nonce
        ],
    )
    def test_v2_encrypted_header_tampering_is_rejected(
        self, offset, replacement, structural_error
    ):
        stego_data, _, _, _ = build_stego_payload(
            b"tamper detection payload", flags=0, password="pw", compress=False,
            comment=None, expires=None,
        )
        mutated = bytearray(stego_data)
        if offset == 8:
            length = int.from_bytes(mutated[8:12], "big")
            mutated[8:12] = (length - 1).to_bytes(4, "big")
        else:
            mutated[offset:offset + 1] = replacement

        if structural_error:
            with pytest.raises(ValueError):
                parse_stego_payload(bytes(mutated), password="pw")
        else:
            with pytest.raises((InvalidTag, ValueError)):
                parse_stego_payload(bytes(mutated), password="pw")

    def test_legacy_v1_encrypted_payload_decodes_with_legacy_aad(self):
        password = "legacy-password"
        legacy_fixture = bytes.fromhex(
            "535447310101100c00000023000102030405060708090a0b0c0d0e0f"
            "000102030405060708090a0bbad3be5065abe8193a480e464cd4de1a"
            "7e5abf44397249633e52002433f1901b90a98e"
        )

        _flags, decoded, _metadata = parse_stego_payload(
            legacy_fixture, password=password
        )

        assert decoded == b"version one fixture"

    @pytest.mark.parametrize(
        ("encrypted", "compress", "metadata"),
        [
            (False, False, None),
            (True, False, None),
            (False, True, None),
            (True, True, None),
            (False, False, {"comment": "estimate", "expires": ""}),
            (True, True, {"comment": "estimate", "expires": ""}),
        ],
    )
    def test_estimated_envelope_size_is_exact(self, encrypted, compress, metadata):
        plaintext = b"exact serialized size" * 7
        comment = metadata.get("comment") if metadata else None
        password = "pw" if encrypted else None
        expected = build_stego_payload(
            plaintext, flags=0, password=password, compress=compress,
            comment=comment, expires=None,
        )[0]

        assert estimate_stego_payload_size(
            plaintext, encrypted=encrypted, compress=compress, metadata=metadata
        ) == len(expected)

    def test_timezone_aware_expiration_is_checked_in_utc(self):
        expired = build_stego_payload(
            b"expired", flags=0, password=None, compress=False,
            comment=None, expires="2000-01-01T00:00:00+00:00",
        )[0]
        unexpired = build_stego_payload(
            b"unexpired", flags=0, password=None, compress=False,
            comment=None, expires="2999-01-01T00:00:00+00:00",
        )[0]

        with pytest.raises(ValueError, match="expired"):
            parse_stego_payload(expired, password=None)
        assert parse_stego_payload(unexpired, password=None)[1] == b"unexpired"


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

        with pytest.raises(InvalidTag):
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
