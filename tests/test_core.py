"""Tests for stego.core module."""

import base64
import random
import zlib
from array import array

import pytest

import stego.core as core
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
    make_rng,
)


def test_decode_stego_base64_rejects_oversized_input_before_decoding(monkeypatch):
    encoded_limit = 4 * ((core.MAX_METADATA_STEGO_BYTES + 2) // 3)
    original_decode = core.base64.b64decode
    was_decoded = False

    def track_decode(encoded, *, validate=False):
        nonlocal was_decoded
        was_decoded = True
        return original_decode(encoded, validate=validate)

    monkeypatch.setattr(core.base64, "b64decode", track_decode)

    with pytest.raises(ValueError, match="1,000,000|limit|too large"):
        core.decode_stego_base64("A" * (encoded_limit + 4))

    assert not was_decoded


def test_metadata_source_input_limit_accounts_for_compression_and_metadata():
    metadata = {"comment": "bounded source", "expires": ""}
    metadata_bytes = len(core.apply_metadata(b"", metadata)[0])

    assert core.max_input_payload_bytes(compress=False, metadata=metadata) == (
        core.MAX_METADATA_STEGO_BYTES
    )
    assert core.max_input_payload_bytes(compress=True, metadata=metadata) == (
        core.MAX_DECOMPRESSED_PAYLOAD_BYTES - metadata_bytes
    )
    assert core.max_input_payload_bytes(compress=True, metadata=None) == (
        core.MAX_DECOMPRESSED_PAYLOAD_BYTES
    )


def test_compact_prng_permutation_matches_legacy_shuffle_order():
    legacy_indices = list(range(512))
    random.Random(92814).shuffle(legacy_indices)

    compact_indices = core._permute_indices(512, random.Random(92814))

    assert isinstance(compact_indices, array)
    assert list(compact_indices) == legacy_indices


def test_streaming_prng_permutation_is_a_stable_prefix_and_full_permutation():
    # The streaming permutation uses a separate forward sparse Fisher-Yates
    # order; this reference implementation also proves it emits each position once.
    expected_stream = list(range(257))
    rng = random.Random(4127)
    for position in range(len(expected_stream)):
        selected = rng.randrange(position, len(expected_stream))
        expected_stream[position], expected_stream[selected] = (
            expected_stream[selected],
            expected_stream[position],
        )

    actual = list(core.iter_prng_indices(257, random.Random(4127)))
    prefix = list(core.iter_prng_indices(257, random.Random(4127), count=7))

    assert actual == expected_stream
    assert len(set(actual)) == 257
    assert prefix == actual[:7]


def test_version_three_payload_uses_authenticated_header():
    envelope, _, _, _ = core.build_stego_payload(
        b"version three",
        flags=core.FLAG_PRNG,
        password="v3-password",
        compress=False,
        comment=None,
        expires=None,
        version=core.STREAMING_PRNG_VERSION,
    )

    parsed_flags, plaintext, metadata = parse_stego_payload(
        envelope, password="v3-password"
    )

    header = core.parse_header(envelope[: 12 + envelope[6] + envelope[7]])
    assert header.version == core.STREAMING_PRNG_VERSION
    assert parsed_flags == core.FLAG_PRNG | core.FLAG_ENCRYPTED
    assert plaintext == b"version three"
    assert metadata is None
    with pytest.raises(ValueError, match="Password is incorrect"):
        parse_stego_payload(envelope, password="wrong-password")

    tampered = bytearray(envelope)
    tampered[5] ^= core.FLAG_LSB_MATCH
    with pytest.raises(
        ValueError, match="Password is incorrect or the embedded payload was modified"
    ):
        parse_stego_payload(bytes(tampered), password="v3-password")


def test_decode_stego_base64_rejects_decoded_payload_over_limit():
    oversized = base64.b64encode(b"x" * (core.MAX_METADATA_STEGO_BYTES + 1))

    with pytest.raises(ValueError, match="1,000,000|limit|too large"):
        core.decode_stego_base64(oversized)


class TestStegoHeader:
    """Test StegoHeader dataclass."""

    def test_header_creation(self):
        """Test creating a StegoHeader."""
        header = StegoHeader(
            flags=0, salt=b"12345678", nonce=b"123456789012", payload_len=100
        )
        assert header.flags == 0
        assert header.payload_len == 100
        assert len(header.salt) == 8
        assert len(header.nonce) == 12

    def test_new_headers_use_version_two_and_aad_is_full_serialized_header(self):
        stego_data, _, _, _ = build_stego_payload(
            b"authenticated",
            flags=0,
            password="pw",
            compress=False,
            comment=None,
            expires=None,
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
            b"tamper detection payload",
            flags=0,
            password="pw",
            compress=False,
            comment=None,
            expires=None,
        )
        mutated = bytearray(stego_data)
        if offset == 8:
            length = int.from_bytes(mutated[8:12], "big")
            mutated[8:12] = (length - 1).to_bytes(4, "big")
        else:
            mutated[offset : offset + 1] = replacement

        if structural_error:
            with pytest.raises(ValueError):
                parse_stego_payload(bytes(mutated), password="pw")
        else:
            with pytest.raises(ValueError):
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
            plaintext,
            flags=0,
            password=password,
            compress=compress,
            comment=comment,
            expires=None,
        )[0]

        assert estimate_stego_payload_size(
            plaintext, encrypted=encrypted, compress=compress, metadata=metadata
        ) == len(expected)

    def test_timezone_aware_expiration_is_checked_in_utc(self):
        expired = build_stego_payload(
            b"expired",
            flags=0,
            password=None,
            compress=False,
            comment=None,
            expires="2000-01-01T00:00:00+00:00",
        )[0]
        unexpired = build_stego_payload(
            b"unexpired",
            flags=0,
            password=None,
            compress=False,
            comment=None,
            expires="2999-01-01T00:00:00+00:00",
        )[0]

        with pytest.raises(ValueError, match="expired"):
            parse_stego_payload(expired, password=None)
        assert parse_stego_payload(unexpired, password=None)[1] == b"unexpired"


class TestPayloadOperations:
    """Test payload building and parsing."""

    def test_build_and_parse_payload_no_encryption(self, sample_text):
        """Test building and parsing unencrypted payload."""
        payload = sample_text.encode("utf-8")
        stego_data, size, salt, nonce = build_stego_payload(
            payload, flags=0, password=None, compress=False, comment=None, expires=None
        )

        assert len(stego_data) > 0
        header, plaintext, metadata = parse_stego_payload(stego_data, password=None)
        assert plaintext == payload

    def test_build_and_parse_payload_with_encryption(self, sample_text, password):
        """Test building and parsing encrypted payload."""
        payload = sample_text.encode("utf-8")
        stego_data, size, salt, nonce = build_stego_payload(
            payload,
            flags=0,
            password=password,
            compress=False,
            comment=None,
            expires=None,
        )

        header, plaintext, metadata = parse_stego_payload(stego_data, password=password)
        assert plaintext == payload

    def test_build_and_parse_payload_with_compression(self, sample_text):
        """Test building and parsing compressed payload."""
        payload = sample_text.encode("utf-8")
        stego_data, size, salt, nonce = build_stego_payload(
            payload, flags=0, password=None, compress=True, comment=None, expires=None
        )

        header, plaintext, metadata = parse_stego_payload(stego_data, password=None)
        assert plaintext == payload

    def test_compressed_payload_expansion_is_bounded(self, monkeypatch):
        monkeypatch.setattr(core, "MAX_DECOMPRESSED_PAYLOAD_BYTES", 1024)
        compressed = zlib.compress(b"A" * 1025)
        header = StegoHeader(
            flags=FLAG_COMPRESSED,
            salt=b"",
            nonce=b"",
            payload_len=len(compressed),
        )

        with pytest.raises(ValueError, match="Decompressed payload exceeds"):
            parse_stego_payload(header.to_bytes() + compressed, password=None)

    def test_compression_refuses_payloads_over_decode_limit(self, monkeypatch):
        monkeypatch.setattr(core, "MAX_DECOMPRESSED_PAYLOAD_BYTES", 1024)

        with pytest.raises(ValueError, match="compressed payload limit"):
            build_stego_payload(
                b"A" * 1025,
                flags=0,
                password=None,
                compress=True,
                comment=None,
                expires=None,
            )

    def test_wrong_password_fails(self, sample_text, password):
        """Test that wrong password fails decryption."""
        payload = sample_text.encode("utf-8")
        stego_data, _, _, _ = build_stego_payload(
            payload,
            flags=0,
            password=password,
            compress=False,
            comment=None,
            expires=None,
        )

        with pytest.raises(ValueError, match="Password is incorrect"):
            parse_stego_payload(stego_data, password="wrong_password")


class TestBitOperations:
    """Test bit embedding and extraction."""

    def test_embed_and_extract_bits(self):
        """Test embedding and extracting bits."""
        from PIL import Image
        import numpy as np

        # Create a small test image
        img_array = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
        img = Image.fromarray(img_array, "RGB")

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
