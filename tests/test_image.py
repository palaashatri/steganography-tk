"""Tests for stego.image module."""

from pathlib import Path

import pytest
from PIL import Image
from stego.image import (
    embed_stego_data_in_image,
    extract_stego_data_from_image,
    image_capacity_bytes,
    load_image,
)
from stego.core import build_stego_payload, parse_header, parse_stego_payload
from stego.core import (
    FLAG_ENCRYPTED,
    FLAG_LSB_MATCH,
    FLAG_PRNG,
    LEGACY_VERSION,
    MAGIC,
    STREAMING_PRNG_VERSION,
    StegoHeader,
    VERSION,
    derive_key,
)
from stego.image import read_payload


def test_read_payload_accepts_an_empty_message():
    assert read_payload("", None) == b""


def test_read_payload_checks_utf8_message_byte_length():
    with pytest.raises(ValueError, match="1-byte input limit"):
        read_payload("é", None, max_bytes=1)


def test_read_payload_limits_reads_when_file_grows_after_stat(temp_dir, monkeypatch):
    payload_path = temp_dir / "payload.bin"
    payload_path.write_bytes(b"grew after stat")
    read_sizes = []
    original_stat = Path.stat
    original_open = Path.open

    class UnderreportedStat:
        def __init__(self, wrapped):
            self._wrapped = wrapped
            self.st_size = 2

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

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

    def underreport_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        return UnderreportedStat(result) if path == payload_path else result

    def tracked_open(path, *args, **kwargs):
        wrapped = original_open(path, *args, **kwargs)
        return ReadTrackingFile(wrapped) if path == payload_path else wrapped

    monkeypatch.setattr(Path, "stat", underreport_stat)
    monkeypatch.setattr(Path, "open", tracked_open)

    with pytest.raises(ValueError, match="2-byte input limit"):
        read_payload(None, str(payload_path), max_bytes=2)

    assert read_sizes == [3]


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
@pytest.mark.parametrize("password", [None, "capacity-password"])
def test_each_image_method_accepts_exact_envelope_capacity(method, password):
    image = Image.new("RGB", (16, 16), (100, 120, 140))
    capacity = image_capacity_bytes(image)
    header_size = 40 if password else 12
    tag_size = 16 if password else 0
    payload = b"x" * (capacity - header_size - tag_size)
    stego_data, _, _, _ = build_stego_payload(
        payload,
        flags=0,
        password=password,
        compress=False,
        comment=None,
        expires=None,
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
        payload,
        flags=0,
        password=password,
        compress=False,
        comment=None,
        expires=None,
    )
    key = "capacity-test-key" if method != "lsb" else None

    assert len(stego_data) == capacity + 1
    with pytest.raises(ValueError, match="too large"):
        embed_stego_data_in_image(image, stego_data, method, key)


def test_legacy_prng_embedding_normalizes_rgba_input_to_rgb():
    image = Image.new("RGBA", (32, 32), (100, 120, 140, 255))
    payload = b"rgba legacy PRNG round trip"
    stego_data, _, _, _ = build_stego_payload(
        payload,
        flags=FLAG_PRNG,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        version=VERSION,
    )

    encoded = embed_stego_data_in_image(image, stego_data, "lsb-prng", "rgba-key")
    extracted = extract_stego_data_from_image(encoded, "lsb-prng", "rgba-key")

    assert encoded.mode == "RGB"
    assert parse_stego_payload(extracted, password=None)[1] == payload


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
def test_each_image_method_round_trips_encrypted_payload_and_rejects_wrong_password(
    method,
):
    image = Image.new("RGB", (32, 32), (100, 120, 140))
    payload = b"binary\x00payload\xff"
    stego_data, _, _, _ = build_stego_payload(
        payload,
        flags=0,
        password="correct",
        compress=False,
        comment=None,
        expires=None,
    )
    key = "round-trip-key" if method != "lsb" else None
    stego_image = embed_stego_data_in_image(image, stego_data, method, key)
    extracted = extract_stego_data_from_image(stego_image, method, key)

    assert parse_stego_payload(extracted, password="correct")[1] == payload
    with pytest.raises(ValueError, match="Password is incorrect"):
        parse_stego_payload(extracted, password="wrong")


@pytest.mark.parametrize("suffix", ["jpg", "jpeg"])
def test_cli_rejects_lossy_image_output(sample_image, temp_dir, suffix):
    from argparse import Namespace

    import app

    output_path = temp_dir / f"stego.{suffix}"
    args = Namespace(
        image=str(sample_image),
        out=str(output_path),
        message="payload",
        in_file=None,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        method="lsb",
        prng_key=None,
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
        assert img.mode == "RGB"

    def test_embed_and_extract_lsb(self, sample_image, sample_text, temp_dir):
        """Test LSB embedding and extraction."""
        # Prepare payload
        payload = sample_text.encode("utf-8")
        stego_data, _, _, _ = build_stego_payload(
            payload, flags=0, password=None, compress=False, comment=None, expires=None
        )

        # Load image and embed
        img = load_image(str(sample_image))
        stego_img = embed_stego_data_in_image(
            img, stego_data, method="lsb", prng_key=None
        )

        # Save and reload
        output_path = temp_dir / "stego_output.png"
        stego_img.save(output_path)
        stego_img = load_image(str(output_path))

        # Extract and verify
        extracted_data = extract_stego_data_from_image(
            stego_img, method="lsb", prng_key=None
        )
        header, plaintext, metadata = parse_stego_payload(extracted_data, password=None)

        assert plaintext == payload

    def test_embed_and_extract_with_password(
        self, sample_image, sample_text, password, temp_dir
    ):
        """Test embedding and extraction with password."""
        payload = sample_text.encode("utf-8")
        stego_data, _, _, _ = build_stego_payload(
            payload,
            flags=0,
            password=password,
            compress=False,
            comment=None,
            expires=None,
        )

        img = load_image(str(sample_image))
        stego_img = embed_stego_data_in_image(
            img, stego_data, method="lsb", prng_key=None
        )

        output_path = temp_dir / "stego_encrypted.png"
        stego_img.save(output_path)
        stego_img = load_image(str(output_path))

        extracted_data = extract_stego_data_from_image(
            stego_img, method="lsb", prng_key=None
        )
        header, plaintext, metadata = parse_stego_payload(
            extracted_data, password=password
        )

        assert plaintext == payload

    def test_capacity_check(self, sample_image, temp_dir):
        """Test that too much data raises an error."""
        # Create data larger than image capacity
        img = load_image(str(sample_image))
        total_pixels = img.width * img.height
        # Each pixel can store 3 bits (RGB), need 8 bits per byte
        max_bytes = (total_pixels * 3) // 8

        large_data = b"X" * (max_bytes + 1000)  # Larger than capacity
        stego_data, _, _, _ = build_stego_payload(
            large_data,
            flags=0,
            password=None,
            compress=False,
            comment=None,
            expires=None,
        )

        with pytest.raises(ValueError, match="too large"):
            embed_stego_data_in_image(img, stego_data, method="lsb", prng_key=None)


def test_pair_chi_square_is_zero_for_balanced_adjacent_value_pairs():
    from stego.detect import lsb_pair_chi_square

    image = Image.new("RGB", (2, 1))
    image.putdata([(100, 102, 104), (101, 103, 105)])

    statistic = lsb_pair_chi_square(image)

    assert isinstance(statistic, float)
    assert statistic == pytest.approx(0.0)


def test_pair_chi_square_grows_for_deliberately_unbalanced_pairs():
    from stego.detect import lsb_pair_chi_square

    image = Image.new("RGB", (4, 1), (100, 102, 104))

    assert lsb_pair_chi_square(image) == pytest.approx(12.0)


def test_image_extraction_reads_only_the_envelope_bits():
    from stego.core import build_stego_payload

    payload = b"small payload in a much larger carrier"
    envelope, _, _, _ = build_stego_payload(
        payload,
        flags=0,
        password=None,
        compress=False,
        comment=None,
        expires=None,
    )
    carrier = embed_stego_data_in_image(
        Image.new("RGB", (256, 256), (100, 120, 140)), envelope, "lsb", None
    )

    class CountingImage:
        width = carrier.width
        height = carrier.height
        mode = "RGB"

        def __init__(self):
            self.channels_read = 0

        def getdata(self):
            for pixel in carrier.getdata():
                self.channels_read += 3
                yield pixel

        def getpixel(self, location):
            self.channels_read += 3
            return carrier.getpixel(location)

    counting_image = CountingImage()

    assert extract_stego_data_from_image(counting_image, "lsb", None) == envelope
    assert counting_image.channels_read <= len(envelope) * 8 + 2
    assert counting_image.channels_read < carrier.width * carrier.height * 3


@pytest.mark.parametrize("method", ["lsb", "lsb-prng", "lsb-match-prng"])
def test_image_extraction_does_not_flatten_the_entire_carrier(method, monkeypatch):
    import stego.image as image_module

    envelope, _, _, _ = build_stego_payload(
        b"bounded extraction",
        flags=0,
        password=None,
        compress=False,
        comment=None,
        expires=None,
    )
    key = "bounded-extraction-key" if method != "lsb" else None
    image = embed_stego_data_in_image(
        Image.new("RGB", (128, 128), (100, 120, 140)), envelope, method, key
    )

    def fail_if_flattened(_image):
        raise AssertionError(
            "extraction flattened the complete image into Python values"
        )

    monkeypatch.setattr(
        image_module, "flatten_channels", fail_if_flattened, raising=False
    )

    assert extract_stego_data_from_image(image, method, key) == envelope


@pytest.mark.parametrize(
    ("method", "flags"),
    [
        ("lsb-prng", FLAG_PRNG),
        ("lsb-match-prng", FLAG_PRNG | FLAG_LSB_MATCH),
    ],
)
def test_version_three_prng_round_trip_uses_only_a_partial_permutation(
    method, flags, monkeypatch
):
    import stego.image as image_module

    payload = b"streamed version three payload"
    envelope, _, _, _ = build_stego_payload(
        payload,
        flags=flags,
        password="version-three-password",
        compress=False,
        comment=None,
        expires=None,
        version=STREAMING_PRNG_VERSION,
    )
    key = "streamed-prng-key"
    image = Image.new("RGB", (128, 128), (100, 120, 140))

    def fail_if_legacy_permutation(*_args, **_kwargs):
        raise AssertionError("version three used the full legacy permutation")

    monkeypatch.setattr(image_module, "_permute_indices", fail_if_legacy_permutation)

    stego_image = embed_stego_data_in_image(image, envelope, method, key)
    extracted = extract_stego_data_from_image(stego_image, method, key)
    header = parse_header(extracted[: 12 + extracted[6] + extracted[7]])
    _flags, extracted_payload, _metadata = parse_stego_payload(
        extracted, "version-three-password"
    )

    assert header.version == STREAMING_PRNG_VERSION
    assert header.flags == flags | FLAG_ENCRYPTED
    assert extracted_payload == payload
    with pytest.raises(ValueError, match="Password is incorrect"):
        parse_stego_payload(extracted, "incorrect-password")


def test_version_three_prng_rejects_capacity_overflow():
    from stego.core import FLAG_PRNG, STREAMING_PRNG_VERSION

    image = Image.new("RGB", (16, 16), (100, 120, 140))
    capacity = image_capacity_bytes(image)
    envelope, _, _, _ = build_stego_payload(
        b"x" * (capacity - 12 + 1),
        flags=FLAG_PRNG,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        version=STREAMING_PRNG_VERSION,
    )

    with pytest.raises(ValueError, match="Payload too large"):
        embed_stego_data_in_image(image, envelope, "lsb-prng", "overflow-key")


def test_version_three_prng_rejects_unknown_method():
    image = Image.new("RGB", (16, 16), (100, 120, 140))
    envelope, _, _, _ = build_stego_payload(
        b"v3 payload",
        flags=FLAG_PRNG,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        version=STREAMING_PRNG_VERSION,
    )

    with pytest.raises(ValueError, match="Unknown method: bogus-method"):
        embed_stego_data_in_image(image, envelope, "bogus-method", "valid-key")


@pytest.mark.parametrize("method", ["lsb-prng", "lsb-match-prng"])
@pytest.mark.parametrize("password", [None, "legacy-password"])
def test_legacy_v1_prng_images_remain_decodable(method, password):
    """Keep decoding carriers emitted before the v2 authenticated header."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from stego.core import FLAG_ENCRYPTED

    payload = b"legacy v1 image payload\x00\xff"
    flags = FLAG_ENCRYPTED if password else 0
    salt = bytes(range(16)) if password else b""
    nonce = bytes(range(12)) if password else b""
    payload_len = len(payload) + (16 if password else 0)
    header = StegoHeader(
        flags=flags,
        salt=salt,
        nonce=nonce,
        payload_len=payload_len,
        version=LEGACY_VERSION,
    )
    if password:
        legacy_aad = MAGIC + bytes([LEGACY_VERSION, flags]) + salt + nonce
        serialized_payload = AESGCM(derive_key(password, salt)).encrypt(
            nonce, payload, legacy_aad
        )
    else:
        serialized_payload = payload
    envelope = header.to_bytes() + serialized_payload

    key = "legacy-image-key"
    carrier = Image.new("RGB", (128, 128), (100, 120, 140))
    stego_image = embed_stego_data_in_image(carrier, envelope, method, key)

    extracted = extract_stego_data_from_image(stego_image, method, key)

    assert extracted == envelope
    assert parse_stego_payload(extracted, password)[1] == payload


def test_version_three_small_payload_avoids_full_carrier_permutation(monkeypatch):
    """Small v3 payloads on large carriers should use sparse permutation state."""
    import stego.core as core

    payload = b"small streaming payload"
    envelope, _, _, _ = build_stego_payload(
        payload,
        flags=FLAG_PRNG,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        version=STREAMING_PRNG_VERSION,
    )
    carrier = Image.new("RGB", (512, 512), (100, 120, 140))
    key = "small-v3-payload-key"

    def fail_if_full_index_array(_length):
        raise AssertionError("small v3 payload allocated a full carrier permutation")

    monkeypatch.setattr(core, "_new_index_array", fail_if_full_index_array)

    stego_image = embed_stego_data_in_image(carrier, envelope, "lsb-prng", key)
    assert extract_stego_data_from_image(stego_image, "lsb-prng", key) == envelope


def test_version_three_near_capacity_uses_compact_prng_indices(monkeypatch):
    """Near-capacity v3 payloads use compact native storage for their permutation."""
    from array import array

    import stego.core as core

    carrier = Image.new("RGB", (32, 32), (100, 120, 140))
    capacity = image_capacity_bytes(carrier)
    envelope, _, _, _ = build_stego_payload(
        b"x" * (capacity - 12),
        flags=FLAG_PRNG,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        version=STREAMING_PRNG_VERSION,
    )
    assert len(envelope) == capacity

    allocated_arrays = []
    original_new_index_array = core._new_index_array

    def track_compact_array(length):
        result = original_new_index_array(length)
        allocated_arrays.append(result)
        return result

    monkeypatch.setattr(core, "_new_index_array", track_compact_array)

    stego_image = embed_stego_data_in_image(
        carrier, envelope, "lsb-prng", "near-capacity-v3-key"
    )

    assert allocated_arrays
    assert all(isinstance(indices, array) for indices in allocated_arrays)
    assert all(indices.itemsize <= 8 for indices in allocated_arrays)
    assert (
        extract_stego_data_from_image(stego_image, "lsb-prng", "near-capacity-v3-key")
        == envelope
    )


def test_version_three_near_capacity_embedding_does_not_expand_payload_to_bit_list(
    monkeypatch,
):
    """Streaming v3 embedding should not allocate eight Python ints per byte."""
    import stego.image as image_module

    carrier = Image.new("RGB", (32, 32), (100, 120, 140))
    capacity = image_capacity_bytes(carrier)
    envelope, _, _, _ = build_stego_payload(
        b"x" * (capacity - 12),
        flags=FLAG_PRNG,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        version=STREAMING_PRNG_VERSION,
    )
    assert len(envelope) == capacity

    def fail_if_materialized(_data):
        raise AssertionError("v3 embedding expanded the full payload into a bit list")

    monkeypatch.setattr(image_module, "bytes_to_bits", fail_if_materialized)

    embed_stego_data_in_image(carrier, envelope, "lsb-prng", "near-capacity-v3-key")


def test_lsb_embedding_does_not_expand_payload_to_bit_list(monkeypatch):
    """The direct LSB path should stream payload bits from their source bytes."""
    import stego.image as image_module

    carrier = Image.new("RGB", (32, 32), (100, 120, 140))
    envelope, _, _, _ = build_stego_payload(
        b"ordinary LSB payload",
        flags=0,
        password=None,
        compress=False,
        comment=None,
        expires=None,
    )

    def fail_if_materialized(_data):
        raise AssertionError("LSB embedding expanded the payload into a bit list")

    monkeypatch.setattr(image_module, "bytes_to_bits", fail_if_materialized)
    stego_image = embed_stego_data_in_image(carrier, envelope, "lsb", None)

    assert extract_stego_data_from_image(stego_image, "lsb", None) == envelope


def test_cli_prng_image_encoding_marks_the_streaming_format(sample_image, temp_dir):
    from argparse import Namespace

    from app import encode_image
    from stego.core import STREAMING_PRNG_VERSION
    from stego.image import extract_image_header

    output = temp_dir / "streaming-prng.png"
    args = Namespace(
        image=str(sample_image),
        out=str(output),
        message="new PRNG format",
        in_file=None,
        password=None,
        compress=False,
        comment=None,
        expires=None,
        method="lsb-prng",
        prng_key="cli-streaming-key",
    )

    encode_image(args)
    header = extract_image_header(
        load_image(str(output)), "lsb-prng", "cli-streaming-key"
    )

    assert header.version == STREAMING_PRNG_VERSION
    assert header.flags & FLAG_PRNG


def test_legacy_prng_fallback_bounds_large_carriers_before_permutation(monkeypatch):
    from types import SimpleNamespace

    import stego.image as image_module

    carrier = SimpleNamespace(
        width=image_module.MAX_LEGACY_PRNG_CHANNELS // 3 + 1, height=1
    )
    calls = []

    def fail_streaming_probe(_image, _method, _key, **kwargs):
        calls.append(kwargs)
        raise ValueError("not a valid version 3 envelope")

    monkeypatch.setattr(image_module, "_read_image_header_once", fail_streaming_probe)

    with pytest.raises(ValueError, match="limited to 33,554,432 channel positions"):
        image_module._read_image_header(carrier, "lsb-prng", "wrong-key")

    assert len(calls) == 1
    assert calls[0]["streaming_prng"] is True


def test_version_three_prng_header_probe_bypasses_legacy_carrier_limit(monkeypatch):
    from types import SimpleNamespace

    import stego.image as image_module

    carrier = SimpleNamespace(
        width=image_module.MAX_LEGACY_PRNG_CHANNELS // 3 + 1, height=1
    )
    header = StegoHeader(
        flags=FLAG_PRNG,
        salt=b"",
        nonce=b"",
        payload_len=0,
        version=STREAMING_PRNG_VERSION,
    )
    serialized_header = header.to_bytes()
    calls = []

    def streaming_probe(_image, _method, _key, **kwargs):
        calls.append(kwargs)
        return header, serialized_header, iter(())

    monkeypatch.setattr(image_module, "_read_image_header_once", streaming_probe)

    result = image_module._read_image_header(carrier, "lsb-prng", "stream-key")

    assert result[0] is header
    assert len(calls) == 2
    assert all(call["streaming_prng"] is True for call in calls)


def test_invalid_version_three_header_fails_before_legacy_permutation(monkeypatch):
    from types import SimpleNamespace

    import stego.image as image_module

    carrier = SimpleNamespace(width=128, height=128)
    header = StegoHeader(
        flags=0,
        salt=b"",
        nonce=b"",
        payload_len=0,
        version=STREAMING_PRNG_VERSION,
    )
    calls = []

    def invalid_v3_probe(_image, _method, _key, **kwargs):
        calls.append(kwargs)
        return header, header.to_bytes(), iter(())

    monkeypatch.setattr(image_module, "_read_image_header_once", invalid_v3_probe)

    with pytest.raises(ValueError, match="Unsupported version 3"):
        image_module._read_image_header(carrier, "lsb-prng", "stream-key")

    assert len(calls) == 1
