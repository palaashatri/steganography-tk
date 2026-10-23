"""Generated-fixture coverage for visible audio metadata embedding."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import wave

import pytest
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mutagen.id3 import APIC, ID3
from mutagen.mp4 import MP4

from stego.audio import embed_data_in_audio, extract_data_from_audio
from stego.video import embed_data_in_video
from stego.core import (
    FLAG_ENCRYPTED,
    FLAG_META,
    FLAG_PAYLOAD_IMAGE,
    FLAG_PAYLOAD_TEXT,
    LEGACY_VERSION,
    MAGIC,
    StegoHeader,
    build_stego_payload,
    derive_key,
    parse_stego_payload,
)
from stego import core


AUDIO_FORMATS = (
    ".mp3", ".mp4", ".m4a", ".wav", ".flac", ".ogg", ".opus", ".aac",
    ".m4b", ".m4p", ".m4v", ".mov",
)
PASSWORD = "metadata-test-password"
PAYLOAD = b"\x00\x01binary payload\xfe\xff"
MAX_METADATA_STEGO_BYTES = 1_000_000


def _run_ffmpeg(*args: str) -> None:
    subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _make_audio(path, extension: str) -> None:
    codecs = {
        ".mp3": "libmp3lame",
        ".mp4": "aac",
        ".m4a": "aac",
        ".m4b": "aac",
        ".m4p": "aac",
        ".m4v": "aac",
        ".mov": "aac",
        ".wav": "pcm_s16le",
        ".flac": "flac",
        ".ogg": "libvorbis",
        ".opus": "libopus",
        ".aac": "aac",
    }
    output_format = {
        ".m4b": "ipod",
        ".m4p": "ipod",
        ".m4v": "mp4",
        ".mov": "mov",
    }.get(extension)
    output_options = ["-f", output_format] if output_format else []
    _run_ffmpeg(
        "-f", "lavfi", "-i", "sine=frequency=880:sample_rate=44100:duration=0.25",
        "-vn", "-c:a", codecs[extension], *output_options, str(path),
    )


@pytest.fixture(params=AUDIO_FORMATS, ids=lambda ext: ext.lstrip("."))
def audio_source(request, tmp_path_factory):
    extension = request.param
    directory = tmp_path_factory.mktemp(f"audio-{extension[1:]}")
    path = directory / f"source{extension}"
    _make_audio(path, extension)
    return path


@pytest.fixture
def mp3_source(tmp_path_factory):
    path = tmp_path_factory.mktemp("audio-mp3") / "source.mp3"
    _make_audio(path, ".mp3")
    return path


@pytest.fixture
def mp4_source(tmp_path_factory):
    path = tmp_path_factory.mktemp("audio-mp4") / "source.mp4"
    _make_audio(path, ".mp4")
    return path


@pytest.fixture
def flac_source(tmp_path_factory):
    path = tmp_path_factory.mktemp("audio-flac") / "source.flac"
    _make_audio(path, ".flac")
    return path


@pytest.fixture
def payload_file(temp_dir):
    path = temp_dir / "payload.bin"
    path.write_bytes(PAYLOAD)
    return path


def _legacy_envelope(plaintext: bytes, flags: int, password: str) -> bytes:
    salt = bytes(range(16))
    nonce = bytes(range(16, 28))
    flags |= FLAG_ENCRYPTED
    header = StegoHeader(
        flags=flags,
        salt=salt,
        nonce=nonce,
        payload_len=len(plaintext) + 16,
        version=LEGACY_VERSION,
    )
    legacy_aad = MAGIC + bytes([LEGACY_VERSION, flags]) + salt + nonce
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(nonce, plaintext, legacy_aad)
    return header.to_bytes() + ciphertext


def _write_mp3_blob(source, destination, blob: bytes) -> None:
    if source != destination:
        shutil.copyfile(source, destination)
    try:
        tags = ID3(destination)
    except Exception:
        tags = ID3()
    tags.delall("APIC")
    tags.add(APIC(
        encoding=3,
        mime="application/octet-stream",
        type=0,
        desc="STEG_DATA",
        data=blob,
    ))
    tags.save(destination, v2_version=3)


def _read_mp3_blob(path) -> bytes:
    tags = ID3(path)
    return next(frame.data for frame in tags.values() if isinstance(frame, APIC))


def _write_mp4_blob(source, destination, blob: bytes) -> None:
    if source != destination:
        shutil.copyfile(source, destination)
    tags = MP4(destination)
    tags["©stg"] = [base64.b64encode(blob).decode("ascii")]
    tags.save()


def _read_mp4_blob(path) -> bytes:
    return base64.b64decode(MP4(path)["©stg"][0], validate=True)


def test_visible_audio_metadata_round_trip_preserves_binary_bytes(
    audio_source, payload_file, temp_dir
):
    extension = audio_source.suffix
    assert audio_source.suffix == extension
    output = temp_dir / f"stego{extension}"
    extracted = temp_dir / "extracted.bin"

    embed_data_in_audio(
        str(audio_source), str(output), password=PASSWORD, in_file=str(payload_file)
    )
    extract_data_from_audio(str(output), str(extracted), password=PASSWORD)

    assert extracted.read_bytes() == PAYLOAD


def test_visible_audio_metadata_rejects_wrong_password(
    audio_source, payload_file, temp_dir
):
    extension = audio_source.suffix
    assert audio_source.suffix == extension
    output = temp_dir / f"stego{extension}"
    extracted = temp_dir / "must-not-exist.bin"
    embed_data_in_audio(
        str(audio_source), str(output), password=PASSWORD, in_file=str(payload_file)
    )

    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_audio(str(output), str(extracted), password="wrong-password")
    assert not extracted.exists()


def test_audio_metadata_overflow_fails_before_creating_output(
    audio_source, temp_dir
):
    extension = audio_source.suffix
    assert audio_source.suffix == extension
    oversized = temp_dir / "oversized.bin"
    oversized.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / f"must-not-exist{extension}"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_audio(
            str(audio_source), str(output), in_file=str(oversized)
        )
    assert not output.exists()


@pytest.mark.parametrize("extension", (".mp3", ".mp4"))
def test_legacy_v1_encrypted_audio_metadata_still_decodes(temp_dir, extension, request):
    audio_source = request.getfixturevalue("mp3_source" if extension == ".mp3" else "mp4_source")
    carrier = temp_dir / f"legacy{extension}"
    output = temp_dir / "legacy.bin"
    blob = _legacy_envelope(PAYLOAD, FLAG_PAYLOAD_TEXT, PASSWORD)
    if extension == ".mp3":
        _write_mp3_blob(audio_source, carrier, blob)
    else:
        _write_mp4_blob(audio_source, carrier, blob)

    extract_data_from_audio(str(carrier), str(output), password=PASSWORD)

    assert output.read_bytes() == PAYLOAD


@pytest.mark.parametrize("extension", (".mp3", ".mp4"))
def test_mp3_mp4_v2_header_tampering_fails_authentication(
    payload_file, temp_dir, extension, request
):
    audio_source = request.getfixturevalue("mp3_source" if extension == ".mp3" else "mp4_source")
    output = temp_dir / f"stego{extension}"
    extracted = temp_dir / "tampered.bin"
    embed_data_in_audio(
        str(audio_source), str(output), password=PASSWORD, in_file=str(payload_file)
    )
    blob = bytearray(
        _read_mp3_blob(output) if extension == ".mp3" else _read_mp4_blob(output)
    )
    assert blob[4] == 2
    blob[5] |= 0x20  # Keep encryption enabled while changing an authenticated flag.
    if extension == ".mp3":
        _write_mp3_blob(output, output, bytes(blob))
        assert _read_mp3_blob(output)[5] == blob[5]
    else:
        _write_mp4_blob(output, output, bytes(blob))

    with pytest.raises(ValueError, match="modified|authenticate|decrypt|password"):
        extract_data_from_audio(str(output), str(extracted), password=PASSWORD)
    assert not extracted.exists()


def test_mp3_image_attachment_preserves_source_bytes_and_checks_password(mp3_source, temp_dir):
    image_path = temp_dir / "source.png"
    Image.new("RGB", (3, 2), (17, 91, 203)).save(image_path)
    output = temp_dir / "stego.mp3"
    restored = temp_dir / "restored.png"
    embed_data_in_audio(
        str(mp3_source), str(output), password=PASSWORD, image_path=str(image_path)
    )

    extract_data_from_audio(str(output), str(restored), password=PASSWORD)
    assert restored.read_bytes() == image_path.read_bytes()
    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_audio(
            str(output), str(temp_dir / "wrong.png"), password="wrong-password"
        )


def test_mp3_legacy_v1_image_attachment_still_decodes(mp3_source, temp_dir):
    pixels = bytes((9, 25, 40, 90, 110, 130))
    blob = _legacy_envelope(pixels, FLAG_PAYLOAD_IMAGE, PASSWORD) + b"\x00\x00\x00\x02\x00\x00\x00\x01"
    carrier = temp_dir / "legacy-image.mp3"
    restored = temp_dir / "legacy-image.png"
    _write_mp3_blob(mp3_source, carrier, blob)

    extract_data_from_audio(str(carrier), str(restored), password=PASSWORD)

    with Image.open(restored) as image:
        assert image.size == (2, 1)
        assert image.convert("RGB").tobytes() == pixels


def test_mp3_image_attachment_overflow_does_not_create_output(mp3_source, temp_dir):
    image_path = temp_dir / "large.png"
    Image.frombytes("RGB", (600, 600), os.urandom(600 * 600 * 3)).save(image_path)
    output = temp_dir / "must-not-exist.mp3"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_audio(
            str(mp3_source), str(output), image_path=str(image_path)
        )
    assert not output.exists()


def test_mp4_image_attachment_preserves_source_bytes_and_checks_password(mp4_source, temp_dir):
    image_path = temp_dir / "source.png"
    Image.new("RGB", (3, 2), (201, 39, 71)).save(image_path)
    output = temp_dir / "stego.mp4"
    restored = temp_dir / "restored.png"
    embed_data_in_audio(
        str(mp4_source), str(output), password=PASSWORD, image_path=str(image_path)
    )

    extract_data_from_audio(str(output), str(restored), password=PASSWORD)
    assert restored.read_bytes() == image_path.read_bytes()
    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_audio(
            str(output), str(temp_dir / "wrong.png"), password="wrong-password"
        )


def test_mp4_legacy_v1_image_attachment_still_decodes(mp4_source, temp_dir):
    pixels = bytes((17, 28, 39, 118, 129, 140))
    blob = _legacy_envelope(pixels, FLAG_PAYLOAD_IMAGE, PASSWORD) + b"\x00\x00\x00\x02\x00\x00\x00\x01"
    carrier = temp_dir / "legacy-image.mp4"
    restored = temp_dir / "legacy-image.png"
    _write_mp4_blob(mp4_source, carrier, blob)

    extract_data_from_audio(str(carrier), str(restored), password=PASSWORD)

    with Image.open(restored) as image:
        assert image.size == (2, 1)
        assert image.convert("RGB").tobytes() == pixels


def test_mp4_image_attachment_overflow_does_not_create_output(mp4_source, temp_dir):
    image_path = temp_dir / "large.png"
    Image.frombytes("RGB", (600, 600), os.urandom(600 * 600 * 3)).save(image_path)
    output = temp_dir / "must-not-exist.mp4"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_audio(str(mp4_source), str(output), image_path=str(image_path))
    assert not output.exists()


def test_mp3_in_mp4_attachment_round_trip_and_wrong_password(mp4_source, mp3_source, temp_dir):
    output = temp_dir / "stego.mp4"
    restored = temp_dir / "restored.mp3"
    embed_data_in_video(
        str(mp4_source), str(output), password=PASSWORD, mp3_path=str(mp3_source)
    )

    extract_data_from_audio(str(output), str(restored), password=PASSWORD)
    assert restored.read_bytes() == mp3_source.read_bytes()
    with pytest.raises(ValueError, match="password|modified|decrypt|authenticate"):
        extract_data_from_audio(
            str(output), str(temp_dir / "wrong.mp3"), password="wrong-password"
        )


def test_mp3_in_mp4_attachment_overflow_does_not_create_output(mp4_source, temp_dir):
    large_mp3 = temp_dir / "large.mp3"
    large_mp3.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / "must-not-exist.mp4"

    with pytest.raises(ValueError, match="capacity|maximum|1,000,000|too large"):
        embed_data_in_video(str(mp4_source), str(output), mp3_path=str(large_mp3))
    assert not output.exists()


def test_mp3_extraction_rejects_truncated_envelope(mp3_source, temp_dir):
    carrier = temp_dir / "truncated.mp3"
    _write_mp3_blob(mp3_source, carrier, b"STG1\x02")

    with pytest.raises(ValueError, match="too short|incomplete|header"):
        extract_data_from_audio(str(carrier), str(temp_dir / "out.bin"), password=PASSWORD)


def test_mp4_extraction_rejects_invalid_base64(mp4_source, temp_dir):
    carrier = temp_dir / "invalid-base64.mp4"
    shutil.copyfile(mp4_source, carrier)
    tags = MP4(carrier)
    tags["©stg"] = ["%%% definitely not base64 %%%"]
    tags.save()

    with pytest.raises(ValueError, match="base64|encoded|payload|stego"):
        extract_data_from_audio(str(carrier), str(temp_dir / "out.bin"), password=PASSWORD)


def test_tagged_audio_extraction_rejects_invalid_base64(flac_source, temp_dir):
    carrier = temp_dir / "invalid-base64.flac"
    shutil.copyfile(flac_source, carrier)
    from mutagen import File as MutagenFile

    tagged = MutagenFile(carrier)
    tagged.add_tags() if tagged.tags is None else None
    tagged["STEGO"] = ["%%% definitely not base64 %%%"]
    tagged.save()

    with pytest.raises(ValueError, match="base64|encoded|payload|stego"):
        extract_data_from_audio(str(carrier), str(temp_dir / "out.bin"), password=PASSWORD)


def test_metadata_capacity_constant_is_one_megabyte():
    assert getattr(core, "MAX_METADATA_STEGO_BYTES", None) == 1_000_000


def test_v2_envelope_rejects_unexpected_trailing_bytes():
    envelope = build_stego_payload(
        PAYLOAD, FLAG_PAYLOAD_TEXT, PASSWORD, False, None, None
    )[0]

    with pytest.raises(ValueError, match="trailing|length"):
        parse_stego_payload(envelope + b"unexpected", PASSWORD)


def test_audio_cli_capacity_error_is_nonzero_and_leaves_no_output(temp_dir):
    source = temp_dir / "source.wav"
    with wave.open(str(source), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 16)
    oversized = temp_dir / "large.bin"
    oversized.write_bytes(b"x" * (MAX_METADATA_STEGO_BYTES + 1))
    output = temp_dir / "must-not-exist.wav"
    result = subprocess.run(
        [
            "python",
            "app.py",
            "audio-encode",
            "--audio",
            str(source),
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


@pytest.mark.parametrize("metadata_json", ("[]", '"scalar"', "17", "true"))
def test_metadata_envelope_rejects_json_that_is_not_an_object(metadata_json):
    metadata_bytes = metadata_json.encode("utf-8")
    plaintext = len(metadata_bytes).to_bytes(4, "big") + metadata_bytes + PAYLOAD
    header = StegoHeader(
        flags=FLAG_META | FLAG_PAYLOAD_TEXT,
        salt=b"",
        nonce=b"",
        payload_len=len(plaintext),
    )
    envelope = header.to_bytes() + plaintext

    with pytest.raises(ValueError, match="(?i)metadata|json object"):
        parse_stego_payload(envelope, None)


@pytest.mark.parametrize("preexisting", (False, True), ids=("new", "existing"))
def test_audio_backend_mismatch_preserves_output(
    mp3_source, temp_dir, preexisting
):
    output = temp_dir / "wrong-backend.wav"
    original = b"existing destination must survive"
    if preexisting:
        output.write_bytes(original)

    with pytest.raises(ValueError, match="backend|extension|carrier"):
        embed_data_in_audio(str(mp3_source), str(output), message="payload")

    if preexisting:
        assert output.read_bytes() == original
    else:
        assert not output.exists()


@pytest.mark.parametrize(
    ("command", "expected_output_help"),
    (
        ("audio-encode", "Output audio carrier path"),
        ("video-encode", "Output video carrier path"),
        ("pdf-encode", "Output PDF carrier path"),
    ),
)
def test_metadata_encode_cli_names_output_as_carrier(
    command, expected_output_help
):
    result = subprocess.run(
        ["python", "app.py", command, "--help"], capture_output=True, text=True
    )

    assert result.returncode == 0
    assert expected_output_help in result.stdout
