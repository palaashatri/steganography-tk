"""Tests for self-contained utility archives."""

from __future__ import annotations

import runpy
import json
import os
import subprocess
import zipfile

import pytest
from PIL import Image

from stego.core import build_stego_payload
from stego.image import embed_stego_data_in_image
from stego.utils import (
    create_portable_decoder,
    create_windows_file_association,
    ensure_output_differs_from_payloads,
)


def test_windows_file_association_escapes_registry_command(tmp_path):
    output = tmp_path / "association.reg"
    python_path = r'C:\Program Files\Python "Preview"\python.exe'
    app_path = r"C:\Users\Test User\Stego Suite\app.py"

    create_windows_file_association(str(output), app_path, python_path)

    command_line = next(
        line
        for line in output.read_text(encoding="utf-8").splitlines()
        if line.startswith("@=") and "decode --image" in line
    )
    assert json.loads(command_line[2:]) == (
        f'"{python_path}" "{app_path}" decode --image "%1" --out "%1.decoded"'
    )


def test_source_portable_decoder_is_runnable_without_exposing_or_overwriting_secrets(
    tmp_path, monkeypatch
):
    payload = b"portable decoder round trip"
    password = "archive-password-92817"
    prng_key = "archive-prng-key-62304"
    carrier_name = "carrier with spaces.png"
    carrier_path = tmp_path / carrier_name
    archive_path = tmp_path / "source decoder.zip"

    image = Image.new("RGB", (256, 256), (40, 60, 80))
    envelope, _, _, _ = build_stego_payload(
        payload,
        flags=0,
        password=password,
        compress=False,
        comment=None,
        expires=None,
    )
    embed_stego_data_in_image(image, envelope, "lsb-prng", prng_key).save(carrier_path)

    create_portable_decoder(
        str(carrier_path),
        str(archive_path),
        method="lsb-prng",
        prng_key=prng_key,
        password=password,
        frame_index=None,
    )

    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        members = set(archive.namelist())
        required = {
            "app.py",
            "requirements.txt",
            "run_decode.py",
            "README.txt",
            carrier_name,
            "stego/__init__.py",
            "stego/core.py",
            "stego/image.py",
            "stego/utils.py",
        }
        assert required <= members
        text_members = [
            name
            for name in members
            if name.endswith(".py") or name in {"README.txt", "requirements.txt"}
        ]
        for name in text_members:
            contents = archive.read(name)
            assert password.encode("utf-8") not in contents
            assert prng_key.encode("utf-8") not in contents
        archive.extractall(extracted_dir)

    credentials = iter((password, prng_key, password, prng_key))
    prompts = []

    def provide_credential(prompt):
        prompts.append(prompt)
        return next(credentials)

    monkeypatch.setattr("getpass.getpass", provide_credential)
    original_run = subprocess.run
    invocations = []

    def record_subprocess_arguments(arguments, **kwargs):
        invocations.append((arguments, kwargs))
        return original_run(arguments, **kwargs)

    monkeypatch.setattr(subprocess, "run", record_subprocess_arguments)
    monkeypatch.chdir(extracted_dir)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(extracted_dir / "run_decode.py"), run_name="__main__")

    assert exit_info.value.code == 0
    assert (extracted_dir / "decoded_output.bin").read_bytes() == payload

    with pytest.raises(SystemExit) as second_exit_info:
        runpy.run_path(str(extracted_dir / "run_decode.py"), run_name="__main__")

    assert second_exit_info.value.code == 0
    assert (extracted_dir / "decoded_output.bin").read_bytes() == payload
    assert (extracted_dir / "decoded_output-1.bin").read_bytes() == payload
    assert len(invocations) == 2
    assert prompts == [
        "Password (leave blank if none): ",
        "PRNG key: ",
        "Password (leave blank if none): ",
        "PRNG key: ",
    ]
    for arguments, options in invocations:
        assert "--credentials-stdin" in arguments
        assert password not in arguments
        assert prng_key not in arguments
        assert "--password" not in arguments
        assert "--prng-key" not in arguments
        assert json.loads(options["input"]) == {
            "password": password,
            "prng_key": prng_key,
        }
        assert options["text"] is True

    readme = (extracted_dir / "README.txt").read_text(encoding="utf-8")
    assert "Python" in readme
    assert "requirements.txt" in readme


def test_source_video_frame_decoder_requests_prng_key_without_exposing_it(
    tmp_path, monkeypatch
):
    password = "frame-decoder-password"
    prng_key = "frame-decoder-prng-key"
    carrier = tmp_path / "video.mkv"
    archive_path = tmp_path / "source decoder.zip"
    extracted_dir = tmp_path / "extracted"
    carrier.write_bytes(b"video frame carrier")

    create_portable_decoder(
        str(carrier),
        str(archive_path),
        method="lsb-prng",
        prng_key=prng_key,
        password=password,
        frame_index=2,
    )

    extracted_dir.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extracted_dir)

    prompts = []
    credentials = iter((password, prng_key))

    def provide_credential(prompt):
        prompts.append(prompt)
        return next(credentials)

    monkeypatch.setattr("getpass.getpass", provide_credential)
    invocations = []

    def record_subprocess_arguments(arguments, **kwargs):
        invocations.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", record_subprocess_arguments)
    monkeypatch.chdir(extracted_dir)

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(extracted_dir / "run_decode.py"), run_name="__main__")

    assert exit_info.value.code == 0
    assert prompts == ["Password (leave blank if none): ", "PRNG key: "]
    assert len(invocations) == 1
    arguments, options = invocations[0]
    assert "video-frame-decode" in arguments
    assert arguments[arguments.index("--frame") + 1] == "2"
    assert arguments[arguments.index("--method") + 1] == "lsb-prng"
    assert "--credentials-stdin" in arguments
    assert "--prng-key" not in arguments
    assert password not in arguments
    assert prng_key not in arguments
    assert json.loads(options["input"]) == {
        "password": password,
        "prng_key": prng_key,
    }


@pytest.mark.parametrize("extension", [".mp3", ".mkv", ".pdf"])
def test_source_decoder_requests_prng_key_only_for_pixel_modes(
    extension, tmp_path, monkeypatch
):
    carrier = tmp_path / f"carrier{extension}"
    archive_path = tmp_path / "source decoder.zip"
    extracted_dir = tmp_path / "extracted"
    carrier.write_bytes(b"metadata carrier")

    create_portable_decoder(
        str(carrier),
        str(archive_path),
        method="lsb-prng",
        prng_key="not-applicable",
        password=None,
        frame_index=None,
    )

    extracted_dir.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extracted_dir)

    prompts = []
    monkeypatch.setattr("getpass.getpass", lambda prompt: prompts.append(prompt) or "")
    invocations = []

    def record_subprocess_arguments(arguments, **kwargs):
        invocations.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", record_subprocess_arguments)
    monkeypatch.chdir(extracted_dir)

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(extracted_dir / "run_decode.py"), run_name="__main__")

    assert exit_info.value.code == 0
    assert prompts == ["Password (leave blank if none): "]
    assert len(invocations) == 1
    arguments, options = invocations[0]
    assert "--prng-key" not in arguments
    assert json.loads(options["input"]) == {"password": ""}


def test_portable_decoder_rejects_hard_link_to_carrier(tmp_path):
    carrier = tmp_path / "carrier.png"
    archive = tmp_path / "decoder.zip"
    carrier.write_bytes(b"preserve carrier bytes")
    try:
        os.link(carrier, archive)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable in this test directory: {exc}")
    original = carrier.read_bytes()

    with pytest.raises(ValueError, match="differ from its inputs and sources"):
        create_portable_decoder(
            str(carrier),
            str(archive),
            method=None,
            prng_key=None,
            password=None,
            frame_index=None,
        )

    assert carrier.read_bytes() == original


def test_payload_output_alias_check_allows_distinct_outputs_and_empty_sources(tmp_path):
    payload = tmp_path / "payload.bin"
    output = tmp_path / "output.png"
    payload.write_bytes(b"payload")

    ensure_output_differs_from_payloads(output, payload, None)


def test_payload_output_alias_check_rejects_hard_link(tmp_path):
    payload = tmp_path / "payload.bin"
    output = tmp_path / "output.bin"
    payload.write_bytes(b"preserve payload")
    try:
        os.link(payload, output)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable in this test directory: {exc}")

    with pytest.raises(ValueError, match="Payload input and output paths must differ"):
        ensure_output_differs_from_payloads(output, payload)

    assert payload.read_bytes() == b"preserve payload"
