"""Utility functions - QR codes, portable decoders, file associations."""

from __future__ import annotations

import zipfile
import os
from pathlib import Path

import qrcode

from .core import AUDIO_EXTS, MP4_CONTAINER_EXTS, VIDEO_EXTS


def read_bounded_file(
    path: str | Path, max_bytes: int, *, description: str = "Payload"
) -> bytes:
    """Read at most max_bytes, rejecting oversized files before and during I/O."""
    if max_bytes < 0:
        raise ValueError(f"{description} too large: exceeds the available capacity")

    source = Path(path)
    limit_message = (
        f"{description} too large: exceeds the {max_bytes:,}-byte input limit"
    )
    if source.stat().st_size > max_bytes:
        raise ValueError(limit_message)

    with source.open("rb") as payload_file:
        payload = payload_file.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(limit_message)
    return payload


def paths_refer_to_same_file(first_path: str | Path, second_path: str | Path) -> bool:
    """Detect lexical, symlink, and hard-link aliases, including new outputs."""
    first = Path(first_path)
    second = Path(second_path)
    try:
        if first.samefile(second):
            return True
    except (OSError, ValueError):
        pass

    try:
        return first.resolve(strict=False) == second.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return os.path.normcase(os.path.abspath(first)) == os.path.normcase(
            os.path.abspath(second)
        )


def ensure_output_differs_from_input(
    input_path: str | Path, output_path: str | Path, media_type: str
) -> None:
    """Refuse extraction outputs that could overwrite their carrier."""
    if paths_refer_to_same_file(input_path, output_path):
        raise ValueError(f"{media_type} input and output paths must differ")


def ensure_output_differs_from_payloads(
    output_path: str | Path, *payload_paths: str | Path | None
) -> None:
    """Refuse outputs that would replace a file used as an encoded payload."""
    for payload_path in payload_paths:
        if payload_path is not None:
            ensure_output_differs_from_input(payload_path, output_path, "Payload")


def generate_qr_code(text: str, output_path: str) -> None:
    """Generate QR code from text."""
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)


def create_portable_decoder(
    stego_path: str,
    output_zip: str,
    method: str | None,
    prng_key: str | None,
    password: str | None,
    frame_index: int | None,
) -> None:
    """Create a source-mode decoder archive without storing secret values."""
    carrier = Path(stego_path).resolve()
    archive_path = Path(output_zip).resolve()
    if not carrier.is_file():
        raise FileNotFoundError(f"Stego file not found: {carrier}")

    extension = carrier.suffix.lower()
    carrier_marker = "__CARRIER__"
    output_marker = "__OUTPUT__"
    requires_prng_key = method in {"lsb-prng", "lsb-match-prng"}
    if extension == ".png":
        arguments = ["decode", "--image", carrier_marker, "--out", output_marker]
        if method:
            arguments.extend(["--method", method])
    elif extension in AUDIO_EXTS:
        arguments = ["audio-decode", "--audio", carrier_marker, "--out", output_marker]
    elif extension in VIDEO_EXTS or extension in MP4_CONTAINER_EXTS:
        if frame_index is None:
            arguments = [
                "video-decode",
                "--video",
                carrier_marker,
                "--out",
                output_marker,
            ]
        else:
            if extension not in VIDEO_EXTS or frame_index < 0:
                raise ValueError(
                    "Frame decoding requires a video file and non-negative index"
                )
            arguments = [
                "video-frame-decode",
                "--video",
                carrier_marker,
                "--frame",
                str(frame_index),
                "--out",
                output_marker,
            ]
            if method:
                arguments.extend(["--method", method])
    elif extension == ".pdf":
        arguments = ["pdf-decode", "--pdf", carrier_marker, "--out", output_marker]
    else:
        raise ValueError("Unsupported stego file type for portable decoder")

    project_root = Path(__file__).resolve().parent.parent
    app_path = project_root / "app.py"
    requirements_path = project_root / "requirements.txt"
    package_root = project_root / "stego"
    package_sources = sorted(package_root.rglob("*.py"))
    project_files = {app_path.resolve(), requirements_path.resolve()}
    project_files.update(source.resolve() for source in package_sources)
    if any(
        paths_refer_to_same_file(archive_path, source)
        for source in {carrier, *project_files}
    ):
        raise ValueError(
            "Portable decoder output must differ from its inputs and sources"
        )

    launcher = f"""#!/usr/bin/env python3
from getpass import getpass
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
carrier = root / {carrier.name!r}
arguments = {arguments!r}
credentials = {{"password": getpass("Password (leave blank if none): ")}}
if {requires_prng_key!r}:
    prng_key = getpass("PRNG key: ")
    if not prng_key:
        raise SystemExit("A PRNG key is required for this carrier.")
    credentials["prng_key"] = prng_key

index = 0
while True:
    name = "decoded_output.bin" if index == 0 else f"decoded_output-{{index}}.bin"
    output = root / name
    try:
        with output.open("xb"):
            pass
    except FileExistsError:
        index += 1
        continue
    break

arguments = [
    str(carrier) if item == {carrier_marker!r}
    else str(output) if item == {output_marker!r}
    else item
    for item in arguments
]
arguments.append("--credentials-stdin")

try:
    result = subprocess.run(
        [sys.executable, str(root / "app.py"), *arguments],
        cwd=root,
        input=json.dumps(credentials),
        text=True,
        check=False,
    )
except BaseException:
    try:
        output.unlink()
    except FileNotFoundError:
        pass
    raise
if result.returncode == 0:
    print(f"Decoded output saved to: {{output}}")
else:
    try:
        output.unlink()
    except FileNotFoundError:
        pass
raise SystemExit(result.returncode)
"""
    readme = (
        "Source portable decoder\n"
        "=======================\n\n"
        "This archive contains the Python application source, its stego package, and the carrier.\n"
        "The convenience launcher requires Python and the listed dependencies. Install them with:\n\n"
        "    python -m pip install -r requirements.txt\n\n"
        "Then run `python run_decode.py` from this extracted folder. It prompts for an optional\n"
        "password and asks for a PRNG key when the selected method requires one. Secrets are not\n"
        "stored in this archive or passed as process arguments. Decoded data is written to a\n"
        "uniquely named decoded_output*.bin file so existing results are preserved.\n"
    )

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(app_path, arcname="app.py")
        bundle.write(requirements_path, arcname="requirements.txt")
        for source in package_sources:
            bundle.write(source, arcname=source.relative_to(project_root).as_posix())
        bundle.write(carrier, arcname=carrier.name)
        bundle.writestr("run_decode.py", launcher)
        bundle.writestr("README.txt", readme)


def create_windows_file_association(
    output_reg: str, app_path: str, python_path: str
) -> None:
    """Create Windows registry file for file association."""
    ext = ".stgimg"
    prog_id = "StegImageFile"
    command = f'"{python_path}" "{app_path}" decode --image "%1" --out "%1.decoded"'
    registry_command = command.replace("\\", "\\\\").replace('"', '\\"')
    content = (
        "Windows Registry Editor Version 5.00\n\n"
        f"[HKEY_CLASSES_ROOT\\{ext}]\n"
        f'@="{prog_id}"\n\n'
        f"[HKEY_CLASSES_ROOT\\{prog_id}]\n"
        '@="Steganography Image"\n\n'
        f"[HKEY_CLASSES_ROOT\\{prog_id}\\shell\\open\\command]\n"
        f'@="{registry_command}"\n'
    )
    Path(output_reg).write_text(content, encoding="utf-8")
