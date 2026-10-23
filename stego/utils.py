"""Utility functions - QR codes, portable decoders, file associations."""

from __future__ import annotations

import zipfile
from pathlib import Path

import qrcode

from .core import AUDIO_EXTS, VIDEO_EXTS


def generate_qr_code(text: str, output_path: str) -> None:
    """Generate QR code from text."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)


def create_portable_decoder(stego_path: str, output_zip: str, method: str | None,
                            prng_key: str | None, password: str | None, frame_index: int | None) -> None:
    """Create a portable decoder package with the stego file and decoding script."""
    stego_file = Path(stego_path)
    if not stego_file.exists():
        raise FileNotFoundError("Stego file not found")
    app_path = Path(__file__).resolve().parent.parent / "app.py"
    launcher = """#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

root = Path(__file__).parent
app = root / "app.py"
target = root / "{target_name}"
out = root / "decoded_output.bin"

cmd = [sys.executable, str(app)] + {args}
subprocess.run(cmd, check=False)
print(f"Decoded output saved to: {{out}}")
"""

    ext = stego_file.suffix.lower()
    if ext in (".png", ".jpg", ".jpeg", ".gif"):
        args = ["decode", "--image", str(target), "--out", str(out)]
        if method:
            args += ["--method", method]
        if prng_key:
            args += ["--prng-key", prng_key]
        if password:
            args += ["--password", password]
    elif ext in AUDIO_EXTS:
        args = ["audio-decode", "--audio", str(target), "--out", str(out)]
        if password:
            args += ["--password", password]
    elif ext in VIDEO_EXTS and frame_index is None:
        args = ["video-decode", "--video", str(target), "--out", str(out)]
        if password:
            args += ["--password", password]
    elif ext in VIDEO_EXTS and frame_index is not None:
        args = ["video-frame-decode", "--video", str(target), "--frame", str(frame_index), "--out", str(out)]
        if method:
            args += ["--method", method]
        if prng_key:
            args += ["--prng-key", prng_key]
        if password:
            args += ["--password", password]
    elif ext == ".pdf":
        args = ["pdf-decode", "--pdf", str(target), "--out", str(out)]
        if password:
            args += ["--password", password]
    else:
        raise ValueError("Unsupported stego file type for portable decoder")

    script = launcher.format(target_name=stego_file.name, args=repr(args))

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(app_path, arcname="app.py")
        zf.write(stego_file, arcname=stego_file.name)
        zf.writestr("run_decode.py", script)


def create_windows_file_association(output_reg: str, app_path: str, python_path: str) -> None:
    """Create Windows registry file for file association."""
    ext = ".stgimg"
    prog_id = "StegImageFile"
    command = f'"{python_path}" "{app_path}" decode --image "%1" --out "%1.decoded"'
    content = (
        "Windows Registry Editor Version 5.00\n\n"
        f"[HKEY_CLASSES_ROOT\\{ext}]\n"
        f"@=\"{prog_id}\"\n\n"
        f"[HKEY_CLASSES_ROOT\\{prog_id}]\n"
        "@=\"Steganography Image\"\n\n"
        f"[HKEY_CLASSES_ROOT\\{prog_id}\\shell\\open\\command]\n"
        f"@=\"{command}\"\n"
    )
    Path(output_reg).write_text(content, encoding="utf-8")
