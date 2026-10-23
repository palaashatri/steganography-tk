"""GUI implementation for Steganography Suite.

Native macOS/Windows/Linux interface using tk/ttk.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import subprocess
import sys
import threading
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable, Iterator, Optional, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import imageio.v2 as imageio
from mutagen import File as MutagenFile
from PIL import Image, ImageChops, ImageStat

# Add parent directory to path to find stego module (development mode only)
# PyInstaller bundles everything, so this is only needed when running from source
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).parent.parent))

# Core steganography operations imported from stego package
from stego import (
    AUDIO_EXTS,
    DEFAULT_NONCE_LEN,
    DEFAULT_SALT_LEN,
    FLAG_COMPRESSED,
    FLAG_ENCRYPTED,
    FLAG_LSB_MATCH,
    FLAG_PAYLOAD_IMAGE,
    FLAG_PRNG,
    MP4_CONTAINER_EXTS,
    VIDEO_EXTS,
    derive_key,
    estimate_stego_payload_size,
    extract_image_header,
    extract_stego_data_from_image,
    apply_metadata,
    image_capacity_bytes,
    load_image,
    parse_header,
    paths_refer_to_same_file,
)

from stego.detect import lsb_pair_chi_square
from stego.core import MAX_DECOMPRESSED_PAYLOAD_BYTES


IMAGE_FILE_EXTENSIONS = (".jpeg", ".jpg", ".png")
AUDIO_FILE_EXTENSIONS = tuple(sorted(AUDIO_EXTS | MP4_CONTAINER_EXTS))
VIDEO_FILE_EXTENSIONS = tuple(sorted(VIDEO_EXTS | MP4_CONTAINER_EXTS))
VIDEO_FRAME_FILE_EXTENSIONS = tuple(sorted(VIDEO_EXTS))
SUPPORTED_FILE_EXTENSIONS = tuple(
    sorted(
        set(IMAGE_FILE_EXTENSIONS)
        | set(AUDIO_FILE_EXTENSIONS)
        | set(VIDEO_FILE_EXTENSIONS)
        | {".pdf"}
    )
)
PORTABLE_DECODER_CREDENTIAL_NOTICE = (
    "Portable archives never store credentials. The decoder prompts for a password "
    "or PRNG key when needed."
)


def build_secret_command(
    command: Sequence[str],
    *,
    password: str | None = None,
    prng_key: str | None = None,
) -> tuple[list[str], str | None]:
    """Keep GUI credentials out of argv by sending JSON through subprocess stdin."""
    credentials = {}
    if password is not None:
        credentials["password"] = password
    if prng_key is not None:
        credentials["prng_key"] = prng_key
    if not credentials:
        return list(command), None
    if "--credentials-stdin" in command:
        raise ValueError("Credential transport flag is already present")
    return [*command, "--credentials-stdin"], json.dumps(
        credentials, ensure_ascii=True, separators=(",", ":")
    )


def build_image_decode_command(
    stego_path: str, output_path: str, method: str
) -> list[str]:
    """Build an image extraction command that always writes a binary-safe file."""
    if not stego_path:
        raise ValueError("Select a stego image.")
    if not output_path.strip():
        raise ValueError("Select an output file path for extracted data.")
    return build_cli_command(
        "decode", "--image", stego_path, "--out", output_path, "--method", method
    )


def payload_source_arguments(message: str, payload_file: str) -> list[str]:
    """Return exactly one message or file argument pair for an embed operation."""
    has_message = bool(message)
    has_file = bool(payload_file)
    if has_message and has_file:
        raise ValueError("Choose either a message or a payload file, not both.")
    if not has_message and not has_file:
        raise ValueError("Enter a message or select a payload file.")
    return ["--in-file", payload_file] if has_file else ["--message", message]


def compute_psnr(img_a: Image.Image, img_b: Image.Image) -> float:
    """Calculate RGB PSNR from per-sample mean squared error."""
    if img_a.size != img_b.size:
        raise ValueError("Images must have the same size for PSNR comparison.")
    diff = ImageChops.difference(img_a.convert("RGB"), img_b.convert("RGB"))
    mean_squared_error = sum(value * value for value in ImageStat.Stat(diff).rms) / 3
    if mean_squared_error == 0:
        return math.inf
    return 10 * math.log10((255**2) / mean_squared_error)


def load_encrypted_vault(path: str | Path, master_password: str) -> dict[str, str]:
    """Load a vault, returning an empty mapping only when no vault exists."""
    vault_path = Path(path)
    if not vault_path.exists():
        return {}
    data = json.loads(vault_path.read_text(encoding="utf-8"))
    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    key = derive_key(master_password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, b"vault")
    payload = json.loads(plaintext.decode("utf-8"))
    if not isinstance(payload, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in payload.items()
    ):
        raise ValueError("Vault contents must map key names to string values")
    return payload


_VAULT_THREAD_LOCK = threading.RLock()


@contextmanager
def _lock_encrypted_vault(path: Path) -> Iterator[None]:
    """Serialize vault updates across threads and application processes."""
    lock_path = path.resolve(strict=False).with_name(f".{path.name}.lock")
    with _VAULT_THREAD_LOCK, lock_path.open("a+b") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            return

        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _write_encrypted_vault(
    vault_path: Path,
    master_password: str,
    payload: dict[str, str],
    original: bytes | None,
) -> None:
    salt = os.urandom(DEFAULT_SALT_LEN)
    nonce = os.urandom(DEFAULT_NONCE_LEN)
    key = derive_key(master_password, salt)
    ciphertext = AESGCM(key).encrypt(
        nonce, json.dumps(payload, ensure_ascii=False).encode("utf-8"), b"vault"
    )
    data = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    serialized = json.dumps(data, indent=2).encode("utf-8")
    if original is None:
        # Exclusive creation prevents an uncoordinated writer from being clobbered.
        with vault_path.open("xb") as vault_file:
            vault_file.write(serialized)
        return
    if vault_path.read_bytes() != original:
        raise RuntimeError(
            "Vault changed while it was being saved; no update was written"
        )
    temporary_path = vault_path.with_name(
        f".{vault_path.name}.{os.urandom(8).hex()}.tmp"
    )
    try:
        with temporary_path.open("xb") as temporary_file:
            temporary_file.write(serialized)
        os.replace(temporary_path, vault_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def save_encrypted_vault(
    path: str | Path, master_password: str, payload: dict[str, str]
) -> None:
    """Merge key updates after authenticating the latest vault contents."""
    if not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in payload.items()
    ):
        raise ValueError("Vault contents must map key names to string values")

    vault_path = Path(path).resolve(strict=False)
    with _lock_encrypted_vault(vault_path):
        original = vault_path.read_bytes() if vault_path.exists() else None
        existing = (
            load_encrypted_vault(vault_path, master_password)
            if original is not None
            else {}
        )
        existing.update(payload)
        _write_encrypted_vault(vault_path, master_password, existing, original)


def _sanitize_plaintext_templates(
    templates: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    """Drop credentials from plaintext template settings, including legacy fields."""
    return {
        name: {
            key: value
            for key, value in settings.items()
            if key not in {"prng_key", "password"}
        }
        for name, settings in templates.items()
        if isinstance(settings, dict)
    }


def load_plaintext_templates(path: str | Path) -> dict[str, dict[str, str]]:
    template_path = Path(path)
    if not template_path.exists():
        return {}
    templates = json.loads(template_path.read_text(encoding="utf-8"))
    if not isinstance(templates, dict):
        raise ValueError("Templates must be a JSON object")
    sanitized = _sanitize_plaintext_templates(templates)
    if sanitized != templates:
        save_plaintext_templates(template_path, sanitized)
    return sanitized


def save_plaintext_templates(
    path: str | Path, templates: dict[str, dict[str, str]]
) -> None:
    template_path = Path(path)
    sanitized = _sanitize_plaintext_templates(templates)
    template_path.write_text(json.dumps(sanitized, indent=2), encoding="utf-8")


def template_values_for_load(settings: dict[str, str]) -> dict[str, str | bool]:
    """Load non-secret template options and always clear any legacy key field."""
    return {
        "method": settings.get("method", "lsb"),
        "prng_key": "",
        "compress": settings.get("compress", "False") == "True",
    }


def get_quick_help_text() -> str:
    return """Steganography Suite - Quick Help

Keyboard Shortcuts:
  Ctrl+O: Open file
  Ctrl+S: Quick save
  Ctrl+H: View history
  Ctrl+,: Settings
  F1: Help

Workflow:
1. Hide Data: Embed data in image pixels or video frames
2. Reveal Data: Extract data from supported files
3. Audio, video, and PDF modes store data in visible metadata, not steganography;
   payload presence is visible, and contents are readable unless password encryption is used
4. Batch Operations: Process multiple images at once
5. Analysis & Tools: Analyze images and look for steganography indicators

Tips:
- Use PNG format for image output to preserve pixel data
- Enable encryption for sensitive data
- PRNG methods randomize pixel selection and require a key
- Check capacity before embedding large files
"""


def run_gui_self_check() -> None:
    """Import packaged runtime dependencies and initialize Tcl without opening Tk."""
    import importlib

    modules = (
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "PIL.ImageTk",
        "PIL.ImageSequence",
        "mutagen.id3",
        "mutagen.mp4",
        "PyPDF2",
        "imageio.v2",
        "imageio_ffmpeg",
        "stego",
    )
    for module in modules:
        importlib.import_module(module)
    import tkinter

    interpreter = tkinter.Tcl()
    interpreter.call("info", "patchlevel")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the noninteractive package smoke check or start the desktop UI."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--self-check"]:
        run_gui_self_check()
        output = getattr(sys, "stdout", None)
        if output is not None:
            output.write("GUI self-check passed\n")
        return 0
    if arguments:
        raise SystemExit("Usage: stego-gui [--self-check]")
    gui_main()
    return 0


def _tk_file_patterns(extensions: tuple[str, ...]) -> str:
    return " ".join(f"*{extension}" for extension in extensions)


def _media_filetypes(label: str, extensions: tuple[str, ...]) -> list[tuple[str, str]]:
    return [(f"{label} files", _tk_file_patterns(extensions)), ("All Files", "*.*")]


@dataclass(frozen=True)
class ImageCapacityEstimate:
    available_bytes: int
    required_bytes: int
    fits: bool


@dataclass(frozen=True)
class ImageCapacityRequest:
    cover_path: str
    payload_file_path: str
    message: str
    password: str | None
    compress: bool
    comment: str | None
    expires: str | None


def packaged_cli_path(
    executable_path: str | Path | None = None,
    platform: str | None = None,
) -> Path:
    """Resolve the standalone CLI beside a frozen GUI executable or app bundle."""
    executable = Path(executable_path or sys.executable).resolve()
    runtime_platform = platform or sys.platform
    cli_name = "stego-cli.exe" if runtime_platform == "win32" else "stego-cli"
    app_bundle = next(
        (parent for parent in executable.parents if parent.suffix.lower() == ".app"),
        None,
    )
    if app_bundle is not None:
        return app_bundle.parent / cli_name
    return executable.with_name(cli_name)


def build_cli_command(*arguments: str) -> list[str]:
    """Build a shell-free source or frozen CLI command."""
    if getattr(sys, "frozen", False):
        return [str(packaged_cli_path()), *arguments]
    app_path = Path(__file__).resolve().parent.parent / "app.py"
    return [sys.executable, str(app_path), *arguments]


def build_qr_command(text: str, output_path: str) -> list[str]:
    return build_cli_command("qr", "--text", text, "--out", output_path)


def build_portable_decoder_command(
    stego_path: str,
    output_path: str,
    *,
    method: str | None = None,
    prng_key: str | None = None,
    password: str | None = None,
    frame: int | str | None = None,
) -> list[str]:
    """Build an archive command; the runtime launcher collects credentials."""
    if getattr(sys, "frozen", False):
        raise RuntimeError(
            "Frozen builds must package the sibling CLI with build_portable_decoder_action"
        )
    command = build_cli_command(
        "portable-decoder", "--stego", stego_path, "--out", output_path
    )
    if method:
        command.extend(["--method", method])
    if frame not in (None, ""):
        command.extend(["--frame", str(frame)])
    return command


def build_file_association_command(output_path: str) -> list[str]:
    if getattr(sys, "frozen", False):
        raise RuntimeError(
            "Frozen builds must create registry content for the packaged CLI"
        )
    app_path = Path(__file__).resolve().parent.parent / "app.py"
    return build_cli_command(
        "file-assoc",
        "--out",
        output_path,
        "--app-path",
        str(app_path),
        "--python-path",
        sys.executable,
    )


def build_metadata_encode_command(
    media_type: str,
    input_path: str,
    output_path: str,
    *,
    message: str | None = None,
    payload_file: str | None = None,
    password: str | None = None,
    compress: bool = False,
    comment: str | None = None,
    expires: str | None = None,
) -> list[str]:
    """Build a metadata encoder command; pass password separately to subprocess stdin."""
    if media_type not in {"audio", "video", "pdf"}:
        raise ValueError(f"Unsupported metadata carrier: {media_type}")
    source_flag = "--pdf" if media_type == "pdf" else f"--{media_type}"
    command = build_cli_command(
        f"{media_type}-encode", source_flag, input_path, "--out", output_path
    )
    command.extend(payload_source_arguments(message or "", payload_file or ""))
    if compress:
        command.append("--compress")
    if comment:
        command.extend(["--comment", comment])
    if expires:
        command.extend(["--expires", expires])
    return command


def build_metadata_decode_command(
    media_type: str,
    input_path: str,
    output_path: str,
    *,
    password: str | None = None,
) -> list[str]:
    """Build a metadata decoder command; pass password separately to subprocess stdin."""
    if media_type not in {"audio", "video", "pdf"}:
        raise ValueError(f"Unsupported metadata carrier: {media_type}")
    source_flag = "--pdf" if media_type == "pdf" else f"--{media_type}"
    command = build_cli_command(
        f"{media_type}-decode", source_flag, input_path, "--out", output_path
    )
    return command


def build_frozen_portable_decoder(
    stego_path: str | Path,
    output_zip: str | Path,
    *,
    cli_path: str | Path,
    method: str | None = None,
    prng_key: str | None = None,
    password: str | None = None,
    frame: int | None = None,
) -> None:
    """Package a frozen CLI beside a carrier and a small decoder launcher."""
    carrier_path = Path(stego_path).resolve()
    cli_executable = Path(cli_path).resolve()
    archive_path = Path(output_zip)
    if not carrier_path.is_file():
        raise FileNotFoundError(f"Stego file not found: {carrier_path}")
    if not cli_executable.is_file():
        raise FileNotFoundError(f"Packaged CLI not found: {cli_executable}")
    if paths_refer_to_same_file(archive_path, carrier_path) or paths_refer_to_same_file(
        archive_path, cli_executable
    ):
        raise ValueError("Portable decoder output must differ from its input files")

    carrier_token = object()
    output_token = object()
    requires_prng_key = False
    extension = carrier_path.suffix.lower()
    if extension == ".png":
        command_parts: list[object] = [
            "decode",
            "--image",
            carrier_token,
            "--out",
            output_token,
        ]
        if method:
            command_parts.extend(["--method", method])
        if method in {"lsb-prng", "lsb-match-prng"}:
            requires_prng_key = True
    elif extension in AUDIO_EXTS:
        command_parts = [
            "audio-decode",
            "--audio",
            carrier_token,
            "--out",
            output_token,
        ]
    elif extension in VIDEO_EXTS or extension in MP4_CONTAINER_EXTS:
        if frame is None:
            command_parts = [
                "video-decode",
                "--video",
                carrier_token,
                "--out",
                output_token,
            ]
        else:
            if extension not in VIDEO_FRAME_FILE_EXTENSIONS or frame < 0:
                raise ValueError(
                    "Frame decoding requires a video file and non-negative index"
                )
            command_parts = [
                "video-frame-decode",
                "--video",
                carrier_token,
                "--frame",
                str(frame),
                "--out",
                output_token,
            ]
            if method:
                command_parts.extend(["--method", method])
            if method in {"lsb-prng", "lsb-match-prng"}:
                requires_prng_key = True
    elif extension == ".pdf":
        command_parts = ["pdf-decode", "--pdf", carrier_token, "--out", output_token]
    else:
        raise ValueError(
            f"Unsupported stego file type: {extension or '(no extension)'}"
        )

    command_expression = ", ".join(
        "str(target)"
        if part is carrier_token
        else "str(output)"
        if part is output_token
        else repr(part)
        for part in command_parts
    )
    cli_name = cli_executable.name
    carrier_name = carrier_path.name
    runner = (
        "from getpass import getpass\n"
        "import json\n"
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n\n"
        "root = Path(__file__).resolve().parent\n"
        f"cli = root / {cli_name!r}\n"
        f"target = root / {carrier_name!r}\n"
        "credentials = {'password': getpass('Password (leave blank if none): ')}\n"
        + (
            "prng_key = getpass('PRNG key: ')\n"
            "if not prng_key:\n"
            "    raise SystemExit('A PRNG key is required for this carrier.')\n"
            "credentials['prng_key'] = prng_key\n"
            if requires_prng_key
            else ""
        )
        + "index = 0\n"
        "while True:\n"
        "    name = 'decoded_output.bin' if index == 0 else f'decoded_output-{index}.bin'\n"
        "    output = root / name\n"
        "    try:\n"
        "        with output.open('xb'):\n"
        "            pass\n"
        "    except FileExistsError:\n"
        "        index += 1\n"
        "        continue\n"
        "    break\n"
        f"arguments = [{command_expression}]\n"
        "arguments.append('--credentials-stdin')\n"
        "try:\n"
        "    result = subprocess.run(\n"
        "        [str(cli), *arguments], input=json.dumps(credentials), text=True, check=False\n"
        "    )\n"
        "except BaseException:\n"
        "    try:\n"
        "        output.unlink()\n"
        "    except FileNotFoundError:\n"
        "        pass\n"
        "    raise\n"
        "if result.returncode == 0:\n"
        "    print(f'Decoded output saved to: {output}')\n"
        "else:\n"
        "    try:\n"
        "        output.unlink()\n"
        "    except FileNotFoundError:\n"
        "        pass\n"
        "raise SystemExit(result.returncode)\n"
    )
    readme = (
        "Frozen portable decoder\n"
        "=======================\n\n"
        f"This archive includes the standalone {cli_name} binary and the carrier. The binary is\n"
        "self-contained and does not need Python or package dependencies. The optional\n"
        "`run_decode.py` convenience launcher prompts for credentials and invokes that binary;\n"
        "running the launcher itself requires Python. Secrets are not stored in this archive or\n"
        "passed as process arguments. Decoded data is written to a uniquely named\n"
        "decoded_output*.bin file so existing results are preserved.\n"
    )
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(cli_executable, arcname=cli_name)
        bundle.write(carrier_path, arcname=carrier_name)
        bundle.writestr("run_decode.py", runner)
        bundle.writestr("README.txt", readme)


def build_frozen_file_association_registry(cli_path: str | Path) -> str:
    """Build a Windows registry file that invokes the packaged CLI directly."""
    cli = str(Path(cli_path))
    command = f'"{cli}" decode --image "%1" --out "%1.decoded"'
    registry_command = command.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_CLASSES_ROOT\\.stgimg]\n"
        '@="StegImageFile"\n\n'
        "[HKEY_CLASSES_ROOT\\StegImageFile]\n"
        '@="Steganography Image"\n\n'
        "[HKEY_CLASSES_ROOT\\StegImageFile\\shell\\open\\command]\n"
        f'@="{registry_command}"\n'
    )


def build_portable_decoder_action(
    stego_path: str,
    output_path: str,
    *,
    frozen: bool | None = None,
    cli_path: str | Path | None = None,
    method: str | None = None,
    prng_key: str | None = None,
    password: str | None = None,
    frame: int | str | None = None,
) -> list[str] | None:
    """Build a source command or create a frozen decoder archive directly."""
    use_frozen_cli = getattr(sys, "frozen", False) if frozen is None else frozen
    if not use_frozen_cli:
        return build_portable_decoder_command(
            stego_path,
            output_path,
            method=method,
            frame=frame,
        )

    parsed_frame = None if frame in (None, "") else int(frame)
    if parsed_frame is not None and parsed_frame < 0:
        raise ValueError("Video frame index must be non-negative")
    build_frozen_portable_decoder(
        stego_path,
        output_path,
        cli_path=cli_path or packaged_cli_path(),
        method=method,
        frame=parsed_frame,
    )
    return None


def build_file_association_action(
    output_path: str,
    *,
    frozen: bool | None = None,
    cli_path: str | Path | None = None,
) -> list[str] | str:
    """Build a source CLI command or frozen registry content for the packaged CLI."""
    use_frozen_cli = getattr(sys, "frozen", False) if frozen is None else frozen
    if use_frozen_cli:
        return build_frozen_file_association_registry(cli_path or packaged_cli_path())
    return build_file_association_command(output_path)


def estimate_image_capacity(
    image: Image.Image,
    plaintext: bytes,
    *,
    password: str | None,
    compress: bool,
    comment: str | None,
    expires: str | None,
) -> ImageCapacityEstimate:
    """Compare the exact envelope estimate with available RGB LSB bytes."""
    metadata = None
    if comment or expires:
        metadata = {"comment": comment or "", "expires": expires or ""}
    available_bytes = image_capacity_bytes(image)
    required_bytes = estimate_stego_payload_size(
        plaintext,
        encrypted=bool(password),
        compress=compress,
        metadata=metadata,
    )
    return ImageCapacityEstimate(
        available_bytes=available_bytes,
        required_bytes=required_bytes,
        fits=required_bytes <= available_bytes,
    )


def estimate_image_capacity_message(request: ImageCapacityRequest) -> str:
    """Read inputs and compute the capacity display message off the Tk thread."""
    payload_path = (
        Path(request.payload_file_path) if request.payload_file_path else None
    )
    if payload_path is not None and not payload_path.is_file():
        raise ValueError(f"Payload path is not a file: {payload_path}")

    metadata = None
    if request.comment or request.expires:
        metadata = {"comment": request.comment or "", "expires": request.expires or ""}
    metadata_overhead = len(apply_metadata(b"", metadata)[0])

    with Image.open(request.cover_path) as cover_image:
        if payload_path is not None and not request.compress:
            payload_size = payload_path.stat().st_size
            encrypted = bool(request.password)
            required_bytes = (
                12
                + (DEFAULT_SALT_LEN + DEFAULT_NONCE_LEN if encrypted else 0)
                + payload_size
                + metadata_overhead
                + (16 if encrypted else 0)
            )
            available_bytes = image_capacity_bytes(cover_image)
            estimate = ImageCapacityEstimate(
                available_bytes=available_bytes,
                required_bytes=required_bytes,
                fits=required_bytes <= available_bytes,
            )
        else:
            if payload_path is not None:
                max_payload_size = MAX_DECOMPRESSED_PAYLOAD_BYTES - metadata_overhead
                if max_payload_size < 0:
                    raise ValueError("Metadata exceeds the compressed payload limit")
                if payload_path.stat().st_size > max_payload_size:
                    raise ValueError(
                        "Payload exceeds the 64 MiB compressed payload limit"
                    )
                with payload_path.open("rb") as payload_file:
                    payload = payload_file.read(max_payload_size + 1)
                if len(payload) > max_payload_size:
                    raise ValueError(
                        "Payload exceeds the 64 MiB compressed payload limit"
                    )
            else:
                payload = request.message.encode("utf-8")
                if (
                    request.compress
                    and len(payload) + metadata_overhead
                    > MAX_DECOMPRESSED_PAYLOAD_BYTES
                ):
                    raise ValueError(
                        "Payload exceeds the 64 MiB compressed payload limit"
                    )
            estimate = estimate_image_capacity(
                cover_image,
                payload,
                password=request.password,
                compress=request.compress,
                comment=request.comment,
                expires=request.expires,
            )
    status = "fits" if estimate.fits else "exceeds capacity"
    return (
        "Estimated encoded envelope: "
        f"{format_capacity_bytes(estimate.required_bytes)} / "
        "RGB LSB capacity: "
        f"{format_capacity_bytes(estimate.available_bytes)} ({status})"
    )


class AsyncImageCapacityEstimator:
    """Debounce capacity requests and publish only the newest worker result."""

    def __init__(
        self,
        root: Any,
        publish: Callable[[str], None],
        *,
        compute: Callable[
            [ImageCapacityRequest], str
        ] = estimate_image_capacity_message,
        thread_factory: Callable[..., Any] = threading.Thread,
        debounce_ms: int = 150,
    ) -> None:
        self.root = root
        self.publish = publish
        self.compute = compute
        self.thread_factory = thread_factory
        self.debounce_ms = debounce_ms
        self._generation = 0
        self._pending_after_id: Any | None = None
        self._poll_after_id: Any | None = None
        self._active_worker = False
        self._pending_snapshot: tuple[int, ImageCapacityRequest] | None = None
        self._results: Queue[tuple[int, str]] = Queue()

    def request(self, snapshot: ImageCapacityRequest) -> int:
        self._generation += 1
        generation = self._generation
        if self._pending_after_id is not None:
            self.root.after_cancel(self._pending_after_id)
        self._pending_after_id = self.root.after(
            self.debounce_ms, self._start_worker, generation, snapshot
        )
        return generation

    def invalidate(self) -> None:
        """Invalidate pending and running work after the cover is cleared."""
        self._generation += 1
        if self._pending_after_id is not None:
            self.root.after_cancel(self._pending_after_id)
            self._pending_after_id = None
        self._pending_snapshot = None

    def _start_worker(self, generation: int, snapshot: ImageCapacityRequest) -> None:
        if generation != self._generation:
            return
        self._pending_after_id = None
        if self._active_worker:
            self._pending_snapshot = (generation, snapshot)
            return
        self._active_worker = True
        if self._poll_after_id is None:
            self._poll_after_id = self.root.after(25, self._poll_results)
        self.thread_factory(
            target=lambda: self._compute_and_publish(generation, snapshot),
            daemon=True,
        ).start()

    def _compute_and_publish(
        self, generation: int, snapshot: ImageCapacityRequest
    ) -> None:
        try:
            result = self.compute(snapshot)
        except Exception as exc:
            result = f"Capacity estimate unavailable: {exc}"
        self._results.put((generation, result))

    def _poll_results(self) -> None:
        """Drain worker results on Tk's main thread and ignore stale snapshots."""
        self._poll_after_id = None
        while True:
            try:
                generation, result = self._results.get_nowait()
            except Empty:
                break
            self._active_worker = False
            if generation == self._generation:
                self.publish(result)
        pending = self._pending_snapshot
        self._pending_snapshot = None
        if pending is not None and pending[0] == self._generation:
            self._start_worker(*pending)
        elif self._active_worker:
            self._poll_after_id = self.root.after(25, self._poll_results)


def format_capacity_bytes(value: int) -> str:
    """Format a byte count for capacity feedback."""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def plan_batch_output_paths(
    files: Sequence[str], output_dir: str, operation: str
) -> list[Path]:
    """Return deterministic, distinct output paths that preserve prior files."""
    suffixes = {"encode": ("_stego", ".png"), "decode": ("_decoded", ".bin")}
    if operation not in suffixes:
        raise ValueError(f"Unsupported batch operation: {operation}")
    root = Path(output_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"Batch output folder not found: {root}")

    outputs: list[Path] = []
    reserved: set[str] = set()
    suffix, extension = suffixes[operation]
    for source in files:
        base = f"{Path(source).stem}{suffix}"
        candidate = root / f"{base}{extension}"
        sequence = 2
        while True:
            key = str(candidate.resolve()).casefold()
            if key not in reserved and not candidate.exists():
                reserved.add(key)
                outputs.append(candidate)
                break
            candidate = root / f"{base}_{sequence}{extension}"
            sequence += 1
    return outputs


def run_batch_commands(
    commands: Sequence[Sequence[str]],
    *,
    credential_inputs: Sequence[str | None] | None = None,
    runner: Callable[..., Any] = subprocess.run,
    timeout: int = 600,
    on_progress: Callable[[int, int], None] | None = None,
    on_finished: Callable[[Exception | None], None] | None = None,
    destinations: Sequence[Path] | None = None,
) -> Exception | None:
    """Run a batch with timeouts and an unconditional finish callback."""
    error: Exception | None = None
    try:
        if credential_inputs is not None and len(credential_inputs) != len(commands):
            raise ValueError("Each batch command must have one credential input")
        if destinations is not None and len(destinations) != len(commands):
            raise ValueError("Each batch command must have one destination")
        total = len(commands)
        for index, command in enumerate(commands, start=1):
            if destinations is not None and destinations[index - 1].exists():
                raise FileExistsError(
                    f"Batch output already exists: {destinations[index - 1]}"
                )
            run_options: dict[str, Any] = {
                "capture_output": True,
                "text": True,
                "timeout": timeout,
            }
            if credential_inputs is not None:
                credential_input = credential_inputs[index - 1]
                if credential_input is not None:
                    run_options["input"] = credential_input
            result = runner(list(command), **run_options)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                raise RuntimeError(detail or f"Command exited with {result.returncode}")
            if on_progress is not None:
                on_progress(index, total)
    except Exception as exc:
        error = exc
    finally:
        if on_finished is not None:
            on_finished(error)

    if error is not None and on_finished is None:
        raise error
    return error


def normalize_dnd_files(
    data: str | tuple[str, ...] | list[str], widget: Any
) -> list[str]:
    """Parse dropped paths from Tk's Tcl string or converted list result."""
    if not data:
        return []
    if isinstance(data, (tuple, list)):
        return [str(path) for path in data]
    return list(widget.tk.splitlist(data))


def handle_dnd_drop(data: str, widget: Any, variable: Any) -> list[str]:
    """Set a file control to the first path in a Tk drop event."""
    files = normalize_dnd_files(data, widget)
    if files:
        variable.set(files[0])
    return files


def format_pair_chi_square_feedback(statistic: float) -> str:
    return (
        f"Pair-values chi-square (heuristic): {statistic:.2f}. "
        "Pair-value balancing can be consistent with LSB replacement, but this "
        "heuristic does not prove whether hidden data is present and cannot "
        "guarantee undetectability."
    )


def build_image_encode_success_message(output_path: str | Path) -> str:
    """Create the success text and heuristic self-check for an encoded PNG."""
    with Image.open(output_path) as encoded_image:
        statistic = lsb_pair_chi_square(encoded_image)
    return f"Saved PNG: {output_path}\n\n{format_pair_chi_square_feedback(statistic)}"


def get_audio_preview_text(path: str | Path) -> str:
    """Return display text from Mutagen's file-type-detecting API."""
    audio = MutagenFile(path)
    info = getattr(audio, "info", None) if audio else None
    length = getattr(info, "length", None)
    bitrate = getattr(info, "bitrate", None)
    duration = f"{length:.1f}s" if length else "Unknown length"
    rate = f"{bitrate // 1000} kbps" if bitrate else ""
    return f"{Path(path).name}\n{duration} {rate}".strip()


def load_video_preview_frame(path: str | Path) -> Image.Image:
    """Read and detach the first video frame for the Tk preview."""
    reader = imageio.get_reader(str(path))
    try:
        return Image.fromarray(reader.get_data(0)).copy()
    finally:
        reader.close()


def metadata_storage_notice(media_type: str) -> str:
    return (
        f"{media_type} data is stored in visible metadata, not steganography. "
        "Anyone inspecting the metadata can see that a payload is stored. Payload "
        "contents are readable unless AES-GCM encryption was enabled with a password."
    )


def _create_tk_root(tk_module: Any, dnd_module: Any | None) -> tuple[Any, bool]:
    """Create one Tk root and enable tkdnd on that same window when available."""
    root = tk_module.Tk()
    if dnd_module is None:
        return root, False
    try:
        dnd_module.require(root)
    except Exception:
        return root, False
    return root, True


def gui_main() -> None:
    # Import tkinter here to avoid module-level initialization
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from PIL import ImageChops, ImageSequence, ImageTk
    from mutagen.id3 import ID3
    from mutagen.mp4 import MP4
    from PyPDF2 import PdfReader

    # Try to import tkinterdnd2
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD

        dnd_available = True
    except (ImportError, RuntimeError, Exception):
        dnd_available = False
        DND_FILES = None
        TkinterDnD = None

    # Spacing constants - 4px grid system
    PADDING_SMALL = 8
    PADDING_MEDIUM = 12
    PADDING_LARGE = 16
    BUTTON_WIDTH = 12
    BUTTON_WIDTH_LARGE = 16

    class PlaceholderEntry(ttk.Entry):
        """Entry widget with placeholder text support."""

        def __init__(self, parent, placeholder="", **kwargs):
            # Extract textvariable if provided
            self._string_var = kwargs.pop("textvariable", None)
            super().__init__(parent, **kwargs)
            self.placeholder = placeholder
            self.placeholder_color = "#999999"
            # Use platform-appropriate default text color
            if sys.platform == "win32":
                self.default_color = "SystemWindowText"
            else:
                self.default_color = "black"
            self._has_placeholder = False
            self._ignore_trace = False

            # Set up trace on the variable if provided
            if self._string_var:
                self._string_var.trace_add("write", self._on_var_changed)

            if placeholder:
                self._show_placeholder()

            self.bind("<FocusIn>", self._on_focus_in)
            self.bind("<FocusOut>", self._on_focus_out)
            self.bind("<KeyRelease>", self._on_key_release)

        def _on_var_changed(self, *args):
            """Handle external changes to the StringVar."""
            if not self._ignore_trace and self._string_var:
                value = self._string_var.get()
                if not value and not self._has_placeholder:
                    self._show_placeholder()

        def _on_key_release(self, *args):
            """Update StringVar when user types (without placeholder)."""
            if not self._has_placeholder and self._string_var:
                self._ignore_trace = True
                self._string_var.set(self.get())
                self._ignore_trace = False

        def _show_placeholder(self, *args):
            if not self.get():
                self._has_placeholder = True
                self.insert(0, self.placeholder)
                self.config(foreground=self.placeholder_color)
                # Don't set placeholder in the StringVar
                if self._string_var:
                    self._ignore_trace = True
                    self._string_var.set("")
                    self._ignore_trace = False

        def _on_focus_in(self, *args):
            if self._has_placeholder:
                self.delete(0, tk.END)
                self.config(foreground=self.default_color)
                self._has_placeholder = False

        def _on_focus_out(self, *args):
            # Update StringVar with actual value
            if not self._has_placeholder and self._string_var:
                self._ignore_trace = True
                self._string_var.set(self.get())
                self._ignore_trace = False

            if not self.get():
                self._show_placeholder()

        def get_value(self):
            """Get the actual value, returning empty string if showing placeholder."""
            if self._has_placeholder:
                return ""
            return self.get()

    class PasswordEntry(ttk.Frame):
        """Password entry with show/hide toggle."""

        def __init__(self, parent, textvariable=None, **kwargs):
            super().__init__(parent)
            self.var = textvariable or tk.StringVar(master=parent)
            self.showing = False

            self.entry = ttk.Entry(self, textvariable=self.var, show="●", **kwargs)
            self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

            self.toggle_btn = ttk.Button(
                self, text="👁", width=3, command=self._toggle_visibility
            )
            self.toggle_btn.pack(side=tk.LEFT, padx=(4, 0))

        def _toggle_visibility(self):
            self.showing = not self.showing
            self.entry.config(show="" if self.showing else "●")
            self.toggle_btn.config(text="👁" if not self.showing else "✕")

    class CapacityCalculator:
        @staticmethod
        def image_lsb_capacity(path: str) -> int:
            try:
                with Image.open(path) as image:
                    return image_capacity_bytes(image.convert("RGB"))
            except (OSError, ValueError):
                return 0

        @staticmethod
        def format_bytes(value: int) -> str:
            return format_capacity_bytes(value)

    class PasswordValidator:
        @staticmethod
        def check_strength(password: str) -> tuple[str, str]:
            if not password:
                return ("none", "No password")

            score = 0
            if len(password) >= 12:
                score += 1
            if len(password) >= 20:
                score += 1
            if any(c.isupper() for c in password):
                score += 1
            if any(c.islower() for c in password):
                score += 1
            if any(c.isdigit() for c in password):
                score += 1
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                score += 1

            levels = {
                0: ("none", "No password"),
                1: ("weak", "Weak"),
                2: ("fair", "Fair"),
                3: ("good", "Good"),
                4: ("strong", "Strong"),
                5: ("strong", "Strong"),
                6: ("very_strong", "Very Strong"),
            }
            return levels.get(score, ("very_strong", "Very Strong"))

    class Tooltip:
        def __init__(self, widget: tk.Widget, text: str):
            self.widget = widget
            self.text = text
            self.tip: Optional[tk.Toplevel] = None
            widget.bind("<Enter>", self.show)
            widget.bind("<Leave>", self.hide)

        def show(self, _event=None):
            if self.tip or not self.text:
                return
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 10
            self.tip = tip = tk.Toplevel(self.widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{x}+{y}")
            # Tooltips always use a light background for readability
            tip.configure(bg="#f0f0f0")
            label = tk.Label(
                tip,
                text=self.text,
                bg="#f0f0f0",
                fg="#000000",
                padx=8,
                pady=4,
                relief=tk.SOLID,
                borderwidth=1,
            )
            label.pack()

        def hide(self, _event=None):
            if self.tip:
                self.tip.destroy()
                self.tip = None

    @dataclass
    class HistoryItem:
        timestamp: str
        action: str
        status: str
        details: str

    class StatusBar(ttk.Frame):
        def __init__(self, parent: tk.Widget):
            super().__init__(parent, relief=tk.RAISED, borderwidth=1)
            self.message = ttk.Label(self, text="Ready", font=("TkDefaultFont", 9))
            self.message.pack(side=tk.LEFT, padx=(PADDING_MEDIUM, PADDING_MEDIUM))

            ttk.Separator(self, orient=tk.VERTICAL).pack(
                side=tk.RIGHT, fill=tk.Y, padx=4
            )

            self.time_label = ttk.Label(self, text="", font=("TkDefaultFont", 9))
            self.time_label.pack(side=tk.RIGHT, padx=(0, PADDING_SMALL))

            self.progress = ttk.Progressbar(self, mode="indeterminate", length=200)
            self.progress.pack(side=tk.RIGHT, padx=PADDING_SMALL, pady=2)

            self.start_time = None

        def set_status(self, text: str, status_type: str = "info") -> None:
            """Set status with optional type (info/success/error/warning)."""
            prefix = ""
            if status_type == "success":
                prefix = "✓ "
            elif status_type == "error":
                prefix = "✗ "
            elif status_type == "warning":
                prefix = "⚠ "
            self.message.config(text=prefix + text)

        def start(self) -> None:
            self.progress.start(10)
            self.start_time = time.time()
            self._update_elapsed()

        def stop(self) -> None:
            self.progress.stop()
            self.start_time = None
            self.time_label.config(text="")

        def _update_elapsed(self):
            if self.start_time:
                elapsed = int(time.time() - self.start_time)
                mins, secs = divmod(elapsed, 60)
                self.time_label.config(text=f"{mins:02d}:{secs:02d}")
                self.after(1000, self._update_elapsed)

    class SteganographyGUI:
        def __init__(self, root: tk.Tk):
            self.root = root
            self.root.title("Steganography Suite")

            # Disable macOS window tabbing to prevent "tk" tab
            if sys.platform == "darwin":
                try:
                    # Removed moveableModal - it breaks window controls
                    # Also try to prevent automatic tab creation
                    self.root.createcommand("::tk::mac::ShowPreferences", lambda: None)
                except Exception:
                    pass

            # Enable DPI awareness on Windows
            if sys.platform == "win32":
                try:
                    from ctypes import windll

                    windll.shcore.SetProcessDpiAwareness(1)
                except Exception:
                    pass

            self.root.geometry("1400x920")
            self.root.minsize(1100, 750)
            self.history: list[HistoryItem] = []
            self.preview_visible = tk.BooleanVar(master=self.root, value=True)
            self.recent_files: list[str] = []
            self.preferences = self._load_preferences()

            # Restore window geometry
            if "geometry" in self.preferences:
                try:
                    self.root.geometry(self.preferences["geometry"])
                except Exception:
                    pass

            # Build UI first, then apply theme
            self._build_ui()
            self._apply_native_theme()
            self._setup_keyboard_shortcuts()

            # Save window geometry on close
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        def _apply_native_theme(self) -> None:
            """Apply native OS theme with dark mode detection."""
            style = ttk.Style()

            if sys.platform == "darwin":
                # Detect macOS dark mode and apply appearance
                dark_mode = self._detect_dark_mode()
                try:
                    appearance = "darkAqua" if dark_mode else "aqua"
                    self.root.tk.call(
                        "::tk::unsupported::MacWindowStyle",
                        "appearance",
                        self.root._w,
                        appearance,
                    )
                except Exception:
                    pass

                # Apply aqua theme
                if "aqua" in style.theme_names():
                    style.theme_use("aqua")

            elif sys.platform == "win32":
                # Detect Windows dark mode
                dark_mode = self._detect_dark_mode()

                if dark_mode:
                    # Use alt/clam theme for better dark mode support
                    if "alt" in style.theme_names():
                        style.theme_use("alt")
                    elif "clam" in style.theme_names():
                        style.theme_use("clam")

                    # Apply dark colors
                    bg_color = "#2b2b2b"
                    fg_color = "#ffffff"
                    select_bg = "#0078d7"

                    style.configure(
                        ".",
                        background=bg_color,
                        foreground=fg_color,
                        fieldbackground="#3c3c3c",
                        selectbackground=select_bg,
                        selectforeground="#ffffff",
                        bordercolor=bg_color,
                        darkcolor=bg_color,
                        lightcolor=bg_color,
                    )

                    style.map(
                        ".",
                        background=[("active", "#3c3c3c")],
                        foreground=[("active", fg_color)],
                    )

                    style.configure("TFrame", background=bg_color)
                    style.configure("TLabel", background=bg_color, foreground=fg_color)
                    style.configure(
                        "TLabelframe", background=bg_color, bordercolor=bg_color
                    )
                    style.configure(
                        "TLabelframe.Label", background=bg_color, foreground=fg_color
                    )
                    style.configure(
                        "Header.TLabel", background=bg_color, foreground=fg_color
                    )

                    style.configure(
                        "TButton",
                        background="#3c3c3c",
                        foreground=fg_color,
                        bordercolor="#3c3c3c",
                        lightcolor="#3c3c3c",
                        darkcolor="#3c3c3c",
                    )
                    style.map(
                        "TButton",
                        background=[("active", "#4c4c4c"), ("pressed", "#1e1e1e")],
                    )

                    style.configure(
                        "TCheckbutton", background=bg_color, foreground=fg_color
                    )
                    style.map("TCheckbutton", background=[("active", bg_color)])

                    style.configure(
                        "TRadiobutton", background=bg_color, foreground=fg_color
                    )
                    style.map("TRadiobutton", background=[("active", bg_color)])

                    style.configure(
                        "TNotebook", background=bg_color, bordercolor=bg_color
                    )
                    style.configure(
                        "TNotebook.Tab", background="#3c3c3c", foreground=fg_color
                    )
                    style.map("TNotebook.Tab", background=[("selected", "#4c4c4c")])

                    style.configure(
                        "TEntry",
                        fieldbackground="#3c3c3c",
                        foreground=fg_color,
                        bordercolor=bg_color,
                        lightcolor=bg_color,
                        darkcolor=bg_color,
                    )

                    self.root.configure(bg=bg_color)

                    # Try to set title bar to dark mode (Windows 10 build 17763+)
                    try:
                        import ctypes

                        hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                        ctypes.windll.dwmapi.DwmSetWindowAttribute(
                            hwnd,
                            DWMWA_USE_IMMERSIVE_DARK_MODE,
                            ctypes.byref(ctypes.c_int(1)),
                            ctypes.sizeof(ctypes.c_int),
                        )
                    except Exception:
                        pass
                else:
                    # Light mode: use native Windows theme
                    for name in ("vista", "xpnative", "winnative"):
                        if name in style.theme_names():
                            style.theme_use(name)
                            break

            # Apply standard styling
            style.configure("Primary.TButton", padding=(PADDING_MEDIUM, PADDING_SMALL))
            style.configure("TLabelframe.Label", font=("TkDefaultFont", 10, "bold"))
            style.configure("Header.TLabel", font=("TkDefaultFont", 16, "bold"))

        def _detect_dark_mode(self) -> bool:
            try:
                if sys.platform == "win32":
                    import winreg

                    key_path = (
                        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                    )
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                        return value == 0
                if sys.platform == "darwin":
                    result = subprocess.run(
                        ["defaults", "read", "-g", "AppleInterfaceStyle"],
                        capture_output=True,
                        text=True,
                    )
                    return result.returncode == 0 and "Dark" in result.stdout
            except Exception:
                return False
            return False

        def _build_ui(self) -> None:
            # Header with title and toolbar
            header = ttk.Frame(self.root)
            header.pack(side=tk.TOP, fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            title_frame = ttk.Frame(header)
            title_frame.pack(side=tk.TOP, fill=tk.X, pady=(PADDING_SMALL, 0))
            ttk.Label(
                title_frame, text="Steganography Suite", style="Header.TLabel"
            ).pack(side=tk.LEFT)

            # Quick action toolbar
            toolbar = ttk.Frame(title_frame)
            toolbar.pack(side=tk.RIGHT)
            ttk.Button(toolbar, text="Open", width=8, command=self._quick_open).pack(
                side=tk.LEFT, padx=2
            )
            ttk.Button(
                toolbar, text="Settings", width=8, command=self._show_settings
            ).pack(side=tk.LEFT, padx=2)
            ttk.Checkbutton(
                toolbar,
                text="Preview",
                variable=self.preview_visible,
                command=self._toggle_preview,
            ).pack(side=tk.LEFT, padx=PADDING_SMALL)

            ttk.Separator(header, orient=tk.HORIZONTAL).pack(
                fill=tk.X, pady=(PADDING_SMALL, 0)
            )

            # Recent files bar
            self.recent_bar = ttk.Frame(header)
            self.recent_bar.pack(side=tk.TOP, fill=tk.X, pady=(4, 0))
            self._update_recent_files_ui()

            # Main content area
            content = ttk.Frame(self.root)
            content.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )
            content.columnconfigure(0, weight=1)
            content.columnconfigure(1, minsize=340)
            content.rowconfigure(0, weight=1)

            main_center = ttk.Frame(content)
            main_center.grid(row=0, column=0, sticky="nsew", padx=(0, PADDING_SMALL))
            main_center.rowconfigure(0, weight=1)
            main_center.columnconfigure(0, weight=1)

            self.notebook = ttk.Notebook(main_center)
            self.notebook.grid(row=0, column=0, sticky="nsew")

            # Clear any default tabs created by ttk.Notebook
            for tab_id in list(self.notebook.tabs()):
                self.notebook.forget(tab_id)

            # Preview panel (collapsible)
            self.preview_frame = ttk.Labelframe(content, text="Preview & Info")
            self.preview_frame.grid(row=0, column=1, sticky="nsew", pady=0)
            self.preview_frame.columnconfigure(0, weight=1)
            self.preview_frame.rowconfigure(0, weight=1)

            self._preview_image_ref = None
            self._preview_video_ref = None

            preview_scroll = ttk.Frame(self.preview_frame)
            preview_scroll.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            image_box = ttk.Labelframe(preview_scroll, text="Image")
            image_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_image = ttk.Label(
                image_box, text="No image selected", anchor=tk.CENTER
            )
            self.preview_image.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            # File info display
            self.file_info_label = ttk.Label(
                image_box, text="", font=("TkDefaultFont", 8), foreground="#666"
            )
            self.file_info_label.pack(
                fill=tk.X, padx=PADDING_SMALL, pady=(0, PADDING_SMALL)
            )

            audio_box = ttk.Labelframe(preview_scroll, text="Audio")
            audio_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_audio = ttk.Label(
                audio_box, text="No audio selected", wraplength=300, justify=tk.LEFT
            )
            self.preview_audio.pack(fill=tk.X, padx=PADDING_SMALL, pady=PADDING_SMALL)

            video_box = ttk.Labelframe(preview_scroll, text="Video")
            video_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_video = ttk.Label(
                video_box, text="No video selected", anchor=tk.CENTER
            )
            self.preview_video.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            pdf_box = ttk.Labelframe(preview_scroll, text="PDF")
            pdf_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_pdf = ttk.Label(
                pdf_box, text="No PDF selected", wraplength=300, justify=tk.LEFT
            )
            self.preview_pdf.pack(fill=tk.X, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # Reorganized tabs by workflow - Create frames NOT as children of notebook yet
            tab_frames = {
                "Hide Data": ttk.Frame(self.root),
                "Reveal Data": ttk.Frame(self.root),
                "Advanced": ttk.Frame(self.root),
                "Batch Operations": ttk.Frame(self.root),
                "Analysis & Tools": ttk.Frame(self.root),
                "History": ttk.Frame(self.root),
            }

            # Now add them to the notebook
            for name, frame in tab_frames.items():
                self.notebook.add(frame, text=name)

            self.tabs = tab_frames

            # Final cleanup - remove any tabs that shouldn't be there
            for tab_id in list(self.notebook.tabs()):
                try:
                    tab_text = self.notebook.tab(tab_id, "text")
                    if tab_text not in self.tabs.keys():
                        self.notebook.forget(tab_id)
                except tk.TclError:
                    self.notebook.forget(tab_id)

            # Build main tabs with sub-notebooks
            self._build_hide_data_tab(self.tabs["Hide Data"])
            self._build_reveal_data_tab(self.tabs["Reveal Data"])
            self._build_advanced_tab(self.tabs["Advanced"])
            self._build_batch_tab(self.tabs["Batch Operations"])
            self._build_tools_tab(self.tabs["Analysis & Tools"])
            self._build_history_tab(self.tabs["History"])

            self.status = StatusBar(self.root)
            self.status.pack(side=tk.BOTTOM, fill=tk.X)

        def _setup_keyboard_shortcuts(self) -> None:
            """Setup keyboard shortcuts for common actions."""
            self.root.bind("<Control-o>", lambda e: self._quick_open())
            self.root.bind("<Control-s>", lambda e: self._quick_save())
            self.root.bind("<Control-comma>", lambda e: self._show_settings())
            self.root.bind("<F1>", lambda e: self._show_help())
            self.root.bind(
                "<Control-h>", lambda e: self.notebook.select(self.tabs["History"])
            )

        def _toggle_preview(self) -> None:
            """Toggle preview panel visibility."""
            if self.preview_visible.get():
                self.preview_frame.grid()
                self.root.update_idletasks()  # Force layout update
            else:
                self.preview_frame.grid_remove()
                self.root.update_idletasks()  # Force layout update

        def _quick_open(self) -> None:
            """Quick file open dialog."""
            path = filedialog.askopenfilename(
                title="Open File",
                filetypes=[
                    ("All Supported", _tk_file_patterns(SUPPORTED_FILE_EXTENSIONS)),
                    ("Images", _tk_file_patterns(IMAGE_FILE_EXTENSIONS)),
                    ("Audio", _tk_file_patterns(AUDIO_FILE_EXTENSIONS)),
                    ("Video", _tk_file_patterns(VIDEO_FILE_EXTENSIONS)),
                    ("PDF", "*.pdf"),
                    ("All Files", "*.*"),
                ],
            )
            if path:
                self._add_recent_file(path)
                self._load_file_to_appropriate_tab(path)

        def _quick_save(self) -> None:
            pass  # Placeholder for quick save

        def _show_help(self) -> None:
            """Show help dialog."""
            help_text = get_quick_help_text()
            win = tk.Toplevel(self.root)
            win.title("Help")
            win.geometry("600x500")
            win.transient(self.root)

            # Apply theme based on mode
            if self._detect_dark_mode():
                win.configure(bg="#2b2d31")
                text = tk.Text(
                    win,
                    wrap=tk.WORD,
                    padx=PADDING_MEDIUM,
                    pady=PADDING_MEDIUM,
                    bg="#2b2d31",
                    fg="#dcddde",
                    insertbackground="#dcddde",
                    borderwidth=0,
                )
            else:
                win.configure(bg="SystemButtonFace")
                text = tk.Text(
                    win,
                    wrap=tk.WORD,
                    padx=PADDING_MEDIUM,
                    pady=PADDING_MEDIUM,
                    bg="white",
                    fg="black",
                    insertbackground="black",
                )
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(tk.END, help_text)
            text.config(state=tk.DISABLED)

            ttk.Button(
                win, text="Close", command=win.destroy, style="Primary.TButton"
            ).pack(pady=PADDING_SMALL)

        def _load_preferences(self) -> dict:
            """Load user preferences."""
            pref_path = Path.home() / ".steg_preferences.json"
            if pref_path.exists():
                try:
                    return json.loads(pref_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
            return {}

        def _save_preferences(self) -> None:
            """Save user preferences."""
            pref_path = Path.home() / ".steg_preferences.json"
            self.preferences["geometry"] = self.root.geometry()
            self.preferences["recent_files"] = self.recent_files[:10]
            pref_path.write_text(
                json.dumps(self.preferences, indent=2), encoding="utf-8"
            )

        def _on_close(self) -> None:
            """Handle window close event."""
            self._save_preferences()
            self.root.destroy()

        def _add_recent_file(self, path: str) -> None:
            """Add file to recent files list."""
            if path in self.recent_files:
                self.recent_files.remove(path)
            self.recent_files.insert(0, path)
            self.recent_files = self.recent_files[:10]
            self._update_recent_files_ui()

        def _update_recent_files_ui(self) -> None:
            """Update recent files display."""
            for widget in self.recent_bar.winfo_children():
                widget.destroy()

            if not self.recent_files:
                ttk.Label(
                    self.recent_bar, text="Recent: None", font=("TkDefaultFont", 8)
                ).pack(side=tk.LEFT)
                return

            ttk.Label(self.recent_bar, text="Recent:", font=("TkDefaultFont", 8)).pack(
                side=tk.LEFT, padx=(0, PADDING_SMALL)
            )
            for i, path in enumerate(self.recent_files[:5]):
                name = Path(path).name
                if len(name) > 25:
                    name = name[:22] + "..."
                btn = ttk.Button(
                    self.recent_bar,
                    text=name,
                    width=max(8, len(name)),
                    command=lambda p=path: self._load_file_to_appropriate_tab(p),
                )
                btn.pack(side=tk.LEFT, padx=2)
                Tooltip(btn, path)

        def _load_file_to_appropriate_tab(self, path: str) -> None:
            """Load file into the appropriate tab based on extension."""
            ext = Path(path).suffix.lower()
            if ext in (".png", ".jpg", ".jpeg"):
                self.notebook.select(self.tabs["Hide Data"])
            elif ext in AUDIO_FILE_EXTENSIONS or ext in VIDEO_FILE_EXTENSIONS:
                self.notebook.select(self.tabs["Hide Data"])
            elif ext == ".pdf":
                self.notebook.select(self.tabs["Hide Data"])

        def _show_settings(self) -> None:
            """Show settings dialog."""
            settings = tk.Toplevel(self.root)
            settings.title("Settings")
            settings.geometry("500x400")
            settings.transient(self.root)
            settings.grab_set()

            # Apply theme colors to toplevel window
            if self._detect_dark_mode():
                settings.configure(bg="#2b2d31")
            else:
                settings.configure(bg="SystemButtonFace")

            notebook = ttk.Notebook(settings)
            notebook.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM
            )

            # Clear any default tabs
            for tab_id in list(notebook.tabs()):
                notebook.forget(tab_id)

            # General settings
            general = ttk.Frame(notebook)
            notebook.add(general, text="General")

            ttk.Label(general, text="Default Compression:").pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_MEDIUM, 0)
            )
            compress_var = tk.BooleanVar(
                master=self.root, value=self.preferences.get("default_compress", False)
            )
            ttk.Checkbutton(
                general, text="Enable compression by default", variable=compress_var
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM)

            ttk.Label(general, text="Default Method:").pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_MEDIUM, 0)
            )
            method_var = tk.StringVar(
                master=self.root, value=self.preferences.get("default_method", "lsb")
            )
            ttk.Radiobutton(
                general, text="LSB (Simple)", variable=method_var, value="lsb"
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM)
            ttk.Radiobutton(
                general,
                text="LSB-PRNG (Randomized)",
                variable=method_var,
                value="lsb-prng",
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM)
            ttk.Radiobutton(
                general,
                text="LSB-Match (PRNG)",
                variable=method_var,
                value="lsb-match-prng",
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM)

            ttk.Separator(general, orient=tk.HORIZONTAL).pack(
                fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM
            )

            ttk.Checkbutton(
                general,
                text="Show preview panel by default",
                variable=self.preview_visible,
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM)

            # Appearance settings
            appearance = ttk.Frame(notebook)
            notebook.add(appearance, text="Appearance")

            ttk.Label(appearance, text="Theme:").pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_MEDIUM, 0)
            )
            ttk.Label(
                appearance,
                text="Using system theme (Light/Dark mode)",
                foreground="gray",
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM)

            # Save button
            btn_frame = ttk.Frame(settings)
            btn_frame.pack(
                side=tk.BOTTOM, fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM
            )

            def save_settings():
                self.preferences["default_compress"] = compress_var.get()
                self.preferences["default_method"] = method_var.get()
                self._save_preferences()
                messagebox.showinfo("Settings", "Settings saved successfully!")
                settings.destroy()

            ttk.Button(
                btn_frame, text="Save", command=save_settings, width=BUTTON_WIDTH
            ).pack(side=tk.RIGHT)
            ttk.Button(
                btn_frame, text="Cancel", command=settings.destroy, width=BUTTON_WIDTH
            ).pack(side=tk.RIGHT, padx=(0, PADDING_SMALL))

        def _build_hide_data_tab(self, parent: ttk.Frame) -> None:
            """Main 'Hide Data' tab with sub-tabs for different file types."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            image_frame = ttk.Frame(sub_notebook)
            audio_frame = ttk.Frame(sub_notebook)
            video_frame = ttk.Frame(sub_notebook)
            pdf_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(image_frame, text="Images")
            sub_notebook.add(audio_frame, text="Audio")
            sub_notebook.add(video_frame, text="Video")
            sub_notebook.add(pdf_frame, text="PDF")

            self._build_image_tab(image_frame)
            self._build_audio_tab(audio_frame)
            self._build_video_tab(video_frame)
            self._build_pdf_tab(pdf_frame)

        def _build_reveal_data_tab(self, parent: ttk.Frame) -> None:
            """Main 'Reveal Data' tab for extraction."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            image_frame = ttk.Frame(sub_notebook)
            audio_frame = ttk.Frame(sub_notebook)
            video_frame = ttk.Frame(sub_notebook)
            pdf_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(image_frame, text="Images")
            sub_notebook.add(audio_frame, text="Audio")
            sub_notebook.add(video_frame, text="Video")
            sub_notebook.add(pdf_frame, text="PDF")

            self._build_image_decode_only(image_frame)
            self._build_audio_decode_only(audio_frame)
            self._build_video_decode_only(video_frame)
            self._build_pdf_decode_only(pdf_frame)

        def _build_advanced_tab(self, parent: ttk.Frame) -> None:
            """Advanced video-frame embedding features."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            vf_frame = ttk.Frame(sub_notebook)
            sub_notebook.add(vf_frame, text="Video Frames")

            self._build_video_frames_tab(vf_frame)

        def _build_image_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM
            )

            encode = ttk.Labelframe(container, text="Encode Image")
            encode.pack(fill=tk.X, pady=(0, PADDING_MEDIUM))

            cover_var = tk.StringVar(master=self.root)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)
            capacity_var = tk.StringVar(master=self.root, value="Capacity: ")
            strength_var = tk.StringVar(master=self.root, value="Strength: ")

            self.image_vars = {
                "method": method_var,
                "prng_key": prng_var,
                "compress": compress_var,
            }

            self._file_row(
                encode,
                "Cover image",
                cover_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg")],
                on_change=self._update_image_preview,
            )
            ttk.Label(encode, textvariable=capacity_var, foreground="#666").pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL)
            )

            ttk.Separator(encode, orient=tk.HORIZONTAL).pack(
                fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL
            )

            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            msg_entry = PlaceholderEntry(
                encode, textvariable=msg_var, placeholder="Enter secret message..."
            )
            msg_entry.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            paste_btn = ttk.Button(
                encode,
                text="Paste from Clipboard",
                command=lambda: msg_var.set(self._paste_clipboard()),
                width=BUTTON_WIDTH_LARGE,
            )
            paste_btn.pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            Tooltip(paste_btn, "Paste text from the system clipboard")

            self._file_row(
                encode,
                "Payload file (optional)",
                payload_file_var,
                filetypes=[("All Files", "*.*")],
            )

            ttk.Separator(encode, orient=tk.HORIZONTAL).pack(
                fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL
            )

            ttk.Label(encode, text="Password (optional)").pack(
                anchor=tk.W, padx=PADDING_MEDIUM
            )
            pwd_entry_frame = PasswordEntry(encode, textvariable=pwd_var)
            pwd_entry_frame.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, 4))
            ttk.Label(
                encode,
                textvariable=strength_var,
                font=("TkDefaultFont", 8),
                foreground="#666",
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            method_row = ttk.Frame(encode)
            method_row.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            method_box = ttk.Combobox(
                method_row,
                textvariable=method_var,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            )
            method_box.pack(side=tk.LEFT, padx=PADDING_SMALL)
            Tooltip(
                method_box,
                "LSB: simple. PRNG: randomized. LSB-match: adjusts selected pixel values.",
            )

            ttk.Label(method_row, text="PRNG key").pack(
                side=tk.LEFT, padx=(PADDING_LARGE, 0)
            )
            prng_entry = PlaceholderEntry(
                method_row,
                textvariable=prng_var,
                width=28,
                placeholder="Required for PRNG",
            )
            prng_entry.pack(side=tk.LEFT, padx=PADDING_SMALL)
            Tooltip(prng_entry, "Required for PRNG methods")

            ttk.Separator(encode, orient=tk.HORIZONTAL).pack(
                fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL
            )

            options_row = ttk.Frame(encode)
            options_row.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Checkbutton(
                options_row, text="Compress payload", variable=compress_var
            ).pack(side=tk.LEFT)

            ttk.Label(encode, text="Comment (optional)").pack(
                anchor=tk.W, padx=PADDING_MEDIUM
            )
            PlaceholderEntry(
                encode, textvariable=comment_var, placeholder="Optional comment"
            ).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(
                anchor=tk.W, padx=PADDING_MEDIUM
            )
            PlaceholderEntry(
                encode, textvariable=expires_var, placeholder="e.g., 2026-12-31"
            ).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            self._save_row(
                encode,
                "Output file",
                out_var,
                def_ext=".png",
                filetypes=[("PNG", "*.png")],
            )

            ttk.Button(
                encode,
                text="Embed Data",
                style="Primary.TButton",
                width=BUTTON_WIDTH_LARGE,
                command=lambda: self._encode_image(
                    cover_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    method_var.get(),
                    prng_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_SMALL, PADDING_MEDIUM)
            )

            capacity_estimator = AsyncImageCapacityEstimator(
                self.root, capacity_var.set
            )

            def update_capacity(*_):
                cover_path = cover_var.get()
                if not cover_path:
                    capacity_estimator.invalidate()
                    capacity_var.set("Estimated envelope: select a cover image")
                    return
                snapshot = ImageCapacityRequest(
                    cover_path=cover_path,
                    payload_file_path=payload_file_var.get(),
                    message=msg_var.get(),
                    password=pwd_var.get() or None,
                    compress=bool(compress_var.get()),
                    comment=comment_var.get() or None,
                    expires=expires_var.get() or None,
                )
                capacity_var.set("Estimating encoded envelope...")
                capacity_estimator.request(snapshot)

            def update_strength(*_):
                _, label = PasswordValidator.check_strength(pwd_var.get())
                strength_var.set(f"Strength: {label}")

            for variable in (
                cover_var,
                msg_var,
                payload_file_var,
                pwd_var,
                compress_var,
                comment_var,
                expires_var,
            ):
                variable.trace_add("write", update_capacity)
            pwd_var.trace_add("write", update_strength)
            update_capacity()

        def _build_image_decode_only(self, parent: ttk.Frame) -> None:
            """Image decode tab (for Reveal Data section)."""
            container = ttk.Frame(parent)
            container.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM
            )

            decode = ttk.Labelframe(container, text="Decode Image")
            decode.pack(fill=tk.X)

            stego_var = tk.StringVar(master=self.root)
            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_var = tk.StringVar(master=self.root)
            dec_method_var = tk.StringVar(master=self.root, value="lsb")
            dec_prng_var = tk.StringVar(master=self.root)

            self._file_row(
                decode,
                "Stego image",
                stego_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg")],
                on_change=self._update_image_preview,
            )

            dec_method_row = ttk.Frame(decode)
            dec_method_row.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Label(dec_method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                dec_method_row,
                textvariable=dec_method_var,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=PADDING_SMALL)
            ttk.Label(dec_method_row, text="PRNG key").pack(
                side=tk.LEFT, padx=(PADDING_LARGE, 0)
            )
            PlaceholderEntry(
                dec_method_row,
                textvariable=dec_prng_var,
                width=28,
                placeholder="If PRNG was used",
            ).pack(side=tk.LEFT, padx=PADDING_SMALL)

            ttk.Separator(decode, orient=tk.HORIZONTAL).pack(
                fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL
            )

            ttk.Label(decode, text="Password (if needed)").pack(
                anchor=tk.W, padx=PADDING_MEDIUM
            )
            pwd_frame = PasswordEntry(decode, textvariable=dec_pwd_var)
            pwd_frame.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            self._save_row(
                decode,
                "Output file",
                dec_out_var,
                def_ext=".bin",
                filetypes=[("All Files", "*.*")],
            )

            ttk.Button(
                decode,
                text="Extract Data",
                style="Primary.TButton",
                width=BUTTON_WIDTH_LARGE,
                command=lambda: self._decode_image(
                    stego_var.get(),
                    dec_pwd_var.get(),
                    dec_out_var.get(),
                    dec_method_var.get(),
                    dec_prng_var.get(),
                ),
            ).pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_SMALL, PADDING_MEDIUM)
            )

        def _build_audio_decode_only(self, parent: ttk.Frame) -> None:
            """Audio decode tab."""
            filetypes = _media_filetypes("Audio", AUDIO_FILE_EXTENSIONS)
            self._build_decode_only_tab(
                parent, media_type="audio", label="Audio", filetypes=filetypes
            )

        def _build_video_decode_only(self, parent: ttk.Frame) -> None:
            """Video decode tab."""
            filetypes = _media_filetypes("Video", VIDEO_FILE_EXTENSIONS)
            self._build_decode_only_tab(
                parent, media_type="video", label="Video", filetypes=filetypes
            )

        def _build_pdf_decode_only(self, parent: ttk.Frame) -> None:
            """PDF decode tab."""
            self._build_decode_only_tab(
                parent, media_type="pdf", label="PDF", filetypes=[("PDF", "*.pdf")]
            )

        def _build_decode_only_tab(
            self, parent: ttk.Frame, media_type: str, label: str, filetypes: list
        ) -> None:
            """Generic decode-only tab."""
            container = ttk.Frame(parent)
            container.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM
            )

            decode = ttk.Labelframe(container, text=f"Decode {label}")
            decode.pack(fill=tk.X)

            stego_var = tk.StringVar(master=self.root)
            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_var = tk.StringVar(master=self.root)

            preview_func = None
            if media_type == "audio":
                preview_func = self._update_audio_preview
            elif media_type == "video":
                preview_func = self._update_video_preview
            elif media_type == "pdf":
                preview_func = self._update_pdf_preview

            self._file_row(
                decode,
                f"{label} file",
                stego_var,
                filetypes=filetypes,
                on_change=preview_func,
            )

            ttk.Separator(decode, orient=tk.HORIZONTAL).pack(
                fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL
            )

            ttk.Label(decode, text="Password (if needed)").pack(
                anchor=tk.W, padx=PADDING_MEDIUM
            )
            pwd_frame = PasswordEntry(decode, textvariable=dec_pwd_var)
            pwd_frame.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            self._save_row(
                decode,
                "Output file",
                dec_out_var,
                def_ext=".bin",
                filetypes=[("All Files", "*.*")],
            )

            ttk.Button(
                decode,
                text="Extract Data",
                style="Primary.TButton",
                width=BUTTON_WIDTH_LARGE,
                command=lambda: self._decode_media(
                    media_type, stego_var.get(), dec_pwd_var.get(), dec_out_var.get()
                ),
            ).pack(
                anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_SMALL, PADDING_MEDIUM)
            )

        def _build_audio_tab(self, parent: ttk.Frame) -> None:
            filetypes = _media_filetypes("Audio", AUDIO_FILE_EXTENSIONS)
            self._build_media_tab(
                parent,
                media_type="audio",
                label="Audio",
                filetypes=filetypes,
                def_ext=".mp3",
                preview_func=self._update_audio_preview,
            )

        def _build_video_tab(self, parent: ttk.Frame) -> None:
            filetypes = _media_filetypes("Video", VIDEO_FILE_EXTENSIONS)
            self._build_media_tab(
                parent,
                media_type="video",
                label="Video",
                filetypes=filetypes,
                def_ext=".mp4",
                preview_func=self._update_video_preview,
            )

        def _build_video_frames_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text="Encode Video Frame")
            encode.pack(fill=tk.X, pady=(0, 12))

            video_var = tk.StringVar(master=self.root)
            frame_var = tk.IntVar(master=self.root, value=0)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            video_filetypes = _media_filetypes("Video", VIDEO_FRAME_FILE_EXTENSIONS)
            self._file_row(
                encode,
                "Video file",
                video_var,
                filetypes=video_filetypes,
                on_change=self._update_video_preview,
            )
            frame_row = ttk.Frame(encode)
            frame_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(frame_row, text="Frame index").pack(side=tk.LEFT)
            ttk.Spinbox(
                frame_row, from_=0, to=1_000_000, textvariable=frame_var, width=8
            ).pack(side=tk.LEFT, padx=8)

            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._file_row(
                encode,
                "Payload file (optional)",
                payload_file_var,
                filetypes=[("All Files", "*.*")],
            )

            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )

            method_row = ttk.Frame(encode)
            method_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                method_row,
                textvariable=method_var,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(method_row, textvariable=prng_var, width=28).pack(
                side=tk.LEFT, padx=8
            )

            ttk.Checkbutton(
                encode, text="Compress payload", variable=compress_var
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(
                fill=tk.X, padx=10, pady=(0, 6)
            )
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(
                anchor=tk.W, padx=10
            )
            ttk.Entry(encode, textvariable=expires_var).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )

            self._save_row(
                encode,
                "Output video (lossless MKV)",
                out_var,
                def_ext=".mkv",
                filetypes=[("Matroska video", "*.mkv")],
            )

            ttk.Button(
                encode,
                text="Embed in Frame",
                command=lambda: self._encode_video_frame(
                    video_var.get(),
                    frame_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    method_var.get(),
                    prng_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text="Decode Video Frame")
            decode.pack(fill=tk.X)

            dec_video = tk.StringVar(master=self.root)
            dec_frame = tk.IntVar(master=self.root, value=0)
            dec_pwd = tk.StringVar(master=self.root)
            dec_out = tk.StringVar(master=self.root)
            dec_method = tk.StringVar(master=self.root, value="lsb")
            dec_prng = tk.StringVar(master=self.root)

            self._file_row(
                decode,
                "Video file",
                dec_video,
                filetypes=video_filetypes,
                on_change=self._update_video_preview,
            )
            dec_row = ttk.Frame(decode)
            dec_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(dec_row, text="Frame index").pack(side=tk.LEFT)
            ttk.Spinbox(
                dec_row, from_=0, to=1_000_000, textvariable=dec_frame, width=8
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_row, text="Method").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Combobox(
                dec_row,
                textvariable=dec_method,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(dec_row, textvariable=dec_prng, width=28).pack(
                side=tk.LEFT, padx=8
            )

            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._save_row(
                decode,
                "Output file",
                dec_out,
                def_ext=".bin",
                filetypes=[("All Files", "*.*")],
            )

            ttk.Button(
                decode,
                text="Extract from Frame",
                command=lambda: self._decode_video_frame(
                    dec_video.get(),
                    dec_frame.get(),
                    dec_pwd.get(),
                    dec_out.get(),
                    dec_method.get(),
                    dec_prng.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_pdf_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text="Encode PDF")
            encode.pack(fill=tk.X, pady=(0, 12))

            pdf_var = tk.StringVar(master=self.root)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            self._file_row(
                encode,
                "PDF file",
                pdf_var,
                filetypes=[("PDF", "*.pdf")],
                on_change=self._update_pdf_preview,
            )
            ttk.Label(
                encode,
                text=metadata_storage_notice("PDF"),
                wraplength=900,
                justify=tk.LEFT,
            ).pack(anchor=tk.W, padx=10, pady=(8, 0))
            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._file_row(
                encode,
                "Payload file (optional)",
                payload_file_var,
                filetypes=[("All Files", "*.*")],
            )
            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            ttk.Checkbutton(
                encode, text="Compress payload", variable=compress_var
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(
                fill=tk.X, padx=10, pady=(0, 6)
            )
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(
                anchor=tk.W, padx=10
            )
            ttk.Entry(encode, textvariable=expires_var).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._save_row(
                encode,
                "Output PDF",
                out_var,
                def_ext=".pdf",
                filetypes=[("PDF", "*.pdf")],
            )

            ttk.Button(
                encode,
                text="Embed in PDF",
                command=lambda: self._encode_pdf(
                    pdf_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text="Decode PDF")
            decode.pack(fill=tk.X)

            dec_pdf = tk.StringVar(master=self.root)
            dec_pwd = tk.StringVar(master=self.root)
            dec_out = tk.StringVar(master=self.root)
            self._file_row(
                decode,
                "PDF file",
                dec_pdf,
                filetypes=[("PDF", "*.pdf")],
                on_change=self._update_pdf_preview,
            )
            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._save_row(
                decode,
                "Output file",
                dec_out,
                def_ext=".bin",
                filetypes=[("All Files", "*.*")],
            )

            ttk.Button(
                decode,
                text="Extract from PDF",
                command=lambda: self._decode_pdf(
                    dec_pdf.get(), dec_pwd.get(), dec_out.get()
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_media_tab(
            self,
            parent: ttk.Frame,
            media_type: str,
            label: str,
            filetypes: list[tuple[str, str]],
            def_ext: str,
            preview_func: Callable[[str], None] | None = None,
        ) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text=f"Encode {label}")
            encode.pack(fill=tk.X, pady=(0, 12))

            input_var = tk.StringVar(master=self.root)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            self._file_row(
                encode,
                f"{label} file",
                input_var,
                filetypes=filetypes,
                on_change=preview_func,
            )
            ttk.Label(
                encode,
                text=metadata_storage_notice(label),
                wraplength=900,
                justify=tk.LEFT,
            ).pack(anchor=tk.W, padx=10, pady=(8, 0))
            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._file_row(
                encode,
                "Payload file (optional)",
                payload_file_var,
                filetypes=[("All Files", "*.*")],
            )
            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            ttk.Checkbutton(
                encode, text="Compress payload", variable=compress_var
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(
                fill=tk.X, padx=10, pady=(0, 6)
            )
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(
                anchor=tk.W, padx=10
            )
            ttk.Entry(encode, textvariable=expires_var).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._save_row(
                encode, "Output file", out_var, def_ext=def_ext, filetypes=filetypes
            )

            ttk.Button(
                encode,
                text="Embed Data",
                command=lambda: self._encode_media(
                    media_type,
                    input_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text=f"Decode {label}")
            decode.pack(fill=tk.X)

            stego_var = tk.StringVar(master=self.root)
            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_var = tk.StringVar(master=self.root)
            self._file_row(
                decode,
                f"{label} file",
                stego_var,
                filetypes=filetypes,
                on_change=preview_func,
            )
            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd_var, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )
            self._save_row(
                decode,
                "Output file",
                dec_out_var,
                def_ext=".bin",
                filetypes=[("All Files", "*.*")],
            )

            ttk.Button(
                decode,
                text="Extract Data",
                command=lambda: self._decode_media(
                    media_type, stego_var.get(), dec_pwd_var.get(), dec_out_var.get()
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_tools_tab(self, parent: ttk.Frame) -> None:
            """Analysis & Tools tab with sub-tabs."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(
                fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL
            )

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            tools_frame = ttk.Frame(sub_notebook)
            analysis_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(tools_frame, text="Tools")
            sub_notebook.add(analysis_frame, text="Analysis")

            self._build_tools_only(tools_frame)
            self._build_analyze_tab(analysis_frame)

        def _build_tools_only(self, parent: ttk.Frame) -> None:
            """Just the tools without analysis."""
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            help_box = ttk.Labelframe(container, text="Help")
            help_box.pack(fill=tk.X, pady=(0, 12))
            info = (
                "Use PNG for image steganography, select strong passwords, and test extraction before sharing files. "
                "PRNG methods require a key. Compression can increase capacity at the cost of predictability."
            )
            ttk.Label(help_box, text=info, wraplength=900, justify=tk.LEFT).pack(
                padx=10, pady=8
            )

            cap_box = ttk.Labelframe(container, text="Capacity Calculator")
            cap_box.pack(fill=tk.X)

            img_var = tk.StringVar(master=self.root)
            cap_var = tk.StringVar(master=self.root, value="RGB LSB capacity: ")
            self._file_row(
                cap_box,
                "Image file",
                img_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
            )
            ttk.Label(cap_box, textvariable=cap_var).pack(
                anchor=tk.W, padx=10, pady=(0, 8)
            )

            def update_cap(*_):
                if img_var.get():
                    cap = CapacityCalculator.image_lsb_capacity(img_var.get())
                    cap_var.set(
                        f"RGB LSB capacity: {CapacityCalculator.format_bytes(cap)}"
                    )
                else:
                    cap_var.set("RGB LSB capacity: ")

            img_var.trace_add("write", update_cap)

            vault_box = ttk.Labelframe(container, text="Key Vault")
            vault_box.pack(fill=tk.X, pady=(12, 0))

            key_name = tk.StringVar(master=self.root)
            key_value = tk.StringVar(master=self.root)
            master_pwd = tk.StringVar(master=self.root)

            ttk.Label(vault_box, text="Key name").pack(
                anchor=tk.W, padx=10, pady=(6, 0)
            )
            ttk.Entry(vault_box, textvariable=key_name).pack(fill=tk.X, padx=10)
            ttk.Label(vault_box, text="Key value").pack(
                anchor=tk.W, padx=10, pady=(6, 0)
            )
            ttk.Entry(vault_box, textvariable=key_value).pack(fill=tk.X, padx=10)
            ttk.Label(vault_box, text="Master password").pack(
                anchor=tk.W, padx=10, pady=(6, 0)
            )
            ttk.Entry(vault_box, textvariable=master_pwd, show="*").pack(
                fill=tk.X, padx=10
            )

            vault_btns = ttk.Frame(vault_box)
            vault_btns.pack(fill=tk.X, padx=10, pady=8)

            def save_key():
                if not key_name.get() or not key_value.get() or not master_pwd.get():
                    messagebox.showerror(
                        "Error", "Provide key name, key value, and master password."
                    )
                    return
                try:
                    self._save_vault(
                        master_pwd.get(), {key_name.get(): key_value.get()}
                    )
                except Exception as exc:
                    reason = str(exc) or (
                        "The master password may be incorrect or the vault may be damaged. "
                        "The existing vault was not changed."
                    )
                    messagebox.showerror("Error", f"Could not save key: {reason}")
                    return
                messagebox.showinfo("Success", "Key saved.")

            def load_key():
                if not key_name.get() or not master_pwd.get():
                    messagebox.showerror(
                        "Error", "Provide key name and master password."
                    )
                    return
                keys = self._load_vault(master_pwd.get())
                if key_name.get() not in keys:
                    messagebox.showerror("Error", "Key not found in vault.")
                    return
                value = keys[key_name.get()]
                key_value.set(value)
                self._copy_to_clipboard(value)
                messagebox.showinfo("Success", "Key loaded and copied to clipboard.")

            ttk.Button(vault_btns, text="Save Key", command=save_key).pack(side=tk.LEFT)
            ttk.Button(vault_btns, text="Load Key", command=load_key).pack(
                side=tk.LEFT, padx=6
            )

            templates_box = ttk.Labelframe(container, text="Templates")
            templates_box.pack(fill=tk.X, pady=(12, 0))

            template_name = tk.StringVar(master=self.root)
            ttk.Label(templates_box, text="Template name").pack(
                anchor=tk.W, padx=10, pady=(6, 0)
            )
            ttk.Entry(templates_box, textvariable=template_name).pack(
                fill=tk.X, padx=10
            )

            tmpl_btns = ttk.Frame(templates_box)
            tmpl_btns.pack(fill=tk.X, padx=10, pady=8)

            def save_template():
                if not template_name.get():
                    messagebox.showerror("Error", "Provide a template name.")
                    return
                templates = self._load_templates()
                if not hasattr(self, "image_vars"):
                    messagebox.showerror("Error", "Image tab is not initialized.")
                    return
                templates[template_name.get()] = {
                    "method": self.image_vars["method"].get(),
                    "compress": str(self.image_vars["compress"].get()),
                }
                self._save_templates(templates)
                messagebox.showinfo("Success", "Template saved.")

            def load_template():
                if not template_name.get():
                    messagebox.showerror("Error", "Provide a template name.")
                    return
                templates = self._load_templates()
                if template_name.get() not in templates:
                    messagebox.showerror("Error", "Template not found.")
                    return
                if not hasattr(self, "image_vars"):
                    messagebox.showerror("Error", "Image tab is not initialized.")
                    return
                values = template_values_for_load(templates[template_name.get()])
                self.image_vars["method"].set(values.get("method", "lsb"))
                self.image_vars["prng_key"].set(values.get("prng_key", ""))
                self.image_vars["compress"].set(values.get("compress", False))
                messagebox.showinfo("Success", "Template loaded into Image tab.")

            ttk.Button(tmpl_btns, text="Save Template", command=save_template).pack(
                side=tk.LEFT
            )
            ttk.Button(tmpl_btns, text="Load Template", command=load_template).pack(
                side=tk.LEFT, padx=6
            )

            qr_box = ttk.Labelframe(container, text="QR Code Generator")
            qr_box.pack(fill=tk.X, pady=(12, 0))
            qr_text = tk.StringVar(master=self.root)
            qr_out = tk.StringVar(master=self.root)
            ttk.Label(qr_box, text="Text").pack(anchor=tk.W, padx=10, pady=(6, 0))
            ttk.Entry(qr_box, textvariable=qr_text).pack(fill=tk.X, padx=10)
            self._save_row(
                qr_box,
                "Output PNG",
                qr_out,
                def_ext=".png",
                filetypes=[("PNG", "*.png")],
            )

            ttk.Button(
                qr_box,
                text="Generate QR",
                command=lambda: self._run_command(
                    build_qr_command(qr_text.get(), qr_out.get()),
                    "QR generate",
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            portable_box = ttk.Labelframe(container, text="Portable Decoder")
            portable_box.pack(fill=tk.X, pady=(12, 0))
            port_in = tk.StringVar(master=self.root)
            port_out = tk.StringVar(master=self.root)
            port_method = tk.StringVar(master=self.root, value="lsb")
            port_frame = tk.StringVar(master=self.root)

            self._file_row(
                portable_box, "Stego file", port_in, filetypes=[("All Files", "*.*")]
            )
            self._save_row(
                portable_box,
                "Output ZIP",
                port_out,
                def_ext=".zip",
                filetypes=[("ZIP", "*.zip")],
            )
            ttk.Label(
                portable_box,
                text=PORTABLE_DECODER_CREDENTIAL_NOTICE,
                wraplength=620,
                justify=tk.LEFT,
            ).pack(anchor=tk.W, padx=10, pady=(4, 8))
            port_row = ttk.Frame(portable_box)
            port_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(port_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                port_row,
                textvariable=port_method,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)

            ttk.Label(portable_box, text="Video frame index").pack(anchor=tk.W, padx=10)
            ttk.Entry(portable_box, textvariable=port_frame).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )

            def run_portable():
                stego_path = port_in.get()
                output_path = port_out.get()
                if not stego_path:
                    messagebox.showerror("Error", "Select a stego file.")
                    return
                if not output_path:
                    messagebox.showerror("Error", "Select an output ZIP.")
                    return

                arguments = {
                    "method": port_method.get() or None,
                    "frame": port_frame.get() or None,
                }
                if not getattr(sys, "frozen", False):
                    try:
                        cmd = build_portable_decoder_action(
                            stego_path, output_path, frozen=False, **arguments
                        )
                    except (OSError, TypeError, ValueError) as exc:
                        messagebox.showerror("Error", str(exc))
                        return
                    assert cmd is not None
                    self._run_command(cmd, "Portable decoder")
                    return

                def task():
                    self.root.after(
                        0, lambda: self._set_status("Portable decoder in progress")
                    )
                    self.root.after(0, self.status.start)
                    try:
                        build_portable_decoder_action(
                            stego_path,
                            output_path,
                            frozen=True,
                            cli_path=packaged_cli_path(),
                            **arguments,
                        )
                    except Exception as exc:
                        error = str(exc)
                        self.root.after(0, self.status.stop)
                        self.root.after(
                            0, lambda: self._set_status("Portable decoder failed")
                        )
                        self.root.after(
                            0,
                            lambda: self._add_history(
                                "Portable decoder", "Failed", error[:200]
                            ),
                        )
                        self.root.after(
                            0, lambda e=error: messagebox.showerror("Error", e)
                        )
                        return

                    self.root.after(0, self.status.stop)
                    self.root.after(
                        0, lambda: self._set_status("Portable decoder complete")
                    )
                    self.root.after(
                        0,
                        lambda: self._add_history(
                            "Portable decoder", "Success", f"Created {output_path}"
                        ),
                    )
                    self.root.after(
                        0,
                        lambda: messagebox.showinfo(
                            "Success", f"Portable decoder created at {output_path}"
                        ),
                    )

                threading.Thread(target=task, daemon=True).start()

            ttk.Button(portable_box, text="Create Decoder", command=run_portable).pack(
                anchor=tk.W, padx=10, pady=(0, 10)
            )

            assoc_box = ttk.Labelframe(container, text="File Association (Windows)")
            assoc_box.pack(fill=tk.X, pady=(12, 0))
            assoc_out = tk.StringVar(master=self.root)
            self._save_row(
                assoc_box,
                "Output .reg",
                assoc_out,
                def_ext=".reg",
                filetypes=[("Registry", "*.reg")],
            )

            def run_file_association():
                output_path = assoc_out.get()
                if not output_path:
                    messagebox.showerror("Error", "Select an output .reg file.")
                    return
                if getattr(sys, "frozen", False):
                    if sys.platform != "win32":
                        messagebox.showerror(
                            "Error",
                            "Windows file associations are only supported by the Windows build.",
                        )
                        return
                    try:
                        registry = build_file_association_action(
                            output_path, frozen=True, cli_path=packaged_cli_path()
                        )
                        assert isinstance(registry, str)
                        Path(output_path).write_text(registry, encoding="utf-8")
                    except (OSError, TypeError, ValueError) as exc:
                        messagebox.showerror("Error", str(exc))
                        return
                    messagebox.showinfo(
                        "Success", f"File association registry saved to {output_path}"
                    )
                    return

                try:
                    command = build_file_association_action(output_path, frozen=False)
                except (OSError, TypeError, ValueError) as exc:
                    messagebox.showerror("Error", str(exc))
                    return
                assert isinstance(command, list)
                self._run_command(command, "File association")

            ttk.Button(
                assoc_box,
                text="Generate .reg",
                command=run_file_association,
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            meta_box = ttk.Labelframe(container, text="Metadata Viewer")
            meta_box.pack(fill=tk.X, pady=(12, 0))
            meta_file = tk.StringVar(master=self.root)
            self._file_row(
                meta_box, "File", meta_file, filetypes=[("All Files", "*.*")]
            )
            meta_text = tk.StringVar(master=self.root, value="")

            def view_meta():
                path = meta_file.get()
                if not path:
                    messagebox.showerror("Error", "Select a file.")
                    return
                info = []
                try:
                    size = Path(path).stat().st_size
                    info.append(f"Size: {CapacityCalculator.format_bytes(size)}")
                except Exception:
                    pass
                ext = Path(path).suffix.lower()
                try:
                    if ext in (".png", ".jpg", ".jpeg", ".gif"):
                        img = Image.open(path)
                        info.append(f"Image: {img.size[0]}x{img.size[1]}")
                        if ext == ".gif":
                            info.append(
                                f"Frames: {sum(1 for _ in ImageSequence.Iterator(img))}"
                            )
                    elif ext == ".mp3":
                        tags = ID3(path)
                        info.append(f"MP3 tags: {len(tags.keys())}")
                    elif ext in MP4_CONTAINER_EXTS:
                        tags = MP4(path)
                        info.append(f"MP4-family tags: {len(tags.keys())}")
                    elif ext == ".pdf":
                        reader = PdfReader(path)
                        info.append(f"Pages: {len(reader.pages)}")
                except Exception as exc:
                    info.append(f"Metadata error: {exc}")
                meta_text.set(" | ".join(info))

            ttk.Button(meta_box, text="View Metadata", command=view_meta).pack(
                anchor=tk.W, padx=10, pady=(0, 8)
            )
            ttk.Label(meta_box, textvariable=meta_text).pack(
                anchor=tk.W, padx=10, pady=(0, 8)
            )

            hash_box = ttk.Labelframe(container, text="Data Integrity Check (SHA256)")
            hash_box.pack(fill=tk.X, pady=(12, 0))
            hash_file = tk.StringVar(master=self.root)
            hash_result = tk.StringVar(master=self.root, value="")
            self._file_row(
                hash_box, "File", hash_file, filetypes=[("All Files", "*.*")]
            )

            def calc_hash():
                path = hash_file.get()
                if not path:
                    messagebox.showerror("Error", "Select a file.")
                    return
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                hash_result.set(h.hexdigest())

            ttk.Button(hash_box, text="Compute Hash", command=calc_hash).pack(
                anchor=tk.W, padx=10, pady=(0, 8)
            )
            ttk.Entry(hash_box, textvariable=hash_result).pack(
                fill=tk.X, padx=10, pady=(0, 8)
            )

            browser_box = ttk.Labelframe(container, text="File Browser")
            browser_box.pack(fill=tk.BOTH, expand=True, pady=(12, 0))
            dir_var = tk.StringVar(master=self.root, value=str(Path.home()))

            dir_row = ttk.Frame(browser_box)
            dir_row.pack(fill=tk.X, padx=10, pady=(6, 6))
            ttk.Label(dir_row, text="Folder").pack(side=tk.LEFT)
            ttk.Entry(dir_row, textvariable=dir_var).pack(
                side=tk.LEFT, fill=tk.X, expand=True, padx=8
            )
            ttk.Button(
                dir_row,
                text="Browse",
                command=lambda: dir_var.set(filedialog.askdirectory()),
            ).pack(side=tk.LEFT)

            file_list = tk.Listbox(browser_box, height=6)
            file_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

            def refresh_list(*_):
                file_list.delete(0, tk.END)
                try:
                    for name in sorted(os.listdir(dir_var.get())):
                        file_list.insert(tk.END, name)
                except Exception as exc:
                    file_list.insert(tk.END, f"Error: {exc}")

            dir_var.trace_add("write", refresh_list)
            refresh_list()

            gallery_box = ttk.Labelframe(container, text="Gallery Builder")
            gallery_box.pack(fill=tk.X, pady=(12, 0))

            gallery_files: list[str] = []
            gallery_list = tk.Listbox(gallery_box, height=5)
            gallery_list.pack(fill=tk.X, padx=10, pady=6)

            def add_gallery_files():
                paths = filedialog.askopenfilenames(
                    filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")]
                )
                for p in paths:
                    if p not in gallery_files:
                        gallery_files.append(p)
                        gallery_list.insert(tk.END, p)

            def remove_gallery_files():
                sel = gallery_list.curselection()
                for idx in reversed(sel):
                    gallery_files.pop(idx)
                    gallery_list.delete(idx)

            gallery_btns = ttk.Frame(gallery_box)
            gallery_btns.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Button(gallery_btns, text="Add Images", command=add_gallery_files).pack(
                side=tk.LEFT
            )
            ttk.Button(
                gallery_btns, text="Remove Selected", command=remove_gallery_files
            ).pack(side=tk.LEFT, padx=6)

            gallery_out = tk.StringVar(master=self.root)
            self._save_row(
                gallery_box,
                "Output ZIP",
                gallery_out,
                def_ext=".zip",
                filetypes=[("ZIP", "*.zip")],
            )

            def build_gallery():
                if not gallery_files:
                    messagebox.showerror("Error", "Add at least one image.")
                    return
                if not gallery_out.get():
                    messagebox.showerror("Error", "Select an output zip.")
                    return
                with zipfile.ZipFile(
                    gallery_out.get(), "w", compression=zipfile.ZIP_DEFLATED
                ) as zf:
                    for p in gallery_files:
                        zf.write(p, arcname=Path(p).name)
                messagebox.showinfo(
                    "Success", "Gallery zip created. Embed it as a payload file."
                )

            ttk.Button(
                gallery_box, text="Create Gallery ZIP", command=build_gallery
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_batch_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            batch_encode = ttk.Labelframe(container, text="Batch Encode Images")
            batch_encode.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

            files_var = []
            listbox = tk.Listbox(batch_encode, height=6)
            listbox.pack(fill=tk.X, padx=10, pady=6)

            def add_files():
                paths = filedialog.askopenfilenames(
                    filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")]
                )
                for p in paths:
                    if p not in files_var:
                        files_var.append(p)
                        listbox.insert(tk.END, p)

            def remove_selected():
                sel = listbox.curselection()
                for idx in reversed(sel):
                    files_var.pop(idx)
                    listbox.delete(idx)

            btn_row = ttk.Frame(batch_encode)
            btn_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Button(btn_row, text="Add Files", command=add_files).pack(side=tk.LEFT)
            ttk.Button(btn_row, text="Remove Selected", command=remove_selected).pack(
                side=tk.LEFT, padx=6
            )

            msg_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_dir_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)

            ttk.Label(batch_encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(batch_encode, textvariable=msg_var).pack(
                fill=tk.X, padx=10, pady=(0, 6)
            )
            ttk.Label(batch_encode, text="Password (optional)").pack(
                anchor=tk.W, padx=10
            )
            ttk.Entry(batch_encode, textvariable=pwd_var, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 6)
            )

            method_row = ttk.Frame(batch_encode)
            method_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                method_row,
                textvariable=method_var,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(method_row, textvariable=prng_var, width=28).pack(
                side=tk.LEFT, padx=8
            )

            ttk.Checkbutton(
                batch_encode, text="Compress payload", variable=compress_var
            ).pack(anchor=tk.W, padx=10)

            out_row = ttk.Frame(batch_encode)
            out_row.pack(fill=tk.X, padx=10, pady=(6, 8))
            ttk.Label(out_row, text="Output folder").pack(side=tk.LEFT)
            ttk.Entry(out_row, textvariable=out_dir_var).pack(
                side=tk.LEFT, fill=tk.X, expand=True, padx=8
            )
            ttk.Button(
                out_row,
                text="Browse",
                command=lambda: out_dir_var.set(filedialog.askdirectory()),
            ).pack(side=tk.LEFT)

            ttk.Button(
                batch_encode,
                text="Run Batch Encode",
                command=lambda: self._batch_encode_images(
                    files_var,
                    msg_var.get(),
                    pwd_var.get(),
                    out_dir_var.get(),
                    method_var.get(),
                    prng_var.get(),
                    compress_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            batch_decode = ttk.Labelframe(container, text="Batch Decode Images")
            batch_decode.pack(fill=tk.BOTH, expand=True)

            dec_files = []
            dec_list = tk.Listbox(batch_decode, height=6)
            dec_list.pack(fill=tk.X, padx=10, pady=6)

            def add_dec_files():
                paths = filedialog.askopenfilenames(
                    filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")]
                )
                for p in paths:
                    if p not in dec_files:
                        dec_files.append(p)
                        dec_list.insert(tk.END, p)

            def remove_dec_selected():
                sel = dec_list.curselection()
                for idx in reversed(sel):
                    dec_files.pop(idx)
                    dec_list.delete(idx)

            dec_btn_row = ttk.Frame(batch_decode)
            dec_btn_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Button(dec_btn_row, text="Add Files", command=add_dec_files).pack(
                side=tk.LEFT
            )
            ttk.Button(
                dec_btn_row, text="Remove Selected", command=remove_dec_selected
            ).pack(side=tk.LEFT, padx=6)

            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_dir = tk.StringVar(master=self.root)
            dec_method = tk.StringVar(master=self.root, value="lsb")
            dec_prng = tk.StringVar(master=self.root)

            ttk.Label(batch_decode, text="Password (optional)").pack(
                anchor=tk.W, padx=10
            )
            ttk.Entry(batch_decode, textvariable=dec_pwd_var, show="*").pack(
                fill=tk.X, padx=10, pady=(0, 6)
            )

            dec_method_row = ttk.Frame(batch_decode)
            dec_method_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(dec_method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                dec_method_row,
                textvariable=dec_method,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(dec_method_row, textvariable=dec_prng, width=28).pack(
                side=tk.LEFT, padx=8
            )

            out_dec_row = ttk.Frame(batch_decode)
            out_dec_row.pack(fill=tk.X, padx=10, pady=(6, 8))
            ttk.Label(out_dec_row, text="Output folder").pack(side=tk.LEFT)
            ttk.Entry(out_dec_row, textvariable=dec_out_dir).pack(
                side=tk.LEFT, fill=tk.X, expand=True, padx=8
            )
            ttk.Button(
                out_dec_row,
                text="Browse",
                command=lambda: dec_out_dir.set(filedialog.askdirectory()),
            ).pack(side=tk.LEFT)

            ttk.Button(
                batch_decode,
                text="Run Batch Decode",
                command=lambda: self._batch_decode_images(
                    dec_files,
                    dec_pwd_var.get(),
                    dec_out_dir.get(),
                    dec_method.get(),
                    dec_prng.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_analyze_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            compare = ttk.Labelframe(container, text="Image Comparison")
            compare.pack(fill=tk.X)

            original_var = tk.StringVar(master=self.root)
            stego_var = tk.StringVar(master=self.root)
            diff_out = tk.StringVar(master=self.root)
            result_var = tk.StringVar(master=self.root, value="")

            self._file_row(
                compare,
                "Original image",
                original_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
            )
            self._file_row(
                compare,
                "Stego image",
                stego_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
            )
            self._save_row(
                compare,
                "Diff output (optional)",
                diff_out,
                def_ext=".png",
                filetypes=[("PNG", "*.png")],
            )

            ttk.Button(
                compare,
                text="Analyze",
                command=lambda: self._analyze_images(
                    original_var.get(), stego_var.get(), diff_out.get(), result_var
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            ttk.Label(compare, textvariable=result_var).pack(
                anchor=tk.W, padx=10, pady=(0, 10)
            )

            detect = ttk.Labelframe(container, text="Stego Detection")
            detect.pack(fill=tk.X, pady=(12, 0))

            detect_image = tk.StringVar(master=self.root)
            detect_method = tk.StringVar(master=self.root, value="lsb")
            detect_prng = tk.StringVar(master=self.root)
            detect_result = tk.StringVar(master=self.root, value="")

            self._file_row(
                detect,
                "Image",
                detect_image,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
            )

            detect_row = ttk.Frame(detect)
            detect_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(detect_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                detect_row,
                textvariable=detect_method,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(detect_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(detect_row, textvariable=detect_prng, width=28).pack(
                side=tk.LEFT, padx=8
            )

            ttk.Button(
                detect,
                text="Detect",
                command=lambda: self._detect_image(
                    detect_image.get(),
                    detect_method.get(),
                    detect_prng.get(),
                    detect_result,
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))

            ttk.Label(detect, textvariable=detect_result).pack(
                anchor=tk.W, padx=10, pady=(0, 8)
            )

            security = ttk.Labelframe(container, text="Security Analysis")
            security.pack(fill=tk.X, pady=(12, 0))

            sec_image = tk.StringVar(master=self.root)
            sec_method = tk.StringVar(master=self.root, value="lsb")
            sec_prng = tk.StringVar(master=self.root)
            sec_result = tk.StringVar(master=self.root, value="")

            self._file_row(
                security,
                "Image",
                sec_image,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
            )
            sec_row = ttk.Frame(security)
            sec_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(sec_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                sec_row,
                textvariable=sec_method,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(sec_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(sec_row, textvariable=sec_prng, width=28).pack(
                side=tk.LEFT, padx=8
            )

            ttk.Button(
                security,
                text="Rate Security",
                command=lambda: self._security_analysis(
                    sec_image.get(), sec_method.get(), sec_prng.get(), sec_result
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(security, textvariable=sec_result).pack(
                anchor=tk.W, padx=10, pady=(0, 8)
            )

        def _update_image_preview(self, path: str) -> None:
            if not path:
                self.preview_image.configure(text="No image selected", image="")
                self._preview_image_ref = None
                return
            try:
                img = Image.open(path)
                img.thumbnail((260, 200))
                tk_img = ImageTk.PhotoImage(img)
                self.preview_image.configure(image=tk_img, text="")
                self._preview_image_ref = tk_img
            except Exception:
                self.preview_image.configure(text="Preview unavailable", image="")
                self._preview_image_ref = None

        def _update_audio_preview(self, path: str) -> None:
            if not path:
                self.preview_audio.configure(text="No audio selected")
                return
            try:
                self.preview_audio.configure(text=get_audio_preview_text(path))
            except Exception:
                self.preview_audio.configure(text="Preview unavailable")

        def _update_video_preview(self, path: str) -> None:
            if not path:
                self.preview_video.configure(text="No video selected", image="")
                self._preview_video_ref = None
                return
            try:
                img = load_video_preview_frame(path)
                img.thumbnail((260, 160))
                tk_img = ImageTk.PhotoImage(img)
                self.preview_video.configure(image=tk_img, text="")
                self._preview_video_ref = tk_img
            except Exception:
                self.preview_video.configure(text="Preview unavailable", image="")
                self._preview_video_ref = None

        def _update_pdf_preview(self, path: str) -> None:
            if not path:
                self.preview_pdf.configure(text="No PDF selected")
                return
            try:
                reader = PdfReader(path)
                pages = len(reader.pages)
                snippet = ""
                if pages:
                    snippet = reader.pages[0].extract_text() or ""
                    snippet = " ".join(snippet.split())[:280]
                name = Path(path).name
                info = f"{name}\nPages: {pages}"
                if snippet:
                    info += f"\n{snippet}"
                self.preview_pdf.configure(text=info)
            except Exception:
                self.preview_pdf.configure(text="Preview unavailable")

        def _build_history_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            self.history_view = ttk.Treeview(
                container,
                columns=("time", "action", "status", "details"),
                show="headings",
            )
            for col, width in [
                ("time", 160),
                ("action", 160),
                ("status", 100),
                ("details", 700),
            ]:
                self.history_view.heading(col, text=col.title())
                self.history_view.column(col, width=width, anchor=tk.W)
            self.history_view.pack(fill=tk.BOTH, expand=True)

            btn_row = ttk.Frame(container)
            btn_row.pack(fill=tk.X, pady=8)
            ttk.Button(btn_row, text="Clear History", command=self._clear_history).pack(
                side=tk.LEFT
            )

        def _file_row(
            self,
            parent: ttk.Frame,
            label: str,
            var: tk.StringVar,
            filetypes=None,
            on_change=None,
        ) -> None:
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, padx=10, pady=6)
            ttk.Label(row, text=label).pack(side=tk.LEFT)
            entry = ttk.Entry(row, textvariable=var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
            ttk.Button(
                row, text="Browse", command=lambda: self._pick_file(var, filetypes)
            ).pack(side=tk.LEFT)

            if on_change is not None:
                var.trace_add("write", lambda *_: on_change(var.get()))

            if dnd_available:
                entry.drop_target_register(DND_FILES)
                entry.dnd_bind("<<Drop>>", lambda e: self._handle_drop(e, var))

        def _save_row(
            self,
            parent: ttk.Frame,
            label: str,
            var: tk.StringVar,
            def_ext: str,
            filetypes=None,
        ) -> None:
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, padx=10, pady=6)
            ttk.Label(row, text=label).pack(side=tk.LEFT)
            ttk.Entry(row, textvariable=var).pack(
                side=tk.LEFT, fill=tk.X, expand=True, padx=8
            )
            ttk.Button(
                row,
                text="Save As",
                command=lambda: self._save_file(var, def_ext, filetypes),
            ).pack(side=tk.LEFT)

        def _pick_file(self, var: tk.StringVar, filetypes=None) -> None:
            path = filedialog.askopenfilename(
                filetypes=filetypes or [("All Files", "*.*")]
            )
            if path:
                var.set(path)

        def _save_file(self, var: tk.StringVar, def_ext: str, filetypes=None) -> None:
            path = filedialog.asksaveasfilename(
                defaultextension=def_ext, filetypes=filetypes or [("All Files", "*.*")]
            )
            if path:
                var.set(path)

        def _handle_drop(self, event, var: tk.StringVar) -> None:
            handle_dnd_drop(event.data, event.widget, var)

        def _paste_clipboard(self) -> str:
            try:
                return self.root.clipboard_get()
            except Exception:
                return ""

        def _set_status(self, text: str) -> None:
            self.status.set_status(text)

        def _add_history(self, action: str, status: str, details: str) -> None:
            item = HistoryItem(
                time.strftime("%Y-%m-%d %H:%M:%S"), action, status, details
            )
            self.history.append(item)
            self.history_view.insert(
                "",
                tk.END,
                values=(item.timestamp, item.action, item.status, item.details),
            )

        def _clear_history(self) -> None:
            self.history.clear()
            for row in self.history_view.get_children():
                self.history_view.delete(row)

        def _vault_path(self) -> Path:
            return Path.home() / ".steg_keys.json"

        def _load_vault(self, master_password: str) -> dict[str, str]:
            return load_encrypted_vault(self._vault_path(), master_password)

        def _save_vault(self, master_password: str, payload: dict[str, str]) -> None:
            save_encrypted_vault(self._vault_path(), master_password, payload)

        def _templates_path(self) -> Path:
            return Path.home() / ".steg_templates.json"

        def _load_templates(self) -> dict[str, dict[str, str]]:
            return load_plaintext_templates(self._templates_path())

        def _save_templates(self, templates: dict[str, dict[str, str]]) -> None:
            save_plaintext_templates(self._templates_path(), templates)

        def _run_command(
            self,
            cmd: list[str],
            action: str,
            on_success: Optional[Callable[[str], None]] = None,
            *,
            password: str | None = None,
            prng_key: str | None = None,
        ) -> None:
            command, credential_input = build_secret_command(
                cmd, password=password, prng_key=prng_key
            )

            def task():
                self.root.after(0, lambda: self._set_status(f"{action} in progress"))
                self.root.after(0, self.status.start)
                try:
                    run_options: dict[str, Any] = {
                        "capture_output": True,
                        "text": True,
                        "timeout": 600,
                    }
                    if credential_input is not None:
                        run_options["input"] = credential_input
                    result = subprocess.run(command, **run_options)
                    stdout = result.stdout.strip()
                    stderr = result.stderr.strip()
                    if result.returncode == 0:
                        self.root.after(0, self.status.stop)
                        self.root.after(
                            0, lambda: self._set_status(f"{action} complete")
                        )
                        self.root.after(
                            0,
                            lambda: self._add_history(
                                action, "Success", stdout or "OK"
                            ),
                        )
                        if on_success:
                            self.root.after(0, lambda: on_success(stdout))
                    else:
                        msg = stderr or stdout or "Operation failed"
                        self.root.after(0, self.status.stop)
                        self.root.after(0, lambda: self._set_status(f"{action} failed"))
                        self.root.after(
                            0, lambda: self._add_history(action, "Failed", msg[:200])
                        )
                        self.root.after(0, lambda: messagebox.showerror("Error", msg))
                except Exception as exc:
                    self.root.after(0, self.status.stop)
                    self.root.after(0, lambda: self._set_status(f"{action} error"))
                    self.root.after(
                        0,
                        lambda e=exc: self._add_history(action, "Error", str(e)),
                    )
                    self.root.after(
                        0, lambda e=exc: messagebox.showerror("Error", str(e))
                    )

            threading.Thread(target=task, daemon=True).start()

        def _encode_image(
            self,
            cover: str,
            message: str,
            payload_file: str,
            password: str,
            output: str,
            method: str,
            prng_key: str,
            compress: bool,
            comment: str,
            expires: str,
        ) -> None:
            if not cover:
                messagebox.showerror("Error", "Select a cover image.")
                return
            try:
                payload_arguments = payload_source_arguments(message, payload_file)
            except ValueError as exc:
                messagebox.showerror("Error", str(exc))
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror(
                    "Error", "PRNG key is required for the selected method."
                )
                return
            if Path(output).suffix.lower() != ".png":
                messagebox.showerror(
                    "Error", "Output file must be PNG for image encoding."
                )
                return

            cmd = build_cli_command(
                "encode",
                "--image",
                cover,
                "--out",
                output,
                "--method",
                method,
            )
            cmd.extend(payload_arguments)
            if compress:
                cmd.append("--compress")
            if comment:
                cmd.extend(["--comment", comment])
            if expires:
                cmd.extend(["--expires", expires])

            def on_success(_stdout: str) -> None:
                messagebox.showinfo(
                    "Image encode complete",
                    build_image_encode_success_message(output),
                )

            self._run_command(
                cmd,
                "Image encode",
                on_success,
                password=password,
                prng_key=prng_key,
            )

        def _decode_image(
            self, stego: str, password: str, output: str, method: str, prng_key: str
        ) -> None:
            if not stego:
                messagebox.showerror("Error", "Select a stego image.")
                return
            if not output.strip():
                messagebox.showerror(
                    "Error", "Select an output file path for extracted data."
                )
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror(
                    "Error", "PRNG key is required for the selected method."
                )
                return

            cmd = build_image_decode_command(stego, output, method)

            def on_success(_stdout: str) -> None:
                messagebox.showinfo("Success", f"Decoded output saved to {output}")

            self._run_command(
                cmd,
                "Image decode",
                on_success,
                password=password,
                prng_key=prng_key,
            )

        def _encode_media(
            self,
            media_type: str,
            input_path: str,
            message: str,
            payload_file: str,
            password: str,
            output: str,
            compress: bool,
            comment: str,
            expires: str,
        ) -> None:
            if not input_path:
                messagebox.showerror("Error", f"Select a {media_type.upper()} file.")
                return
            try:
                payload_source_arguments(message, payload_file)
            except ValueError as exc:
                messagebox.showerror("Error", str(exc))
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return

            cmd = build_metadata_encode_command(
                media_type,
                input_path,
                output,
                message=message,
                payload_file=payload_file or None,
                password=password or None,
                compress=compress,
                comment=comment or None,
                expires=expires or None,
            )
            self._run_command(cmd, f"{media_type.upper()} encode", password=password)

        def _decode_media(
            self,
            media_type: str,
            input_path: str,
            password: str,
            output: str,
        ) -> None:
            if not input_path:
                messagebox.showerror("Error", f"Select a {media_type.upper()} file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return

            cmd = build_metadata_decode_command(
                media_type, input_path, output, password=password or None
            )
            self._run_command(cmd, f"{media_type.upper()} decode", password=password)

        def _encode_pdf(
            self,
            pdf_path: str,
            message: str,
            payload_file: str,
            password: str,
            output: str,
            compress: bool,
            comment: str,
            expires: str,
        ) -> None:
            if not pdf_path:
                messagebox.showerror("Error", "Select a PDF file.")
                return
            try:
                payload_source_arguments(message, payload_file)
            except ValueError as exc:
                messagebox.showerror("Error", str(exc))
                return
            if not output:
                messagebox.showerror("Error", "Select an output PDF.")
                return

            cmd = build_metadata_encode_command(
                "pdf",
                pdf_path,
                output,
                message=message,
                payload_file=payload_file or None,
                password=password or None,
                compress=compress,
                comment=comment or None,
                expires=expires or None,
            )

            self._run_command(cmd, "PDF encode", password=password)

        def _decode_pdf(self, pdf_path: str, password: str, output: str) -> None:
            if not pdf_path:
                messagebox.showerror("Error", "Select a PDF file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return

            cmd = build_metadata_decode_command(
                "pdf", pdf_path, output, password=password or None
            )

            def on_success(_stdout: str) -> None:
                messagebox.showinfo("Success", f"Decoded output saved to {output}")

            self._run_command(cmd, "PDF decode", on_success, password=password)

        def _encode_video_frame(
            self,
            video_path: str,
            frame_index: int,
            message: str,
            payload_file: str,
            password: str,
            output: str,
            method: str,
            prng_key: str,
            compress: bool,
            comment: str,
            expires: str,
        ) -> None:
            if not video_path:
                messagebox.showerror("Error", "Select a video file.")
                return
            try:
                payload_arguments = payload_source_arguments(message, payload_file)
            except ValueError as exc:
                messagebox.showerror("Error", str(exc))
                return
            if not output:
                messagebox.showerror("Error", "Select an output video.")
                return
            if Path(output).suffix.lower() != ".mkv":
                messagebox.showerror(
                    "Error", "Video-frame output must use lossless MKV format."
                )
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror(
                    "Error", "PRNG key is required for the selected method."
                )
                return

            cmd = build_cli_command(
                "video-frame-encode",
                "--video",
                video_path,
                "--out",
                output,
                "--frame",
                str(frame_index),
                "--method",
                method,
            )
            cmd.extend(payload_arguments)
            if compress:
                cmd.append("--compress")
            if comment:
                cmd.extend(["--comment", comment])
            if expires:
                cmd.extend(["--expires", expires])

            self._run_command(
                cmd, "Video frame encode", password=password, prng_key=prng_key
            )

        def _decode_video_frame(
            self,
            video_path: str,
            frame_index: int,
            password: str,
            output: str,
            method: str,
            prng_key: str,
        ) -> None:
            if not video_path:
                messagebox.showerror("Error", "Select a video file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror(
                    "Error", "PRNG key is required for the selected method."
                )
                return

            cmd = build_cli_command(
                "video-frame-decode",
                "--video",
                video_path,
                "--frame",
                str(frame_index),
                "--method",
                method,
                "--out",
                output,
            )

            def on_success(_stdout: str) -> None:
                messagebox.showinfo("Success", f"Decoded output saved to {output}")

            self._run_command(
                cmd,
                "Video frame decode",
                on_success,
                password=password,
                prng_key=prng_key,
            )

        def _batch_encode_images(
            self,
            files: list[str],
            message: str,
            password: str,
            output_dir: str,
            method: str,
            prng_key: str,
            compress: bool,
        ) -> None:
            if not files:
                messagebox.showerror("Error", "Add at least one image file.")
                return
            if not message:
                messagebox.showerror("Error", "Enter a message to embed.")
                return
            if not output_dir:
                messagebox.showerror("Error", "Select an output folder.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror(
                    "Error", "PRNG key is required for the selected method."
                )
                return

            source_files = list(files)
            try:
                destinations = plan_batch_output_paths(
                    source_files, output_dir, "encode"
                )
            except (FileExistsError, NotADirectoryError, ValueError) as exc:
                messagebox.showerror("Error", str(exc))
                return

            commands = []
            credential_inputs = []
            for source, destination in zip(source_files, destinations):
                command = build_cli_command(
                    "encode",
                    "--image",
                    source,
                    "--out",
                    str(destination),
                    "--message",
                    message,
                    "--method",
                    method,
                )
                if compress:
                    command.append("--compress")
                command, credential_input = build_secret_command(
                    command, password=password, prng_key=prng_key
                )
                commands.append(command)
                credential_inputs.append(credential_input)

            def on_progress(index: int, total: int) -> None:
                self.root.after(
                    0,
                    lambda i=index, count=total: self._set_status(
                        f"Batch encode {i}/{count}"
                    ),
                )

            def on_finished(error: Exception | None) -> None:
                self.root.after(0, self.status.stop)
                if error is None:
                    self.root.after(
                        0, lambda: self._set_status("Batch encode complete")
                    )
                    self.root.after(
                        0,
                        lambda: self._add_history(
                            "Batch encode", "Success", f"{len(source_files)} files"
                        ),
                    )
                    return
                error_message = str(error)
                self.root.after(0, lambda: self._set_status("Batch encode failed"))
                self.root.after(
                    0,
                    lambda e=error_message: self._add_history(
                        "Batch encode", "Failed", e[:200]
                    ),
                )
                self.root.after(
                    0,
                    lambda e=error_message: messagebox.showerror("Error", e),
                )

            def task():
                self.root.after(0, self.status.start)
                self.root.after(0, lambda: self._set_status("Batch encode in progress"))
                run_batch_commands(
                    commands,
                    credential_inputs=credential_inputs,
                    on_progress=on_progress,
                    on_finished=on_finished,
                    destinations=destinations,
                )

            threading.Thread(target=task, daemon=True).start()

        def _batch_decode_images(
            self,
            files: list[str],
            password: str,
            output_dir: str,
            method: str,
            prng_key: str,
        ) -> None:
            if not files:
                messagebox.showerror("Error", "Add at least one image file.")
                return
            if not output_dir:
                messagebox.showerror("Error", "Select an output folder.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror(
                    "Error", "PRNG key is required for the selected method."
                )
                return

            source_files = list(files)
            try:
                destinations = plan_batch_output_paths(
                    source_files, output_dir, "decode"
                )
            except (FileExistsError, NotADirectoryError, ValueError) as exc:
                messagebox.showerror("Error", str(exc))
                return

            commands = []
            credential_inputs = []
            for source, destination in zip(source_files, destinations):
                command = build_cli_command(
                    "decode",
                    "--image",
                    source,
                    "--out",
                    str(destination),
                    "--method",
                    method,
                )
                command, credential_input = build_secret_command(
                    command, password=password, prng_key=prng_key
                )
                commands.append(command)
                credential_inputs.append(credential_input)

            def on_progress(index: int, total: int) -> None:
                self.root.after(
                    0,
                    lambda i=index, count=total: self._set_status(
                        f"Batch decode {i}/{count}"
                    ),
                )

            def on_finished(error: Exception | None) -> None:
                self.root.after(0, self.status.stop)
                if error is None:
                    self.root.after(
                        0, lambda: self._set_status("Batch decode complete")
                    )
                    self.root.after(
                        0,
                        lambda: self._add_history(
                            "Batch decode", "Success", f"{len(source_files)} files"
                        ),
                    )
                    return
                error_message = str(error)
                self.root.after(0, lambda: self._set_status("Batch decode failed"))
                self.root.after(
                    0,
                    lambda e=error_message: self._add_history(
                        "Batch decode", "Failed", e[:200]
                    ),
                )
                self.root.after(
                    0,
                    lambda e=error_message: messagebox.showerror("Error", e),
                )

            def task():
                self.root.after(0, self.status.start)
                self.root.after(0, lambda: self._set_status("Batch decode in progress"))
                run_batch_commands(
                    commands,
                    credential_inputs=credential_inputs,
                    on_progress=on_progress,
                    on_finished=on_finished,
                    destinations=destinations,
                )

            threading.Thread(target=task, daemon=True).start()

        def _analyze_images(
            self, original: str, stego: str, diff_out: str, result_var: tk.StringVar
        ) -> None:
            if not original or not stego:
                messagebox.showerror("Error", "Select both original and stego images.")
                return
            try:
                img_a = Image.open(original).convert("RGB")
                img_b = Image.open(stego).convert("RGB")
                if img_a.size != img_b.size:
                    messagebox.showerror(
                        "Error", "Images must be the same size for comparison."
                    )
                    return
                diff = ImageChops.difference(img_a, img_b)
                psnr = compute_psnr(img_a, img_b)
                if diff_out:
                    diff.save(diff_out)
                result = f"PSNR: {psnr:.2f} dB"
                if diff_out:
                    result += f" | Diff saved: {diff_out}"
                result_var.set(result)
                self._add_history("Analyze", "Success", result)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def _detect_image(
            self,
            image_path: str,
            method: str,
            prng_key: str,
            result_var: tk.StringVar,
        ) -> None:
            if not image_path:
                messagebox.showerror("Error", "Select an image.")
                return
            try:
                image = load_image(image_path)
                heuristic = format_pair_chi_square_feedback(lsb_pair_chi_square(image))
                if method not in ("lsb", "lsb-prng", "lsb-match-prng"):
                    raise ValueError("Unknown method")
                if method != "lsb" and not prng_key:
                    messagebox.showerror("Error", "PRNG key required for PRNG methods.")
                    return
                try:
                    header = extract_image_header(image, method, prng_key)
                except ValueError:
                    result_var.set(f"No stego header detected. {heuristic}")
                    return

                flags = []
                if header.flags & FLAG_ENCRYPTED:
                    flags.append("Encrypted")
                if header.flags & FLAG_PRNG:
                    flags.append("PRNG")
                if header.flags & FLAG_LSB_MATCH:
                    flags.append("LSB-match")
                if header.flags & FLAG_COMPRESSED:
                    flags.append("Compressed")
                payload = (
                    "Image" if (header.flags & FLAG_PAYLOAD_IMAGE) else "Text/File"
                )
                result = (
                    f"Stego header detected | Payload: {payload} | "
                    f"Flags: {', '.join(flags) or 'None'}\n{heuristic}"
                )
                result_var.set(result)
                self._add_history("Detect", "Success", result)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def _security_analysis(
            self,
            image_path: str,
            method: str,
            prng_key: str,
            result_var: tk.StringVar,
        ) -> None:
            if not image_path:
                messagebox.showerror("Error", "Select an image.")
                return
            try:
                stego_data = extract_stego_data_from_image(
                    load_image(image_path), method, prng_key
                )
                header = parse_header(stego_data)
                flags = header.flags
                score = 0
                if flags & FLAG_ENCRYPTED:
                    score += 2
                if flags & FLAG_PRNG:
                    score += 2
                if flags & FLAG_LSB_MATCH:
                    score += 1
                if flags & FLAG_COMPRESSED:
                    score += 1
                rating = "Low"
                if score >= 4:
                    rating = "High"
                elif score >= 2:
                    rating = "Medium"
                result = (
                    f"Security setting score: {rating} (score {score}); "
                    "this is a configuration summary, not a security guarantee."
                )
                result_var.set(result)
                self._add_history("Security analysis", "Success", result)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def _show_text_output(self, text: str) -> None:
            win = tk.Toplevel(self.root)
            win.title("Decoded Text")
            win.geometry("700x400")

            # Apply theme based on mode
            if self._detect_dark_mode():
                win.configure(bg="#2b2d31")
                txt = tk.Text(
                    win,
                    wrap=tk.WORD,
                    bg="#1e1f22",
                    fg="#dcddde",
                    insertbackground="#dcddde",
                    borderwidth=0,
                    padx=8,
                    pady=8,
                )
            else:
                win.configure(bg="SystemButtonFace")
                txt = tk.Text(
                    win,
                    wrap=tk.WORD,
                    bg="white",
                    fg="black",
                    insertbackground="black",
                    padx=8,
                    pady=8,
                )
            txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
            txt.insert(tk.END, text)
            txt.config(state=tk.DISABLED)

            btn_row = ttk.Frame(win)
            btn_row.pack(fill=tk.X, padx=8, pady=(0, 8))
            ttk.Button(
                btn_row,
                text="Copy to Clipboard",
                command=lambda: self._copy_to_clipboard(text),
            ).pack(side=tk.LEFT)

        def _copy_to_clipboard(self, text: str) -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

    root, dnd_available = _create_tk_root(tk, TkinterDnD if dnd_available else None)

    root.title("Steganography Suite")
    SteganographyGUI(root)
    root.mainloop()


if __name__ == "__main__":
    raise SystemExit(main())
