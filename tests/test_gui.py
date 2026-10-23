"""Tests for GUI behavior and the helpers it presents to users."""

import sys
import zipfile
import os
from pathlib import Path

import pytest
from PIL import Image


@pytest.fixture
def tk_root():
    """Create a real Tcl interpreter when a display is available."""
    require_tk = os.environ.get("REQUIRE_TK", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    try:
        import tkinter as tk
    except ImportError as exc:
        if require_tk:
            pytest.fail(f"Tk runtime is required but unavailable: {exc}")
        pytest.skip(f"Tk runtime unavailable: {exc}")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        if require_tk:
            pytest.fail(f"Tk display is required but unavailable: {exc}")
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    yield root
    root.destroy()


def test_required_tk_fixture_fails_instead_of_skipping_without_display(monkeypatch):
    class FakeTk:
        class TclError(Exception):
            pass

        @staticmethod
        def Tk():
            raise FakeTk.TclError("no display")

    monkeypatch.setitem(sys.modules, "tkinter", FakeTk)
    monkeypatch.setenv("REQUIRE_TK", "1")
    fixture_generator = tk_root.__wrapped__()

    with pytest.raises(pytest.fail.Exception, match="Tk display is required"):
        next(fixture_generator)


def test_tk_fixture_keeps_local_skip_when_tk_is_not_required(monkeypatch):
    class FakeTk:
        class TclError(Exception):
            pass

        @staticmethod
        def Tk():
            raise FakeTk.TclError("no display")

    monkeypatch.setitem(sys.modules, "tkinter", FakeTk)
    monkeypatch.delenv("REQUIRE_TK", raising=False)
    fixture_generator = tk_root.__wrapped__()

    with pytest.raises(pytest.skip.Exception, match="Tk display unavailable"):
        next(fixture_generator)


def test_gui_module_imports_without_creating_a_window():
    from gui import main

    assert callable(main.gui_main)


def test_cli_command_builder_uses_current_python_and_resolved_app_path():
    from gui.main import build_cli_command

    arguments = [
        "encode",
        "--image",
        "cover with {braces} ü.png",
        "--out",
        "output.png",
        "--message",
        "keep this as one argument",
    ]
    command = build_cli_command(*arguments)
    expected_app = Path(__file__).resolve().parents[1] / "app.py"

    assert command == [sys.executable, str(expected_app), *arguments]

    from app import build_parser

    parsed = build_parser().parse_args(command[2:])
    assert parsed.command == "encode"
    assert parsed.image == "cover with {braces} ü.png"
    assert parsed.message == "keep this as one argument"


def test_frozen_windows_command_uses_sibling_packaged_cli(tmp_path, monkeypatch):
    from app import build_parser
    from gui.main import build_cli_command

    executable = tmp_path / "dist" / "stego-gui.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "win32")

    command = build_cli_command(
        "decode", "--image", "cover image.png", "--out", "secret.bin"
    )

    assert command[0] == str(executable.with_name("stego-cli.exe"))
    parsed = build_parser().parse_args(command[1:])
    assert parsed.command == "decode"
    assert parsed.image == "cover image.png"
    assert parsed.out == "secret.bin"


def test_frozen_macos_app_command_uses_cli_sibling_outside_app_bundle(
    tmp_path, monkeypatch
):
    from app import build_parser
    from gui.main import build_cli_command

    executable = (
        tmp_path
        / "steganography-macos"
        / "stego-gui.app"
        / "Contents"
        / "MacOS"
        / "stego-gui"
    )
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "darwin")

    command = build_cli_command("qr", "--text", "snow 雪", "--out", "qr.png")

    assert command[0] == str(executable.parents[3] / "stego-cli")
    parsed = build_parser().parse_args(command[1:])
    assert parsed.command == "qr"
    assert parsed.text == "snow 雪"
    assert parsed.out == "qr.png"


def test_frozen_portable_decoder_contains_packaged_cli_and_launcher(tmp_path):
    from gui.main import build_frozen_portable_decoder

    cli = tmp_path / "stego-cli.exe"
    cli.write_bytes(b"packaged executable")
    carrier = tmp_path / "cover image {draft} ü.png"
    carrier.write_bytes(b"carrier")
    archive = tmp_path / "portable decoder.zip"
    password = "frozen-password-92731"
    prng_key = "frozen-prng-key-48105"

    build_frozen_portable_decoder(
        carrier,
        archive,
        cli_path=cli,
        method="lsb-prng",
        prng_key=prng_key,
        password=password,
    )

    with zipfile.ZipFile(archive) as bundle:
        assert set(bundle.namelist()) == {
            cli.name,
            carrier.name,
            "run_decode.py",
            "README.txt",
        }
        runner = bundle.read("run_decode.py").decode("utf-8")
        text_contents = [
            bundle.read(name)
            for name in bundle.namelist()
            if name == "run_decode.py" or name.endswith(".txt")
        ]
    assert f"root / {cli.name!r}" in runner
    assert f"root / {carrier.name!r}" in runner
    assert "app.py" not in runner
    assert "'decode', '--image', str(target)" in runner
    assert "credentials['prng_key']" in runner
    assert "--credentials-stdin" in runner
    assert "'--prng-key'" not in runner
    assert "'--password'" not in runner
    assert all(password.encode() not in content for content in text_contents)
    assert all(prng_key.encode() not in content for content in text_contents)


def test_frozen_portable_decoder_launcher_does_not_pass_credentials_in_argv(tmp_path):
    from gui.main import build_frozen_portable_decoder

    cli = tmp_path / "stego-cli.exe"
    cli.write_bytes(b"packaged executable")
    carrier = tmp_path / "cover.png"
    carrier.write_bytes(b"carrier")
    archive = tmp_path / "decoder.zip"

    build_frozen_portable_decoder(
        carrier,
        archive,
        cli_path=cli,
        method="lsb-prng",
    )

    with zipfile.ZipFile(archive) as bundle:
        runner = bundle.read("run_decode.py").decode("utf-8")

    assert "--credentials-stdin" in runner
    assert "'--password'" not in runner
    assert "'--prng-key'" not in runner
    assert "input=json.dumps(credentials)" in runner


def test_frozen_portable_decoder_preserves_an_existing_output(tmp_path, monkeypatch):
    import runpy
    import subprocess
    from types import SimpleNamespace

    from gui.main import build_frozen_portable_decoder

    cli = tmp_path / "stego-cli.exe"
    cli.write_bytes(b"packaged executable")
    carrier = tmp_path / "cover.png"
    carrier.write_bytes(b"carrier")
    archive = tmp_path / "decoder.zip"
    build_frozen_portable_decoder(carrier, archive, cli_path=cli)

    extracted_dir = tmp_path / "extracted frozen decoder"
    extracted_dir.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(extracted_dir)

    existing_output = extracted_dir / "decoded_output.bin"
    existing_output.write_bytes(b"keep this recovered file")
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "")
    invocations = []

    def fake_cli_run(arguments, **kwargs):
        invocations.append((arguments, kwargs))
        output_path = Path(arguments[arguments.index("--out") + 1])
        output_path.write_bytes(b"second recovered file")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_cli_run)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(extracted_dir / "run_decode.py"), run_name="__main__")

    assert exit_info.value.code == 0
    assert existing_output.read_bytes() == b"keep this recovered file"
    assert (
        extracted_dir / "decoded_output-1.bin"
    ).read_bytes() == b"second recovered file"
    assert len(invocations) == 1
    arguments, options = invocations[0]
    assert "--credentials-stdin" in arguments
    assert options["input"] == '{"password": ""}'
    assert options["text"] is True


@pytest.mark.parametrize("linked_input", ("carrier", "cli"))
def test_frozen_portable_decoder_rejects_hard_link_output(tmp_path, linked_input):
    import os

    from gui.main import build_frozen_portable_decoder

    cli = tmp_path / "stego-cli.exe"
    cli.write_bytes(b"packaged executable")
    carrier = tmp_path / "cover.png"
    carrier.write_bytes(b"carrier")
    linked_source = carrier if linked_input == "carrier" else cli
    archive = tmp_path / "decoder.zip"
    try:
        os.link(linked_source, archive)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable in this test directory: {exc}")
    original = linked_source.read_bytes()

    with pytest.raises(ValueError, match="output must differ"):
        build_frozen_portable_decoder(carrier, archive, cli_path=cli)

    assert linked_source.read_bytes() == original


def test_frozen_file_association_registry_targets_packaged_cli(tmp_path, monkeypatch):
    import sys

    from gui.main import build_file_association_action

    executable = tmp_path / "dist" / "stego-gui.exe"
    cli = executable.with_name("stego-cli.exe")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "win32")
    registry = build_file_association_action(str(tmp_path / "association.reg"))

    assert isinstance(registry, str)
    assert str(cli).replace("\\", "\\\\") in registry
    assert r"decode --image \"%1\" --out \"%1.decoded\"" in registry
    assert "app.py" not in registry


def test_frozen_portable_decoder_action_builds_packaged_decoder_archive(
    tmp_path, monkeypatch
):
    import sys

    from gui.main import build_portable_decoder_action

    executable = tmp_path / "dist" / "stego-gui.exe"
    cli = executable.with_name("stego-cli.exe")
    cli.parent.mkdir()
    cli.write_bytes(b"packaged executable")
    carrier = tmp_path / "carrier.pdf"
    carrier.write_bytes(b"carrier")
    archive = tmp_path / "decoder.zip"

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "win32")
    command = build_portable_decoder_action(str(carrier), str(archive))

    assert command is None
    with zipfile.ZipFile(archive) as bundle:
        assert cli.name in bundle.namelist()
        runner = bundle.read("run_decode.py").decode("utf-8")
    assert "pdf-decode" in runner
    assert cli.name in runner
    assert "app.py" not in runner


def test_frozen_utilities_do_not_fall_back_to_missing_app_py(tmp_path, monkeypatch):
    import sys

    from gui.main import build_file_association_command, build_portable_decoder_command

    executable = tmp_path / "stego-gui.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "win32")

    with pytest.raises(RuntimeError, match="sibling CLI"):
        build_portable_decoder_command("carrier.png", "decoder.zip")
    with pytest.raises(RuntimeError, match="registry content"):
        build_file_association_command("association.reg")


def test_qr_utility_command_uses_registered_parser_arguments():
    from app import build_parser
    from gui.main import build_qr_command

    command = build_qr_command("example", "qr output.png")
    parsed = build_parser().parse_args(command[2:])

    assert parsed.command == "qr"
    assert parsed.text == "example"
    assert parsed.out == "qr output.png"


def test_portable_decoder_command_uses_registered_parser_arguments():
    from app import build_parser
    from gui.main import (
        PORTABLE_DECODER_CREDENTIAL_NOTICE,
        build_portable_decoder_command,
    )

    command = build_portable_decoder_command(
        "cover image.png",
        "decoder.zip",
        method="lsb-prng",
        prng_key="secret key",
        password="password",
        frame=3,
    )
    parsed = build_parser().parse_args(command[2:])

    assert parsed.command == "portable-decoder"
    assert parsed.stego == "cover image.png"
    assert parsed.out == "decoder.zip"
    assert parsed.method == "lsb-prng"
    assert parsed.prng_key is None
    assert parsed.password is None
    assert parsed.frame == 3
    assert "secret key" not in command
    assert "password" not in command
    assert "never store credentials" in PORTABLE_DECODER_CREDENTIAL_NOTICE
    assert "prompts" in PORTABLE_DECODER_CREDENTIAL_NOTICE


def test_file_association_command_supplies_all_required_parser_arguments():
    from app import build_parser
    from gui.main import build_file_association_command

    command = build_file_association_command("association.reg")
    parsed = build_parser().parse_args(command[2:])

    assert parsed.command == "file-assoc"
    assert parsed.out == "association.reg"
    assert parsed.app_path == str(Path(__file__).resolve().parents[1] / "app.py")
    assert parsed.python_path == sys.executable


def test_image_capacity_estimate_includes_header_crypto_and_metadata_boundaries():
    from gui.main import estimate_image_capacity

    image = Image.new("RGB", (32, 32), (40, 60, 80))
    metadata_json = b'{"comment": "memo", "expires": "2030-01-02"}'
    envelope_overhead = 12 + 16 + 12 + 16 + 4 + len(metadata_json)
    exact_payload = b"x" * (384 - envelope_overhead)

    exact = estimate_image_capacity(
        image,
        exact_payload,
        password="secret",
        compress=False,
        comment="memo",
        expires="2030-01-02",
    )
    overflow = estimate_image_capacity(
        image,
        exact_payload + b"x",
        password="secret",
        compress=False,
        comment="memo",
        expires="2030-01-02",
    )

    assert (exact.available_bytes, exact.required_bytes, exact.fits) == (384, 384, True)
    assert (overflow.available_bytes, overflow.required_bytes, overflow.fits) == (
        384,
        385,
        False,
    )


def test_image_capacity_estimate_includes_compression_of_metadata_and_payload():
    import zlib

    from gui.main import estimate_image_capacity

    image = Image.new("RGB", (64, 64), (40, 60, 80))
    payload = b"repeatable payload " * 20
    metadata_json = b'{"comment": "short note", "expires": "2030-01-02"}'
    prepared = len(metadata_json).to_bytes(4, "big") + metadata_json + payload
    expected_size = 12 + 16 + 12 + 16 + len(zlib.compress(prepared))

    estimate = estimate_image_capacity(
        image,
        payload,
        password="secret",
        compress=True,
        comment="short note",
        expires="2030-01-02",
    )

    assert estimate.required_bytes == expected_size
    assert estimate.available_bytes == 1536
    assert estimate.fits


def test_uncompressed_capacity_file_uses_stat_and_includes_full_envelope(
    tmp_path, monkeypatch
):
    from gui.main import (
        ImageCapacityRequest,
        estimate_image_capacity_message,
        format_capacity_bytes,
    )
    from stego.core import estimate_stego_payload_size

    cover_path = tmp_path / "cover.png"
    Image.new("RGB", (64, 64), (20, 30, 40)).save(cover_path)
    payload_path = tmp_path / "payload.bin"
    payload = b"uncompressed payload bytes"
    payload_path.write_bytes(payload)
    metadata = {"comment": "review", "expires": "2030-01-02"}
    expected = estimate_stego_payload_size(
        payload,
        encrypted=True,
        compress=False,
        metadata=metadata,
    )

    def fail_read(_path):
        pytest.fail("uncompressed file capacity must not read payload contents")

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    message = estimate_image_capacity_message(
        ImageCapacityRequest(
            str(cover_path),
            str(payload_path),
            "",
            "pw",
            False,
            metadata["comment"],
            metadata["expires"],
        )
    )

    assert message.startswith(
        f"Estimated encoded envelope: {format_capacity_bytes(expected)} / "
    )


def test_compressed_capacity_file_estimate_matches_exact_envelope(tmp_path):
    from gui.main import (
        ImageCapacityRequest,
        estimate_image_capacity_message,
        format_capacity_bytes,
    )
    from stego.core import estimate_stego_payload_size

    cover_path = tmp_path / "cover.png"
    Image.new("RGB", (128, 128), (20, 30, 40)).save(cover_path)
    payload_path = tmp_path / "payload.bin"
    payload = b"bounded compressed payload " * 100
    payload_path.write_bytes(payload)
    metadata = {"comment": "compressed", "expires": "2030-01-02"}
    expected = estimate_stego_payload_size(
        payload,
        encrypted=True,
        compress=True,
        metadata=metadata,
    )

    message = estimate_image_capacity_message(
        ImageCapacityRequest(
            str(cover_path),
            str(payload_path),
            "",
            "pw",
            True,
            metadata["comment"],
            metadata["expires"],
        )
    )

    assert message.startswith(
        f"Estimated encoded envelope: {format_capacity_bytes(expected)} / "
    )


def test_oversized_compressed_capacity_file_is_rejected_before_read(
    tmp_path, monkeypatch
):
    from gui.main import ImageCapacityRequest, estimate_image_capacity_message
    from stego.core import MAX_DECOMPRESSED_PAYLOAD_BYTES

    cover_path = tmp_path / "cover.png"
    Image.new("RGB", (16, 16), (20, 30, 40)).save(cover_path)
    payload_path = tmp_path / "oversized.bin"
    with payload_path.open("wb") as payload_file:
        payload_file.truncate(MAX_DECOMPRESSED_PAYLOAD_BYTES + 1)

    def fail_read(_path):
        pytest.fail("oversized compressed file must be rejected before reading")

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    original_open = Path.open

    def fail_payload_open(path, *args, **kwargs):
        if path == payload_path:
            pytest.fail("oversized compressed payload was opened before its size check")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_payload_open)
    with pytest.raises(ValueError, match="64 MiB compressed payload limit"):
        estimate_image_capacity_message(
            ImageCapacityRequest(
                str(cover_path), str(payload_path), "", None, True, None, None
            )
        )


def test_capacity_estimate_rejects_payload_directory(tmp_path):
    from gui.main import ImageCapacityRequest, estimate_image_capacity_message

    cover_path = tmp_path / "cover.png"
    Image.new("RGB", (16, 16), (20, 30, 40)).save(cover_path)
    payload_directory = tmp_path / "payload folder"
    payload_directory.mkdir()

    with pytest.raises(ValueError, match="Payload path is not a file"):
        estimate_image_capacity_message(
            ImageCapacityRequest(
                str(cover_path), str(payload_directory), "", None, False, None, None
            )
        )


def test_detectability_feedback_labels_the_statistic_as_heuristic_and_states_limits():
    from gui.main import format_pair_chi_square_feedback

    feedback = format_pair_chi_square_feedback(12.5)

    assert "Pair-values chi-square (heuristic): 12.50" in feedback
    assert "does not prove whether hidden data is present" in feedback
    assert "cannot guarantee undetectability" in feedback


def test_image_encode_success_message_includes_detector_result_and_limits(tmp_path):
    from gui.main import build_image_encode_success_message

    output = tmp_path / "encoded cover.png"
    image = Image.new("RGB", (2, 1))
    image.putdata([(100, 102, 104), (101, 103, 105)])
    image.save(output)

    message = build_image_encode_success_message(output)

    assert f"Saved PNG: {output}" in message
    assert "Pair-values chi-square (heuristic): 0.00" in message
    assert "does not prove whether hidden data is present" in message
    assert "cannot guarantee undetectability" in message


def test_tcl_drop_normalization_and_callback_preserve_complex_paths(tk_root):
    import tkinter as tk

    from gui.main import handle_dnd_drop, normalize_dnd_files

    paths = [
        r"C:\Users\Ada\Pictures\cover with braces {draft} ü.png",
        "/tmp/payload with spaces {notes} 雪.bin",
    ]
    event_data = tk_root.tk.call("list", *paths)
    string_event_data = " ".join(f"{{{path}}}" for path in paths)
    variable = tk.StringVar(master=tk_root)

    assert normalize_dnd_files(event_data, tk_root) == paths
    assert normalize_dnd_files(string_event_data, tk_root) == paths
    assert handle_dnd_drop(event_data, tk_root, variable) == paths
    assert variable.get() == paths[0]


def test_metadata_storage_notice_identifies_visible_metadata_and_disclosure():
    from gui.main import metadata_storage_notice

    notice = metadata_storage_notice("Audio")

    assert "visible metadata" in notice.lower()
    assert "not steganography" in notice.lower()
    assert "anyone inspecting" in notice.lower()
    assert "payload contents are readable unless" in notice.lower()
    assert "aes-gcm encryption" in notice.lower()


def test_macos_drag_and_drop_loads_into_the_existing_tk_root():
    from gui.main import _create_tk_root

    class FakeTkRoot:
        pass

    class FakeTkModule:
        def __init__(self):
            self.roots = []

        def Tk(self):
            root = FakeTkRoot()
            self.roots.append(root)
            return root

    class FakeDndModule:
        def __init__(self):
            self.roots = []

        def require(self, root):
            self.roots.append(root)

    tk_module = FakeTkModule()
    dnd_module = FakeDndModule()

    root, available = _create_tk_root(tk_module, dnd_module)

    assert available is True
    assert len(tk_module.roots) == 1
    assert dnd_module.roots == [root]


def test_drag_and_drop_dependency_failure_keeps_the_standard_tk_root():
    from gui.main import _create_tk_root

    class FakeTkRoot:
        pass

    class FakeTkModule:
        def __init__(self):
            self.root = FakeTkRoot()

        def Tk(self):
            return self.root

    class FailingDndModule:
        def require(self, _root):
            raise RuntimeError("tkdnd unavailable")

    tk_module = FakeTkModule()

    root, available = _create_tk_root(tk_module, FailingDndModule())

    assert root is tk_module.root
    assert available is False


@pytest.mark.parametrize("media_type", ["audio", "video", "pdf"])
def test_metadata_callbacks_build_registered_encode_and_decode_commands(media_type):
    from app import build_parser
    from gui.main import (
        build_metadata_decode_command,
        build_metadata_encode_command,
        metadata_storage_notice,
    )

    carrier_path = f"carrier with spaces.{media_type}"
    output_path = f"encoded carrier.{media_type}"
    encode = build_metadata_encode_command(
        media_type,
        carrier_path,
        output_path,
        payload_file="payload with spaces.bin",
        password="secret",
        compress=True,
        comment="visible comment",
        expires="2030-01-02",
    )
    parsed_encode = build_parser().parse_args(encode[2:])
    source_attr = "pdf" if media_type == "pdf" else media_type

    assert parsed_encode.command == f"{media_type}-encode"
    assert getattr(parsed_encode, source_attr) == carrier_path
    assert parsed_encode.out == output_path
    assert parsed_encode.in_file == "payload with spaces.bin"
    assert parsed_encode.password is None
    assert "secret" not in encode
    assert parsed_encode.compress is True
    assert parsed_encode.comment == "visible comment"
    assert parsed_encode.expires == "2030-01-02"

    decode = build_metadata_decode_command(
        media_type, carrier_path, f"decoded output.{media_type}", password="secret"
    )
    parsed_decode = build_parser().parse_args(decode[2:])
    assert parsed_decode.command == f"{media_type}-decode"
    assert getattr(parsed_decode, source_attr) == carrier_path
    assert parsed_decode.out == f"decoded output.{media_type}"
    assert parsed_decode.password is None
    assert "secret" not in decode

    label = "PDF" if media_type == "pdf" else media_type.title()
    notice = metadata_storage_notice(label)
    assert "visible metadata" in notice.lower()
    assert "not steganography" in notice.lower()
    assert "anyone inspecting" in notice.lower()


def test_media_selectors_include_verified_mp4_family_containers():
    from gui.main import AUDIO_FILE_EXTENSIONS, VIDEO_FILE_EXTENSIONS

    mp4_family = {".mp4", ".m4a", ".m4b", ".m4p", ".m4v", ".mov"}
    assert mp4_family <= set(AUDIO_FILE_EXTENSIONS)
    assert mp4_family <= set(VIDEO_FILE_EXTENSIONS)
    audio_formats = {".mp3", ".wav", ".flac", ".ogg", ".opus", ".aac"}
    video_formats = {".mkv", ".avi", ".webm"}
    assert audio_formats <= set(AUDIO_FILE_EXTENSIONS)
    assert video_formats <= set(VIDEO_FILE_EXTENSIONS)


def test_audio_preview_text_uses_mutagen_file_metadata(monkeypatch):
    from types import SimpleNamespace

    import gui.main as gui_module

    monkeypatch.setattr(
        gui_module,
        "MutagenFile",
        lambda path: SimpleNamespace(
            info=SimpleNamespace(length=61.9, bitrate=192_000)
        ),
    )

    assert gui_module.get_audio_preview_text("song.mp3") == "song.mp3\n61.9s 192 kbps"


def test_video_preview_reads_and_closes_first_frame(monkeypatch):
    import numpy as np

    import gui.main as gui_module

    class Reader:
        closed = False

        def get_data(self, index):
            assert index == 0
            return np.full((2, 3, 3), (10, 20, 30), dtype=np.uint8)

        def close(self):
            self.closed = True

    reader = Reader()
    monkeypatch.setattr(gui_module.imageio, "get_reader", lambda path: reader)

    frame = gui_module.load_video_preview_frame("clip.mp4")

    assert frame.size == (3, 2)
    assert frame.getpixel((0, 0)) == (10, 20, 30)
    assert reader.closed


@pytest.mark.parametrize(
    "operation,suffix",
    [
        ("encode", "_stego.png"),
        ("decode", "_decoded.bin"),
    ],
)
def test_batch_output_plan_numbers_same_stem_inputs(tmp_path, operation, suffix):
    from gui.main import plan_batch_output_paths

    source_paths = [
        str(tmp_path / "left" / "cover.png"),
        str(tmp_path / "right" / "cover.jpg"),
    ]

    outputs = plan_batch_output_paths(source_paths, str(tmp_path), operation)

    assert [path.name for path in outputs] == [
        f"cover{suffix}",
        f"cover{suffix[:-4]}_2{suffix[-4:]}",
    ]


@pytest.mark.parametrize(
    "operation,filename",
    [
        ("encode", "cover_stego.png"),
        ("decode", "cover_decoded.bin"),
    ],
)
def test_batch_output_plan_skips_existing_and_reserved_destinations(
    tmp_path, operation, filename
):
    from gui.main import plan_batch_output_paths

    sources = [
        str(tmp_path / "left" / "cover.png"),
        str(tmp_path / "right" / "cover.jpg"),
    ]
    existing = tmp_path / filename
    second_existing = existing.with_name(f"{existing.stem}_2{existing.suffix}")
    existing.write_bytes(b"keep existing output")
    second_existing.write_bytes(b"keep second existing output")

    outputs = plan_batch_output_paths(sources, str(tmp_path), operation)

    assert [path.name for path in outputs] == [
        f"{existing.stem}_3{existing.suffix}",
        f"{existing.stem}_4{existing.suffix}",
    ]
    assert existing.read_bytes() == b"keep existing output"
    assert second_existing.read_bytes() == b"keep second existing output"


def test_batch_runner_passes_timeout_and_always_calls_finish_callback():
    from subprocess import CompletedProcess

    from gui.main import run_batch_commands

    runner_calls = []
    progress = []
    finished = []

    def runner(command, *, capture_output, text, timeout):
        runner_calls.append((command, capture_output, text, timeout))
        return CompletedProcess(command, 0, stdout="ok", stderr="")

    run_batch_commands(
        [["stego", "encode"]],
        runner=runner,
        timeout=17,
        on_progress=lambda index, total: progress.append((index, total)),
        on_finished=finished.append,
    )

    assert runner_calls == [(["stego", "encode"], True, True, 17)]
    assert progress == [(1, 1)]
    assert finished == [None]


def test_batch_runner_reports_timeout_and_calls_finish_callback():
    import subprocess

    from gui.main import run_batch_commands

    finished = []

    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    run_batch_commands(
        [["stego", "decode"]],
        runner=runner,
        timeout=23,
        on_finished=finished.append,
    )

    assert len(finished) == 1
    assert isinstance(finished[0], subprocess.TimeoutExpired)
    assert finished[0].timeout == 23


def test_batch_runner_rechecks_destinations_before_running_commands(tmp_path):
    from gui.main import run_batch_commands

    destination = tmp_path / "cover_stego.png"
    destination.write_bytes(b"created after planning")
    runner_calls = []
    finished = []

    run_batch_commands(
        [["stego", "encode"]],
        runner=lambda *args, **kwargs: runner_calls.append((args, kwargs)),
        on_finished=finished.append,
        destinations=[destination],
    )

    assert runner_calls == []
    assert len(finished) == 1
    assert isinstance(finished[0], FileExistsError)
    assert destination.read_bytes() == b"created after planning"


def test_batch_runner_finishes_cleanup_callback_when_preflight_fails(tmp_path):
    from gui.main import run_batch_commands

    finished = []
    run_batch_commands(
        [["stego", "encode"]],
        on_finished=finished.append,
        destinations=[],
    )

    assert len(finished) == 1
    assert isinstance(finished[0], ValueError)
    assert "one destination" in str(finished[0])


def test_capacity_estimator_debounces_snapshots_and_ignores_stale_results():
    from gui.main import AsyncImageCapacityEstimator, ImageCapacityRequest

    class FakeRoot:
        def __init__(self):
            self.callbacks = {}
            self.cancelled = set()
            self.next_id = 0

        def after(self, delay_ms, callback, *args):
            self.next_id += 1
            token = self.next_id
            self.callbacks[token] = (delay_ms, callback, args)
            return token

        def after_cancel(self, token):
            self.cancelled.add(token)
            self.callbacks.pop(token, None)

        def run(self, token):
            _delay, callback, args = self.callbacks.pop(token)
            callback(*args)

    class FakeThread:
        instances = []
        active_count = 0
        max_active_count = 0

        def __init__(self, *, target, daemon):
            self.target = target
            self.daemon = daemon
            self.instances.append(self)

        def start(self):
            pass

        def run(self):
            type(self).active_count += 1
            type(self).max_active_count = max(
                type(self).max_active_count, type(self).active_count
            )
            try:
                self.target()
            finally:
                type(self).active_count -= 1

    root = FakeRoot()
    computed = []
    published = []
    FakeThread.instances.clear()
    FakeThread.active_count = 0
    FakeThread.max_active_count = 0

    def compute(request):
        computed.append(request.cover_path)
        return f"ready: {request.cover_path}"

    estimator = AsyncImageCapacityEstimator(
        root,
        published.append,
        compute=compute,
        thread_factory=FakeThread,
        debounce_ms=40,
    )
    first = ImageCapacityRequest("first.png", "", "message", None, False, None, None)
    second = ImageCapacityRequest("second.png", "", "message", None, False, None, None)
    third = ImageCapacityRequest("third.png", "", "message", None, False, None, None)
    fourth = ImageCapacityRequest("fourth.png", "", "message", None, False, None, None)

    def token_with_delay(delay_ms):
        return next(
            token
            for token, (delay, _callback, _args) in root.callbacks.items()
            if delay == delay_ms
        )

    estimator.request(first)
    first_timer = token_with_delay(40)
    estimator.request(second)
    second_timer = token_with_delay(40)
    assert first_timer in root.cancelled
    root.run(second_timer)
    second_worker = FakeThread.instances[-1]

    estimator.request(third)
    third_timer = token_with_delay(40)
    root.run(third_timer)
    assert FakeThread.instances == [second_worker]

    estimator.request(fourth)
    fourth_timer = token_with_delay(40)
    root.run(fourth_timer)
    assert FakeThread.instances == [second_worker]

    second_worker.run()
    root.run(token_with_delay(25))
    latest_worker = FakeThread.instances[-1]
    assert latest_worker is not second_worker
    latest_worker.run()
    root.run(token_with_delay(25))

    assert computed == ["second.png", "fourth.png"]
    assert FakeThread.max_active_count == 1
    assert published == ["ready: fourth.png"]


def test_capacity_worker_never_calls_tk_from_its_thread():
    import threading

    from gui.main import AsyncImageCapacityEstimator, ImageCapacityRequest

    main_thread_id = threading.get_ident()

    class MainThreadOnlyRoot:
        def __init__(self):
            self.callbacks = {}
            self.next_id = 0

        def after(self, delay_ms, callback, *args):
            assert threading.get_ident() == main_thread_id
            self.next_id += 1
            token = self.next_id
            self.callbacks[token] = (delay_ms, callback, args)
            return token

        def after_cancel(self, token):
            assert threading.get_ident() == main_thread_id
            self.callbacks.pop(token, None)

        def run(self, token):
            _delay, callback, args = self.callbacks.pop(token)
            callback(*args)

    root = MainThreadOnlyRoot()
    worker_finished = threading.Event()
    published = []
    compute_thread_ids = []

    def thread_factory(*, target, daemon):
        def run_target():
            try:
                target()
            finally:
                worker_finished.set()

        return threading.Thread(target=run_target, daemon=daemon)

    estimator = AsyncImageCapacityEstimator(
        root,
        published.append,
        compute=lambda _request: (
            compute_thread_ids.append(threading.get_ident()) or "ready"
        ),
        thread_factory=thread_factory,
        debounce_ms=0,
    )
    estimator.request(
        ImageCapacityRequest("cover.png", "", "", None, False, None, None)
    )
    debounce_token = next(iter(root.callbacks))
    root.run(debounce_token)

    assert worker_finished.wait(2)
    poll_token = next(iter(root.callbacks))
    root.run(poll_token)

    assert compute_thread_ids and compute_thread_ids[0] != main_thread_id
    assert published == ["ready"]


def test_vault_save_with_wrong_master_password_preserves_existing_vault(tmp_path):
    from cryptography.exceptions import InvalidTag

    from gui.main import load_encrypted_vault, save_encrypted_vault

    vault_path = tmp_path / "keys.json"
    save_encrypted_vault(vault_path, "correct horse", {"key": "original"})
    original_bytes = vault_path.read_bytes()

    with pytest.raises(InvalidTag):
        save_encrypted_vault(vault_path, "wrong password", {"key": "replacement"})

    assert vault_path.read_bytes() == original_bytes
    assert load_encrypted_vault(vault_path, "correct horse") == {"key": "original"}


def test_image_decode_command_requires_an_output_path_and_always_writes_bytes():
    from gui.main import build_image_decode_command

    with pytest.raises(ValueError, match="output file path"):
        build_image_decode_command("carrier.png", "", "lsb")

    command = build_image_decode_command("carrier.png", "decoded.bin", "lsb")

    assert "--out" in command
    assert command[command.index("--out") + 1] == "decoded.bin"


def test_gui_secret_command_keeps_credentials_out_of_argv_and_on_stdin():
    import json

    from gui.main import build_secret_command

    password = "password-visible-nowhere"
    prng_key = "prng-visible-nowhere"
    argv, stdin_payload = build_secret_command(
        ["stego", "video-frame-encode", "--video", "clip.mkv"],
        password=password,
        prng_key=prng_key,
    )

    assert password not in argv
    assert prng_key not in argv
    assert "--credentials-stdin" in argv
    assert json.loads(stdin_payload) == {"password": password, "prng_key": prng_key}


def test_gui_secret_command_preserves_explicit_empty_credentials():
    import json

    from gui.main import build_secret_command

    argv, stdin_payload = build_secret_command(
        ["stego", "decode"], password="", prng_key=""
    )

    assert "--credentials-stdin" in argv
    assert json.loads(stdin_payload) == {"password": "", "prng_key": ""}


@pytest.mark.parametrize("media_type", ["audio", "video", "pdf"])
def test_metadata_command_builders_never_put_passwords_in_argv(media_type):
    from gui.main import build_metadata_decode_command, build_metadata_encode_command

    secret = "metadata-password-must-not-be-in-argv"
    encode = build_metadata_encode_command(
        media_type,
        f"carrier.{media_type}",
        f"encoded.{media_type}",
        message="payload",
        password=secret,
    )
    decode = build_metadata_decode_command(
        media_type,
        f"encoded.{media_type}",
        "decoded.bin",
        password=secret,
    )

    assert secret not in encode
    assert secret not in decode


def test_batch_runner_passes_credentials_only_on_stdin():
    import json
    from subprocess import CompletedProcess

    from gui.main import build_secret_command, run_batch_commands

    secret = "batch-secret-not-in-command"
    command, credential_input = build_secret_command(
        ["stego", "encode", "--image", "cover.png"],
        password=secret,
        prng_key="batch-prng-secret",
    )
    calls = []

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return CompletedProcess(arguments, 0, stdout="ok", stderr="")

    run_batch_commands([command], credential_inputs=[credential_input], runner=runner)

    arguments, kwargs = calls[0]
    assert secret not in arguments
    assert json.loads(kwargs["input"]) == {
        "password": secret,
        "prng_key": "batch-prng-secret",
    }


@pytest.mark.parametrize(
    "command_args",
    [
        ("encode", "--image", "image.png", "--out", "out.png"),
        ("decode", "--image", "image.png"),
        ("audio-encode", "--audio", "in.mp3", "--out", "out.mp3"),
        ("audio-decode", "--audio", "in.mp3", "--out", "out.bin"),
        ("video-encode", "--video", "in.mp4", "--out", "out.mp4"),
        ("video-decode", "--video", "in.mp4", "--out", "out.bin"),
        ("pdf-encode", "--pdf", "in.pdf", "--out", "out.pdf"),
        ("pdf-decode", "--pdf", "in.pdf", "--out", "out.bin"),
        (
            "video-frame-encode",
            "--video",
            "in.mkv",
            "--out",
            "out.mkv",
            "--frame",
            "0",
        ),
        (
            "video-frame-decode",
            "--video",
            "in.mkv",
            "--out",
            "out.bin",
            "--frame",
            "0",
        ),
        ("portable-decoder", "--stego", "in.png", "--out", "decoder.zip"),
    ],
)
def test_cli_secret_subcommands_accept_gui_stdin_transport(command_args):
    from app import build_parser

    args = build_parser().parse_args([*command_args, "--credentials-stdin"])

    assert args.credentials_stdin is True


def test_cli_reads_gui_credentials_from_stdin_and_keeps_legacy_flags():
    import io

    from app import apply_stdin_credentials, build_parser

    parser = build_parser()
    args = parser.parse_args(
        [
            "video-frame-encode",
            "--video",
            "clip.mkv",
            "--out",
            "out.mkv",
            "--frame",
            "0",
            "--credentials-stdin",
        ]
    )
    apply_stdin_credentials(
        args,
        io.StringIO('{"password":"stdin password","prng_key":"stdin key"}'),
    )

    assert args.password == "stdin password"
    assert args.prng_key == "stdin key"

    legacy_args = parser.parse_args(
        [
            "decode",
            "--image",
            "cover.png",
            "--password",
            "legacy password",
        ]
    )
    assert legacy_args.password == "legacy password"


def test_cli_main_applies_stdin_credentials_before_dispatch(monkeypatch):
    import io

    import app

    dispatched = []
    monkeypatch.setattr(app, "encode_image", dispatched.append)
    monkeypatch.setattr(
        app.sys,
        "stdin",
        io.StringIO('{"password":"dispatched password","prng_key":"dispatched key"}'),
    )

    app.main(
        [
            "encode",
            "--image",
            "cover.png",
            "--out",
            "stego.png",
            "--credentials-stdin",
        ]
    )

    assert len(dispatched) == 1
    assert dispatched[0].password == "dispatched password"
    assert dispatched[0].prng_key == "dispatched key"


def test_plaintext_templates_omit_keys_and_ignore_legacy_key_fields(tmp_path):
    import json

    from gui.main import (
        load_plaintext_templates,
        save_plaintext_templates,
        template_values_for_load,
    )

    templates_path = tmp_path / "templates.json"
    legacy_secret = "legacy-template-prng-key"
    legacy_templates = {
        "old": {"method": "lsb-prng", "prng_key": legacy_secret, "compress": "True"}
    }
    templates_path.write_text(json.dumps(legacy_templates), encoding="utf-8")

    loaded = load_plaintext_templates(templates_path)
    assert loaded == {"old": {"method": "lsb-prng", "compress": "True"}}
    assert legacy_secret not in templates_path.read_text(encoding="utf-8")
    assert template_values_for_load(legacy_templates["old"])["prng_key"] == ""

    save_plaintext_templates(templates_path, legacy_templates)
    assert legacy_secret not in templates_path.read_text(encoding="utf-8")


def test_psnr_uses_mean_squared_error_and_returns_infinity_for_identical_images():
    import math

    from gui.main import compute_psnr

    original = Image.new("RGB", (1, 1), (0, 0, 0))
    one_channel_off = Image.new("RGB", (1, 1), (1, 0, 0))

    assert compute_psnr(original, one_channel_off) == pytest.approx(
        10 * math.log10(255**2 / (1 / 3))
    )
    assert math.isinf(compute_psnr(original, original.copy()))


def test_payload_source_rejects_message_and_file_together():
    from gui.main import payload_source_arguments

    with pytest.raises(ValueError, match="either a message or a payload file"):
        payload_source_arguments("text data", "payload.bin")

    assert payload_source_arguments("text data", "") == ["--message", "text data"]
    assert payload_source_arguments("", "payload.bin") == ["--in-file", "payload.bin"]


def test_quick_help_discloses_metadata_storage_without_security_superlatives():
    from gui.main import get_quick_help_text

    help_text = get_quick_help_text().lower()

    assert "audio, video, and pdf" in help_text
    assert "visible metadata" in help_text
    assert "not steganography" in help_text
    assert "readable unless password encryption is used" in help_text
    assert "most secure" not in help_text
    assert "more secure" not in help_text


def test_gui_self_check_does_not_open_a_window(monkeypatch):
    import gui.main as gui_module

    def fail_if_gui_starts():
        pytest.fail("self-check must not launch the GUI")

    monkeypatch.setattr(gui_module, "gui_main", fail_if_gui_starts)

    assert gui_module.main(["--self-check"]) == 0
