"""Contract checks for CI and release workflow behavior.

These checks guard the repository's workflow wiring: the reusable Python test
workflow must be the sole cross-platform test source, and downloadable assets
must be attached only by jobs gated on a published release.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _job_blocks(workflow: str) -> dict[str, str]:
    """Return top-level job blocks from a GitHub Actions workflow."""
    lines = workflow.splitlines()
    jobs_start = next(
        index for index, line in enumerate(lines) if line == "jobs:"
    )
    starts = [
        (index, match.group(1))
        for index, line in enumerate(lines[jobs_start + 1 :], jobs_start + 1)
        if (match := re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line))
    ]
    blocks = {}
    for position, (start, job_name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        blocks[job_name] = "\n".join(lines[start:end])
    return blocks


def test_one_python_314_cross_platform_workflow_runs_for_ci_events() -> None:
    """Push/PR CI must call one Python 3.14 Linux/macOS/Windows test matrix."""
    ci = (WORKFLOWS / "ci-cd.yml").read_text(encoding="utf-8")
    tests = (WORKFLOWS / "test.yml").read_text(encoding="utf-8")

    assert re.search(r"(?m)^  push:\s*$", ci)
    assert re.search(r"(?m)^  pull_request:\s*$", ci)
    assert re.search(r"(?m)^  workflow_call:\s*$", tests)
    assert "uses: ./.github/workflows/test.yml" in ci
    assert "python-version: ['3.14']" in tests
    assert "os: [ubuntu-latest, macos-latest, windows-latest]" in tests
    assert "upload" not in tests.lower()
    assert "pytest" not in ci


def test_linux_and_docker_test_commands_start_xvfb_and_keep_ffmpeg() -> None:
    """Linux GUI tests and Docker tests must run with Xvfb, Tk, and ffmpeg."""
    tests = (WORKFLOWS / "test.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert re.search(r"(?m)^\s*run:.*xvfb-run -a pytest", tests)
    assert "CI: ''" in tests or 'CI: ""' in tests
    linux_install = tests.split("sudo apt-get install -y", maxsplit=1)[1].split(
        "\n\n", maxsplit=1
    )[0]
    linux_packages = set(
        re.findall(r"(?m)^\s+([a-z0-9][a-z0-9-]*)\s*\\?$", linux_install)
    )
    assert {"ffmpeg", "xvfb", "tk", "tk-dev"} <= linux_packages
    docker_install = dockerfile.split(
        "apt-get install -y --no-install-recommends", maxsplit=1
    )[1].split("&&", maxsplit=1)[0]
    docker_packages = set(
        re.findall(r"(?m)^\s+([a-z0-9][a-z0-9-]*)\s*\\?$", docker_install)
    )
    assert "tk" in docker_packages
    assert "brew install ffmpeg" in tests
    assert "choco install ffmpeg -y" in tests
    assert "python:3.14-slim" in dockerfile
    assert re.search(r"(?is)apt-get install(?:(?!&&).)*\bffmpeg\b", dockerfile)
    assert re.search(r'(?m)^CMD \["xvfb-run", "-a", "pytest"', dockerfile)


def test_only_published_releases_build_and_upload_windows_and_macos_packages() -> None:
    """Only published releases may package and upload platform downloads."""
    ci = (WORKFLOWS / "ci-cd.yml").read_text(encoding="utf-8")
    jobs = _job_blocks(ci)
    published_gate = "github.event_name == 'release' && github.event.action == 'published'"
    upload_jobs = {
        name: block
        for name, block in jobs.items()
        if "softprops/action-gh-release@" in block
    }
    package_jobs = {
        name: block
        for name, block in jobs.items()
        if "pyinstaller" in block.lower() or "steganography-" in block
    }

    assert re.search(r"(?m)^  release:\s*$", ci)
    release_event = ci.split("  release:\n", maxsplit=1)[1].split("\njobs:", maxsplit=1)[0]
    assert "types: [published]" in release_event
    assert len(upload_jobs) == 2
    assert {"windows-release", "macos-release"} <= upload_jobs.keys()
    assert package_jobs.keys() == upload_jobs.keys()

    for block in upload_jobs.values():
        assert published_gate in block
        assert re.search(r"(?m)^\s+needs: test$", block)
        assert re.search(
            r"(?m)^\s+permissions:\s*\n\s+contents: write$",
            block,
        )
        assert "softprops/action-gh-release@" in block
        assert "python-version: '3.14'" in block

    windows = upload_jobs["windows-release"]
    assert "pyinstaller" in windows.lower()
    assert "dist/stego-cli.exe" in windows
    assert "dist/stego-gui.exe" in windows
    assert "dist/steganography-windows.zip" in windows
    assert "Compress-Archive" in windows

    macos = upload_jobs["macos-release"]
    assert "pyinstaller" in macos.lower()
    assert "--windowed" in macos
    assert "dist/stego-cli" in macos
    assert "dist/stego-gui.app" in macos
    assert "ditto dist/stego-gui.app dist/steganography-macos/stego-gui.app" in macos
    assert "ditto dist/stego-cli dist/steganography-macos/stego-cli" in macos
    assert (
        "ditto -c -k --sequesterRsrc --keepParent "
        "dist/steganography-macos dist/steganography-macos.zip"
    ) in macos
    assert "actions/upload-release-asset@" not in ci
