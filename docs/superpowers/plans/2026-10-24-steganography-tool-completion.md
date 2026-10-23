# Steganography Tool Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the repository roadmap on a separate branch with a working GUI, truthful mode descriptions, reliable round trips, capacity feedback, drag-and-drop, a bounded detectability heuristic, and Windows/macOS release downloads.

**Architecture:** Merge the modular `uiuximprov` implementation into the isolated branch based on `gui`, then repair its core, metadata, CLI, GUI, and packaging boundaries in separately reviewed commits. New encrypted payloads use a versioned serialized header as AES-GCM AAD; image and video-frame modes write lossless output, while metadata containers remain visibly described and size-bounded.

**Tech Stack:** Python 3, Tkinter, Pillow, cryptography, Mutagen, PyPDF2, imageio/imageio-ffmpeg, pytest, Docker, GitHub Actions, PyInstaller.

**Spec:** `docs/superpowers/specs/2026-10-24-steganography-tool-completion-design.md`

## Global Constraints

- The GUI must call library functions directly or use `sys.executable` with a path relative to `__file__`.
- Image stego output must be PNG or another verified lossless format; JPEG and lossy video output must be refused or warned against.
- Crypto remains AES-GCM with fresh random salt and nonce per message, PBKDF2-SHA256 at least 200,000 iterations, and header fields bound as AAD.
- Every retained embed mode needs an embed/extract byte-identical round-trip test, wrong-password test, and capacity-overflow test.
- Metadata embedding must be described as visible metadata storage and have a finite encoded-blob capacity.
- The statistical self-check must be labeled a heuristic and must not promise secrecy or undetectability.
- Windows and macOS release assets must be built only for a published release; this task does not publish a release.
- Do not commit virtual environments, `pyvenv.cfg`, generated stego files, or test outputs.

## Review Focus

- Header fields changed after encryption must fail authentication; test tampering of serialized flags, lengths, salt, nonce, and payload length in Task 2.
- Inputs with timezone-aware expiration strings must not crash during comparisons; test valid expired and unexpired UTC timestamps in Task 2.
- Image capacity boundaries must include header, salt, nonce, and GCM-tag overhead; test exact-fit and one-byte-overflow payloads in Task 2.
- Video-frame output must survive file encoding without changing embedded channel bits; test a generated frame round trip and reject non-MKV output in Task 2.
- Drag-and-drop paths containing spaces, braces, and Unicode must resolve as individual files; test path-list normalization and the GUI callback in Task 4.

---

### Task 1: Integrate the modular implementation and clean repository state

**Files:**
- Modify: `README.md`
- Modify: `.gitignore`
- Delete: `pyvenv.cfg`
- Delete: obsolete `gui.py` and `test.py` if still present after merge
- Preserve: `app.py`, `gui/`, `stego/`, `tests/`, `.github/workflows/`, `Dockerfile`, `requirements.txt`
- Include: `docs/superpowers/specs/2026-10-24-steganography-tool-completion-design.md`
- Include: `docs/superpowers/plans/2026-10-24-steganography-tool-completion.md`

**Interfaces:**
- Consumes: clean worktree branch `codex/stego-complete` based on `origin/gui`.
- Produces: a merge commit of `origin/uiuximprov` with no tracked environment files or generated outputs; later tasks use the candidate's `app.py`, `gui/main.py`, `stego/`, and pytest layout.

- [ ] **Step 1: Merge the candidate branch**

Run: `git merge --no-commit --no-ff origin/uiuximprov`
Resolve conflicts by preserving the modular implementation and its current CLI while deferring truthful wording to Task 3. Keep the user-approved design and plan documents.

- [ ] **Step 2: Remove tracked local-environment and obsolete launch/test artifacts**

Delete `pyvenv.cfg` and any legacy `gui.py`/`test.py` that remain after the merge. Add ignore rules for `.venv/`, `venv/`, `pyvenv.cfg`, generated `stego.*` outputs, and `test_op.jpg`.

- [ ] **Step 3: Verify merge hygiene**

Run: `git diff --check`
Run: `git ls-files pyvenv.cfg gui.py test.py`
Expected: no whitespace errors and no output from the tracked-file query.

- [ ] **Step 4: Commit integration**

```bash
git add -A
git commit -m "merge: integrate modular steganography implementation"
```

### Task 2: Authenticate envelopes and enforce lossless image/frame capacity

**Files:**
- Modify: `stego/core.py`
- Modify: `stego/image.py`
- Modify: `stego/__init__.py` (remove exports for the retired GIF-frame API)
- Modify: `app.py` (image and video-frame output validation only)
- Modify: `gui/main.py` (remove only GIF-frame actions and their callbacks)
- Test: `tests/test_core.py`
- Test: `tests/test_image.py`
- Create: `tests/test_video_frame.py`

**Interfaces:**
- Consumes: `StegoHeader`, `build_stego_payload`, `parse_stego_payload`, and image/frame operations from Task 1.
- Produces: `StegoHeader.version`; `build_aad(header: StegoHeader) -> bytes`; `estimate_stego_payload_size(plaintext: bytes, *, encrypted: bool, compress: bool, metadata: dict | None) -> int`; and `image_capacity_bytes(image: Image.Image) -> int`. The estimate returns the exact serialized envelope byte count; image capacity returns `width * height * 3 // 8` bytes available for that envelope.
- Version 2 encrypted envelopes authenticate `header.to_bytes()` as AES-GCM AAD. Version 1 encrypted envelopes retain the existing legacy AAD only for decoding. Image output accepts `.png` only. Video-frame output accepts `.mkv` only and uses FFV1; remove GIF-frame commands and UI entry points because palette conversion cannot guarantee bit preservation.

- [ ] **Step 1: Add failing core tests**

Test encrypted version 2 round trips, version 1 fixture decoding, tampering of each serialized header field, timezone-aware expired and unexpired UTC metadata, and equality between `estimate_stego_payload_size(...)` and `len(build_stego_payload(...)[0])` for encrypted, compressed, and metadata-bearing payloads.

- [ ] **Step 2: Run the core tests to verify failure**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_core.py -q`
Expected: new version/AAD/size tests fail before implementation.

- [ ] **Step 3: Implement versioned header authentication and exact size estimation**

Keep PBKDF2-SHA256 at 200,000 iterations and fresh random 16-byte salt/12-byte nonce. Encode v2 headers for new payloads; parse v1 and v2; authenticate every serialized v2 header byte; decode v1 with the existing legacy AAD.

- [ ] **Step 4: Add failing image and frame capacity/output tests**

Test exact-fit and one-byte-overflow image payloads for `lsb`, `lsb-prng`, and `lsb-match-prng`; reject `.jpg`/`.jpeg`; create a short FFV1 MKV fixture and test exact byte round trip, wrong password, capacity overflow, and rejection of non-MKV output. Assert removed GIF CLI commands are rejected.

- [ ] **Step 5: Run focused image/frame tests to verify failure**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_image.py tests/test_video_frame.py -q`
Expected: new boundary/format/round-trip tests fail before implementation.

- [ ] **Step 6: Implement lossless output and frame validation**

Add exact capacity checks before writes. Keep only formats whose written output preserves all embedded channel bits; use FFV1 for video-frame MKV and reject other output suffixes. Remove GIF-frame API and parser actions.

- [ ] **Step 7: Run Task 2 tests**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_core.py tests/test_image.py tests/test_video_frame.py -q`
Expected: all focused tests pass, including legacy decode and wrong-password rejection.

- [ ] **Step 8: Commit Task 2**

```bash
git add stego/core.py stego/image.py stego/__init__.py app.py tests/test_core.py tests/test_image.py tests/test_video_frame.py
git commit -m "fix: authenticate headers and preserve lossless payloads"
```

### Task 3: Bound and truthfully describe metadata embedding modes

**Files:**
- Modify: `stego/core.py`
- Modify: `stego/audio.py`
- Modify: `stego/video.py`
- Modify: `stego/pdf.py`
- Modify: `stego/utils.py`
- Modify: `app.py`
- Modify: `README.md`
- Test: `tests/test_audio.py`
- Test: `tests/test_cli.py`
- Test: `tests/test_video.py`
- Test: `tests/test_pdf.py`

**Interfaces:**
- Consumes: the versioned payload API from Task 2.
- Produces: `MAX_METADATA_STEGO_BYTES = 1_000_000`; every metadata backend validates the complete serialized stego blob against this limit before writing. Retained CLI actions identify MP3/MP4/audio/video/PDF storage as visible metadata embedding. GIF actions are removed. README claims match commands and retained formats.
- Retained backends: MP3 ID3/APIC, MP4/M4A tags, WAV/FLAC/OGG/OPUS/AAC tags, MKV/AVI/WEBM comments, and PDF document metadata.

- [ ] **Step 1: Add failing backend round-trip tests**

For every retained backend, test byte-identical extraction of a small binary file, wrong-password rejection, and overflow rejection at the 1,000,000-byte encoded-blob limit. Use small generated media/PDF fixtures and assert no output is written on overflow.

- [ ] **Step 2: Run metadata tests to verify failure**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_audio.py tests/test_video.py tests/test_pdf.py -q`
Expected: missing mode coverage, capacity checks, or existing MP4 errors fail before implementation.

- [ ] **Step 3: Enforce the common encoded-blob limit in each backend**

Validate the finalized header and payload bytes before invoking Mutagen, FFmpeg, or PyPDF2. Normalize malformed, truncated, and invalid-base64 payloads to clear `ValueError` results.

- [ ] **Step 4: Add failing CLI disclosure and mode-removal tests**

Assert CLI help identifies metadata storage as visible metadata embedding, rejects removed GIF commands, retains supported metadata commands, and returns non-zero on an over-capacity payload.

- [ ] **Step 5: Run CLI tests to verify failure**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_cli.py -q`
Expected: parser/help/disclosure tests fail before implementation.

- [ ] **Step 6: Update CLI behavior and README disclosures**

Correct subcommand arguments and examples to match parser definitions. State that metadata tags/comments are visible to tag viewers and are not steganography; describe finite capacity and lossless output requirements accurately.

- [ ] **Step 7: Run Task 3 tests**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_audio.py tests/test_video.py tests/test_pdf.py tests/test_cli.py -q`
Expected: each retained backend passes round trip, wrong-password, overflow, and disclosure tests.

- [ ] **Step 8: Commit Task 3**

```bash
git add stego/core.py stego/audio.py stego/video.py stego/pdf.py stego/utils.py app.py README.md tests/test_audio.py tests/test_video.py tests/test_pdf.py tests/test_cli.py
git commit -m "fix: bound and disclose metadata embedding modes"
```

### Task 4: Repair the GUI and complete the user-facing roadmap

**Files:**
- Modify: `gui/main.py`
- Create: `stego/detect.py`
- Test: `tests/test_gui.py`
- Test: `tests/test_image.py` (chi-square behavior)

**Interfaces:**
- Consumes: exact envelope-size and lossless-output APIs from Tasks 2–3; supported commands from Task 3.
- Produces: `stego.detect.lsb_pair_chi_square(image: Image.Image) -> float`; a pure CLI command builder using `sys.executable` and `Path(__file__).resolve().parent.parent / "app.py"`; an image capacity meter that compares actual estimated encoded size (including header, crypto, compression, and metadata overhead) to available RGB LSB bytes; drag-and-drop path normalization for cover/payload controls; and post-encode chi-square feedback labeled heuristic.
- Existing GUI callbacks must resolve imports and command flags, and all utility actions left visible in the interface must have valid parser arguments.

- [ ] **Step 1: Add failing tests for detector, capacity UI model, drag-and-drop normalization, and command construction**

Test balanced vs. deliberately unbalanced value-pairs, detector output labels/limits, estimated image envelope fit and overflow, Windows/Linux paths containing spaces/braces/Unicode, and the child command's interpreter and `app.py` path.

- [ ] **Step 2: Run focused GUI/model tests to verify failure**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test xvfb-run -a pytest tests/test_gui.py tests/test_image.py -q`
Expected: new tests fail before implementation; GUI tests run under Xvfb instead of skipping merely because CI is set.

- [ ] **Step 3: Repair GUI imports and command callbacks**

Use `sys.executable` and the path relative to `__file__`; align parser subcommand names and flags; remove callback actions whose CLI parser was removed; preserve subprocess argument lists without shell interpolation.

- [ ] **Step 4: Implement capacity meter, drag-and-drop, and post-encode self-check**

Refresh capacity from current cover, payload bytes, password, compression, and metadata state. Normalize Tcl drag-and-drop lists with Tk's list parser. Label metadata actions as visible metadata storage. After a successful image encode, compute and show the pair-values chi-square statistic plus a short heuristic explanation and an explicit limitation.

- [ ] **Step 5: Run GUI tests in the isolated display environment**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test xvfb-run -a pytest tests/test_gui.py tests/test_image.py -q`
Expected: GUI/model tests execute (not module-skipped) and pass.

- [ ] **Step 6: Commit Task 4**

```bash
git add gui/main.py stego/detect.py tests/test_gui.py tests/test_image.py
git commit -m "feat: complete capacity drag and detection feedback"
```

### Task 5: Make verification and Windows/macOS release downloads reliable

**Files:**
- Modify: `.github/workflows/test.yml`
- Modify: `.github/workflows/ci-cd.yml`
- Modify: `Dockerfile`
- Modify: `.dockerignore`
- Modify: `requirements.txt`
- Modify: `README.md`

**Interfaces:**
- Consumes: tested CLI, GUI, and mode interfaces from Tasks 2–4.
- Produces: Linux/macOS/Windows test jobs on Python 3.14 that execute GUI tests with Xvfb where needed; a Python 3.14 Docker test target whose command supplies Xvfb; one non-duplicated cross-platform test source of truth; Windows `.zip` and macOS `.zip`/`.dmg` release assets attached only on `release: published`; documentation linking to downloads and the tested source/Docker workflows.

- [ ] **Step 1: Add workflow and packaging validation checks**

Add `tests/test_workflows.py` that checks workflow event/job declarations and asserts published-release gating, Windows and macOS build/package jobs, no release-asset upload on push/pull_request, and Xvfb test invocation in Docker/Linux.

- [ ] **Step 2: Run the workflow checks to verify failure**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_workflows.py -q`
Expected: the current duplicate workflows and upload conditions fail before implementation.

- [ ] **Step 3: Repair CI and Docker test execution**

Keep one cross-platform test matrix; run GUI tests under Xvfb on Linux; ensure Docker's test target starts Xvfb; install the package versions that support the configured Python versions; keep ffmpeg available to mode tests.

- [ ] **Step 4: Gate and package platform release assets**

Build Windows GUI/CLI executables and a `.zip`; build macOS GUI/CLI executables and a `.zip` or `.dmg`; upload only on a published release. Do not build/publish Linux assets unless the same workflow needs them for tests.

- [ ] **Step 5: Run workflow and Docker verification**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test pytest tests/test_workflows.py -q`
Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test`
Expected: workflow validation passes, Docker image builds, and the full test suite passes under Xvfb.

- [ ] **Step 6: Update download and verification documentation**

Document that Windows/macOS assets appear on published releases, provide source and Docker verification commands, and keep each supported format and mode claim aligned with tests.

- [ ] **Step 7: Commit Task 5**

```bash
git add .github/workflows/test.yml .github/workflows/ci-cd.yml Dockerfile .dockerignore requirements.txt README.md tests/test_workflows.py
git commit -m "ci: verify modes and publish platform downloads"
```

### Task 6: Perform final verification, hostile review, and PR handoff

**Files:**
- Review all commits and changed files; make focused fixes through reviewed follow-up commits.

**Interfaces:**
- Consumes: reviewed completion of Tasks 1–5.
- Produces: clean full test/build evidence, an independent hostile branch review with findings adjudicated, and a pushed `codex/stego-complete` branch with a PR opened against `gui`.

- [ ] **Step 1: Run the complete Docker test suite and all configured local build checks**

Run: `docker build --target test -t stego-test .`
Run: `docker run --rm stego-test`
Run: `git diff --check`
Expected: each command succeeds; record exact summaries in the ledger and PR body.

- [ ] **Step 2: Dispatch an independent whole-branch hostile review**

Review the complete branch against the design spec, Global Constraints, security/crypto, mode-specific round trips, UI commands, filesystem outputs, workflow triggers, and README/release claims. Fix every Critical/Important finding and re-review the fixes.

- [ ] **Step 3: Push and open the PR into `gui`**

Confirm `git status --short` is clean, push only `codex/stego-complete`, create a PR targeting `gui`, attach the PR artifact to this task, and report the URL with actual verification results.
