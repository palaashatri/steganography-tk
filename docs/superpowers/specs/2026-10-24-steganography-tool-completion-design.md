# Steganography Tool Completion Design

## Intent

Complete the repository roadmap on a separate branch based on `gui`, integrating the existing `uiuximprov` work and making its GUI, CLI, embedding modes, tests, and release pipeline safe to use and accurately described.

## Current state

The `gui` branch contains a broken legacy launcher. `uiuximprov` adds the modular `stego/` package, a new `gui/` package, GIF/PDF/video-frame modes, auxiliary GUI tools, tests, Docker configuration, CI, and PyInstaller release jobs. Static review found that the candidate still violates required gates: incomplete AES-GCM header AAD, lossy output paths, missing per-mode tests, untested MP4 behavior, undisclosed metadata embedding, broken GUI imports and command wiring, and a tracked developer virtual-environment file. Several roadmap features exist only partially: the capacity display omits envelope overhead, the detector checks only for the app's header, and the release workflow has upload conditions that do not match its events.

## Goals

- Merge `uiuximprov` into a new branch based on `gui`; resolve the README and application conflicts in favor of a coherent current CLI/GUI. Remove `pyvenv.cfg`, obsolete launch/test files, and generated test images; ignore local environments and generated outputs.
- Keep AES-256-GCM with a fresh random salt and nonce per message and PBKDF2-SHA256 at 200,000 or more iterations. Authenticate the complete serialized header for new encrypted payloads, and keep existing payloads readable where the format allows.
- Guarantee round trips for each retained embed mode. Require PNG for image LSB output; use a lossless video-frame output path or reject lossy output. Reject inputs that exceed each mode's actual capacity.
- Treat MP3/MP4/audio/video/PDF metadata storage as metadata embedding in the CLI, GUI, and README. Do not describe visible metadata tags as steganography.
- Make the GUI launch the current CLI with `sys.executable` and an `app.py` path relative to `__file__`, repair callbacks with missing imports and wrong command arguments, and keep normal UI actions usable.
- Complete the roadmap's usable image-capacity meter, drag-and-drop for cover and payload files, and post-encode statistical detectability estimate. The statistical result must be described as a heuristic with limits, not a guarantee of secrecy.
- Provide Windows and macOS PyInstaller downloads through a release workflow. Publishing a release itself is outside this branch task; the workflow must build and attach the files when a release is published.
- Run the project tests and relevant build checks in an isolated Docker environment, and review the final branch independently before pushing and opening a PR into `gui`.

## Approaches

1. **Merge and repair the existing branch (selected by the repository instructions).** This preserves the modular implementation and its existing user-facing work, while allowing a reviewable merge into `gui` followed by focused corrections.
2. Cherry-pick selected commits. This still has to reconcile the two histories and risks dropping related GUI, tests, or workflow changes; it also contradicts the explicit merge instruction.
3. Rewrite from `gui`. This discards most of the candidate's implementation and adds more risk and work without improving the specified result.

The requested branch workflow and AGENTS.md select approach 1.

## Product behavior decisions

- New encrypted payloads will use a versioned header whose serialized bytes, including lengths, are supplied as AES-GCM AAD. Legacy payload decoding will be retained only where it can be unambiguously and safely recognized.
- Metadata modes will have an explicit finite payload limit so capacity overflow is deterministic and testable.
- Retained audio/video attachment options preserve the original image or MP3 file bytes. New attachment payloads use the versioned envelope; legacy version 1 image attachments remain decodable where their dimensions are present.
- Detectability feedback will use a pairs-of-values chi-square statistic for LSB-replacement images. It will report the statistic and a plain-language heuristic, and state that it does not prove whether data is present or guarantee undetectability.
- Image/frame embedding will be available only where the output can be verified to preserve embedded bits. A mode that cannot meet that contract will be removed from the UI/CLI rather than reported as successful.
- macOS downloads will be packaged in the platform's standard app bundle/archive form when a single-file executable is not appropriate; users will not need to install Python.

## Non-goals

- Renaming the remote default branch, deleting remote branches, or merging the PR.
- Publishing a GitHub release, signing/notarizing builds, or changing repository ownership and settings.
- Adding cryptographic algorithms, lowering cryptographic parameters, or promising statistical undetectability.
- Adding unrelated media formats or features outside the AGENTS.md roadmap.

## Constraints

- The GUI must call library functions directly or use `sys.executable` with a path relative to `__file__`.
- Lossy outputs destroy LSB data. Image stego output must be PNG or another verified lossless format; JPEG and lossy video output must be refused or warned against.
- Crypto remains AES-GCM with fresh random salt and nonce per message, PBKDF2-SHA256 at least 200,000 iterations, and header fields bound as AAD.
- Every retained embed mode needs an embed/extract byte-identical round-trip test, wrong-password test, and capacity-overflow test.
- Do not commit virtual environments, `pyvenv.cfg`, generated stego files, or test outputs.
