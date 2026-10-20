# AGENTS.md — steganography-tk

A Python 3 Tkinter desktop app plus CLI for hiding data: LSB steganography in images (key-derived pixel permutation, optional AES-256-GCM encryption with PBKDF2-SHA256 at 200k iterations), and embedding payloads in MP3/MP4 files.

## Current state (2026-10-20) — read before changing anything

The default branch is **`gui`**, and it is broken:

- `gui.py` runs `python3 1_Implementation/app.py ...` from the parent directory. That folder no longer exists, so **every GUI action fails**. `test.py` uses the same path, so it reports 0/10.
- With the path fixed, the CLI passes the image and MP3 cases (6/10); the four MP4 decode cases fail with "Could not read MP4 metadata".
- MP3/MP4 "embedding" stores the payload in ID3/MP4 metadata tags. That is hiding data in a container, not steganography; anyone listing the tags sees it. Say so in the UI and README.

The branch **`uiuximprov`** (13 commits ahead of `gui`, no PR yet) already fixes most of this: it splits the code into a `stego/` package (`core`, `image`, `audio`, `video`, `pdf`, `utils`), adds a `gui/` package, GIF/PDF/video-frame modes, a pytest suite (17 passed, 2 skipped when run on 2026-10-20) and GitHub Actions on Linux/macOS/Windows with Python 3.14. It also commits a stray `pyvenv.cfg` and still carries the old `app.py`/`test.py`. **First task: review and merge `uiuximprov` into `gui` (deleting `pyvenv.cfg`), then make the old files go away.** The `cli` branch is 4 commits behind `gui` and can be deleted.

## Commands (on `gui`)

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt   # Pillow, cryptography, mutagen
python3 app.py encode --image cover.png --out stego.png --message "hi" [--password pw]
python3 app.py decode --image stego.png --out secret.txt [--password pw]
python3 app.py mp3-encode|mp3-decode|mp4-encode|mp4-decode ...   # see python3 app.py -h
python3 gui.py            # broken until the path above is fixed
./run.sh                  # creates .venv and runs an encode demo
```

On `uiuximprov`: `pip install -r requirements.txt pytest && pytest -q` (GUI tests need a display; CI uses `xvfb-run` on Linux, and ffmpeg for audio/video).

## Rules

- The GUI must call the library functions directly (or `sys.executable` with a path relative to `__file__`), never a bare `python3` with a hard-coded directory.
- Lossy outputs destroy LSB data. Always write PNG (or another lossless format) for image stego output, and refuse or warn on JPEG/lossy video output.
- Crypto: AES-GCM with a fresh random salt and nonce per message, PBKDF2-SHA256 ≥ 200k iterations, header fields bound as AAD. Don't weaken these or add "custom" ciphers.
- Every embed mode needs a round-trip test (embed → extract → identical bytes), a wrong-password test and a capacity-overflow test.
- Don't commit virtualenvs, `pyvenv.cfg`, generated stego files or test outputs (`test_op.jpg`).

## Git workflow

Never push to `gui`/`main` directly; branch and open a PR with the test results. Consider renaming the default branch to `main` once `uiuximprov` is merged.
