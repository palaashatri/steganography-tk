# Steganography Tool

[![Tests](https://github.com/palaashatri/steganography-tk/actions/workflows/test.yml/badge.svg)](https://github.com/palaashatri/steganography-tk/actions/workflows/test.yml)

This project provides image LSB steganography and a desktop GUI. Its audio, video, and PDF commands store payloads in ordinary container metadata; those commands do **not** conceal that data and should not be described as steganography.

## What each mode does

### Image LSB mode

The `encode` and `decode` commands store bytes in image pixel least-significant bits. Encoded image output is PNG so those bits survive saving. JPEG and GIF are not supported as output formats. Optional encryption uses AES-GCM with a fresh salt and nonce and PBKDF2-SHA256 (200,000 iterations).

### Visible metadata modes

Metadata is visible to tag and document inspection tools. Encryption protects the payload contents when a password is supplied, but the tag, comment, or PDF field remains present and detectable. Each metadata mode accepts a serialized envelope of at most **1,000,000 bytes**. The limit is checked before the carrier output is written; base64 storage adds overhead to the final container size.

| Command | Supported carrier extensions | Metadata location |
| --- | --- | --- |
| `audio-encode` / `audio-decode` | `.mp3`, `.mp4`, `.m4a`, `.m4b`, `.m4p`, `.m4v`, `.mov`, `.wav`, `.flac`, `.ogg`, `.opus`, `.aac` | MP3 APIC frame, MP4-family atom, or audio metadata tag |
| `video-encode` / `video-decode` | `.mp4`, `.m4a`, `.m4b`, `.m4p`, `.m4v`, `.mov`, `.mkv`, `.avi`, `.webm` | MP4-family atom or visible container comment |
| `pdf-encode` / `pdf-decode` | `.pdf` | PDF document metadata field |

MP3 and MP4-family metadata modes also accept image attachments; MP4-family video metadata supports `--image` and `--mp3` attachments. Attachments are stored as their original file bytes in new envelopes. Existing version 1 pixel-based image attachments remain decodable where their dimensions are present.

## Installation

```bash
git clone https://github.com/palaashatri/steganography-tk.git
cd steganography-tk
python -m pip install -r requirements.txt
```

Run the GUI with:

```bash
python gui/main.py
```

## CLI examples

Image LSB embedding writes a PNG carrier:

```bash
python app.py encode --image cover.png --out stego.png --in-file secret.bin --password "choose-a-password"
python app.py decode --image stego.png --out recovered.bin --password "choose-a-password"
```

The following commands store **visible metadata**. Anyone who lists the carrier tags or document properties can see that a payload was stored.

```bash
# Audio tags or metadata
python app.py audio-encode --audio input.flac --out output.flac --in-file secret.bin --password "choose-a-password"
python app.py audio-decode --audio output.flac --out recovered.bin --password "choose-a-password"

# Video container comment or metadata
python app.py video-encode --video input.mkv --out output.mkv --message "Visible metadata payload"
python app.py video-decode --video output.mkv --out recovered.bin

# PDF document metadata
python app.py pdf-encode --pdf input.pdf --out output.pdf --in-file secret.bin
python app.py pdf-decode --pdf output.pdf --out recovered.bin
```

For MP3 or MP4-family carriers, `audio-encode` accepts `--image` to store an image file. For MP4-family carriers, `video-encode` accepts `--image` or `--mp3`. Those options preserve the attached file bytes inside the envelope; they do not embed image pixels in a video or audio stream.

Use `python app.py --help` or a command's `--help` for all options. Metadata encode help states the visibility and 1,000,000-byte envelope limit.

## Verification

Run tests locally with:

```bash
python -m pip install pytest pytest-cov
pytest -q
```

Run the Docker test image with:

```bash
docker build --target test -t stego-test .
docker run --rm stego-test
```

The [CI workflow](https://github.com/palaashatri/steganography-tk/actions/workflows/ci-cd.yml) runs source tests on Linux, macOS, and Windows, and builds and runs the Docker test image. The Docker verification commands above use the same test suite. [Windows and macOS downloadable packages are attached to published GitHub releases](https://github.com/palaashatri/steganography-tk/releases); this repository does not publish a release as part of normal branch verification.

## Project structure

```text
steganography-tk/
├── app.py              # CLI interface
├── stego/              # Core, image, audio, video, PDF, and utility operations
├── gui/                # Tkinter interface
├── tests/              # Automated tests
├── Dockerfile          # Containerized verification and build stages
└── .github/workflows/  # CI and release packaging
```

## License

MIT License. See [LICENSE](LICENSE).
