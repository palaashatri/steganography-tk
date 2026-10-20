# Steganography Suite built with Python 3 PyTk

<img width="1842" height="1376" alt="image" src="https://github.com/user-attachments/assets/483c80c4-fa38-4839-b4d1-ebf94ff58659" />


Complete CLI tool for steganography with multiple embedding methods:
- **LSB Image Steganography**: Hide text/files in images using Least Significant Bit techniques
- **MP3 Audio Steganography**: Hide text/files/images in MP3 files using ID3 tags

All methods support optional AES-256-GCM encryption with password protection.


> **Status (2026-10-20):** on this branch the **GUI does not work** — `gui.py` still launches `python3 1_Implementation/app.py`, a folder that no longer exists. Use the command-line tool (`python3 app.py …`) for now. MP3 and MP4 modes store the payload in the file's metadata tags; anyone who lists the tags can see it, so treat them as hidden-in-container rather than steganography, and use `--password` if the content matters. MP4 extraction currently fails on the test fixtures. The `uiuximprov` branch fixes most of this and adds tests; it has not been merged yet.

## Roadmap

In priority order — each is something a user would notice:

1. **A working GUI** — merge `uiuximprov` (package split, GUI rewrite, tests, CI on three OSes).
2. **Honest modes in the UI:** label image LSB as steganography and MP3/MP4 as metadata embedding, and warn when output would be saved in a lossy format that destroys hidden data.
3. **Capacity meter:** show how many bytes a chosen cover image can hold before encoding.
4. **Drag and drop** cover files and payloads into the window.
5. **Detection self-check:** after encoding, run a basic statistical test (for example chi-square on LSBs) and tell the user how detectable the result is.
6. **Single-file downloads** for Windows and macOS so users don't need Python.

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Features

### Image Steganography (LSB)
- **lsb:** Basic sequential LSB substitution
- **lsb-prng:** Pixels selected via PRNG permutation using `--prng-key`
- **lsb-match-prng:** LSB matching (±1) with PRNG permutation
- Optional AES-256-GCM encryption

### MP3 Steganography (ID3 Tags)
- Embed text messages, files, or images in MP3 files
- Automatic payload type detection on extraction
- Optional AES-256-GCM encryption
- Preserves audio quality and playback

**Note:** Use lossless image formats (PNG) for outputs; JPEG recompression will destroy hidden data.

## Usage

### Graphical User Interface (GUI)

Launch the GUI application with a user-friendly interface:
```bash
python3 gui.py
```

The GUI provides:
- **Tabbed Interface**: Separate tabs for Image, MP3, and MP4 encode/decode operations
- **File Browsing**: Easy file selection with native file dialogs
- **Visual Feedback**: Status bar showing operation progress and results
- **Data Extraction Display**: Built-in text viewer for extracted content
- **Password Protection**: Simple password entry for encrypted operations

**Features:**
- Image steganography (LSB) with text/file/image embedding
- MP3 audio steganography with auto-detection of payload types
- MP4 video steganography with comprehensive data embedding
- Optional encryption/decryption with passwords
- Real-time status updates and error messages
- Clear and intuitive workflow for each media type

### Image Steganography

**Encode text into image (basic LSB):**
```bash
python3 app.py encode --image cover.png --out secret.png --message "hello world"
```

**Encode with PRNG permutation:**
```bash
python3 app.py encode --image cover.png --out secret.png --message "hello world" --method lsb-prng --prng-key "my-key"
```

**Encode with LSB matching + PRNG:**
```bash
python3 app.py encode --image cover.png --out secret.png --message "hello world" --method lsb-match-prng --prng-key "my-key"
```

**Encode file with encryption:**
```bash
python3 app.py encode --image cover.png --out secret.png --in-file notes.txt --password "strong passphrase"
```

**Decode from image:**
```bash
python3 app.py decode --image secret.png --method lsb
```

**Decode encrypted image to file:**
```bash
python3 app.py decode --image secret.png --out extracted.txt --password "strong passphrase"
```

### MP3 Steganography

**Embed text message in MP3:**
```bash
python3 app.py mp3-encode --mp3 song.mp3 --out output.mp3 --message "Secret message"
```

**Embed text with encryption:**
```bash
python3 app.py mp3-encode --mp3 song.mp3 --out output.mp3 --message "Secret message" --password "secure_key"
```

**Embed file in MP3:**
```bash
python3 app.py mp3-encode --mp3 song.mp3 --out output.mp3 --in-file secret.zip
```

**Embed image in MP3:**
```bash
python3 app.py mp3-encode --mp3 song.mp3 --out output.mp3 --image secret.png
```

**Extract from MP3 (auto-detects type):**
```bash
python3 app.py mp3-decode --mp3 output.mp3 --out extracted_data
```

**Extract encrypted MP3:**
```bash
python3 app.py mp3-decode --mp3 output.mp3 --out extracted_data --password "secure_key"
```

### MP4 Steganography

**Embed text message in MP4:**
```bash
python3 app.py mp4-encode --mp4 video.mp4 --out output.mp4 --message "Secret message"
```

**Embed text with encryption:**
```bash
python3 app.py mp4-encode --mp4 video.mp4 --out output.mp4 --message "Secret message" --password "secure_key"
```

**Embed image in MP4:**
```bash
python3 app.py mp4-encode --mp4 video.mp4 --out output.mp4 --image secret.png
```

**Embed MP3 in MP4:**
```bash
python3 app.py mp4-encode --mp4 video.mp4 --out output.mp4 --mp3 audio.mp3
```

**Extract from MP4 (auto-detects type):**
```bash
python3 app.py mp4-decode --mp4 output.mp4 --out extracted_data
```

**Extract encrypted MP4:**
```bash
python3 app.py mp4-decode --mp4 output.mp4 --out extracted_data --password "secure_key"
```

## Complete Example Workflow

```bash
# 1. Hide text in image using LSB
python3 app.py encode --image cover.png --out image_with_text.png --message "Secret message"

# 2. Hide the image file in MP3
python3 app.py mp3-encode --mp3 song.mp3 --out song_with_image.mp3 --image image_with_text.png

# 3. Extract image from MP3
python3 app.py mp3-decode --mp3 song_with_image.mp3 --out recovered_image.png

# 4. Extract text from recovered image
python3 app.py decode --image recovered_image.png --out final_message.txt
```

## Testing

Run the comprehensive test suite:
```bash
python3 test_suite.py
```

This validates all functionality including:
- LSB image steganography
- LSB with encryption
- MP3 text embedding
- MP3 image embedding
- MP3 file embedding
- MP3 encrypted embedding
- MP4 text embedding
- MP4 image embedding
- MP4 MP3 embedding
- MP4 encrypted embedding

**Expected Result:** 10/10 tests passed

Decode (PRNG-based):
```bash
python 1_Implementation/app.py decode --image secret.png --method lsb-prng --prng-key "my-key"
# or for LSB matching
python 1_Implementation/app.py decode --image secret.png --method lsb-match-prng --prng-key "my-key"
```

Decode to a file:
```bash
python 1_Implementation/app.py decode --image secret.png --out recovered.bin --method lsb
```

Add `--verbose` to see debug logging.

## Run script (macOS)
```bash
./run.sh encode --image cover.png --out secret.png --message "hi" --method lsb
./run.sh decode --image secret.png --method lsb
```

## Resources
* Steganography - [Wikipedia](https://en.wikipedia.org/wiki/Steganography)
* Python Image Library (Pillow) - [Website](https://python-pillow.org/)
