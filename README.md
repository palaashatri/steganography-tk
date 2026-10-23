# Steganography Tool

[![Tests](https://github.com/palaashatri/steganography-tk/actions/workflows/test.yml/badge.svg)](https://github.com/palaashatri/steganography-tk/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/palaashatri/steganography-tk/branch/main/graph/badge.svg)](https://codecov.io/gh/palaashatri/steganography-tk)

A powerful LSB (Least Significant Bit) steganography tool with GUI and CLI interfaces, supporting multiple file formats with optional AES-GCM encryption.

## Features

- **Multiple File Formats**: Images (PNG, JPG, GIF), Audio (MP3, MP4, WAV), Video (MP4, MKV, AVI), PDF
- **LSB Methods**: Standard LSB, LSB-PRNG, LSB-Match-PRNG
- **Encryption**: Optional AES-GCM encryption with password protection
- **Compression**: Optional zlib compression for payloads
- **Dual Interface**: Full-featured GUI and comprehensive CLI
- **Cross-Platform**: Windows, macOS, Linux support
- **Native Theming**: macOS aqua/darkAqua support

## Installation

### From Source

```bash
git clone https://github.com/palaashatri/steganography-tk.git
cd steganography-tk
pip install -r requirements.txt
```

### Using Docker

```bash
docker build -t steganography .
docker run -it steganography
```

### Pre-built Executables

Download from [Releases](https://github.com/palaashatri/steganography-tk/releases)

## Usage

### GUI

```bash
python gui/main.py
```

### CLI

```bash
# Encode message in image
python app.py encode --image input.png --out output.png --message "Secret message"

# Decode from image
python app.py decode --image output.png

# With encryption
python app.py encode --image input.png --out output.png --message "Secret" --password mypass

# Audio steganography
python app.py audio-encode --audio input.mp3 --out output.mp3 --message "Hidden"

# Generate QR code
python app.py qr --text "https://example.com" --out qr.png
```

## Testing

### Local Testing

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_core.py
```

### Docker Testing

```bash
# Build and run tests
docker build --target test -t stego-test .
docker run --rm stego-test
```

### CI/CD

The project uses GitHub Actions for:
- Automated testing on Linux, macOS, Windows
- Code coverage reporting
- Building executables for all platforms
- Docker image publishing

## Project Structure

```
steganography-tk/
├── app.py              # CLI interface
├── stego/              # Core steganography modules
│   ├── core.py         # Headers, encryption, bit operations
│   ├── image.py        # Image LSB operations
│   ├── audio.py        # Audio metadata operations
│   ├── video.py        # Video metadata operations
│   ├── pdf.py          # PDF metadata operations
│   └── utils.py        # Utilities (QR, decoders)
├── gui/                # GUI interface
│   └── main.py         # Tkinter GUI
├── tests/              # Test suite
│   ├── test_core.py
│   ├── test_image.py
│   ├── test_cli.py
│   └── ...
├── Dockerfile          # Multi-stage Docker build
└── .github/workflows/  # CI/CD pipelines
```

## Development

### Running Tests

```bash
# All tests
pytest -v

# Specific module
pytest tests/test_core.py -v

# With coverage
pytest --cov=stego --cov=gui --cov=app --cov-report=html

# Skip slow tests
pytest -m "not slow"
```

### Building Executables

```bash
# Install PyInstaller
pip install pyinstaller

# Build CLI
pyinstaller --onefile --name stego-cli app.py

# Build GUI
pyinstaller --onefile --windowed --name stego-gui gui/main.py
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## Authors

- [@palaashatri](https://github.com/palaashatri)
