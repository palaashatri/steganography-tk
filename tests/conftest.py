"""Pytest configuration and fixtures."""

import os
import sys
import tempfile
from pathlib import Path

import pytest
from PIL import Image
import numpy as np

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_image(temp_dir):
    """Create a sample test image."""
    img_path = temp_dir / "test_image.png"
    # Create a 100x100 RGB image
    img_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(img_array)
    img.save(img_path)
    return img_path


@pytest.fixture
def sample_text():
    """Sample text for testing."""
    return "This is a secret message for testing steganography!"


@pytest.fixture
def sample_file(temp_dir):
    """Create a sample text file."""
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("This is test file content for steganography testing.")
    return file_path


@pytest.fixture
def password():
    """Standard password for tests."""
    return "test_password_123"
