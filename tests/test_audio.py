"""Tests for stego.audio module."""

import pytest
from stego.audio import (
    embed_data_in_audio,
    extract_data_from_audio,
)


class TestAudioOperations:
    """Test audio steganography operations."""

    @pytest.fixture
    def sample_mp3(self, temp_dir):
        """Create a minimal MP3 file for testing."""
        # Note: This is a placeholder - in real tests you'd need actual audio files
        # For CI/CD, we'll use fixtures or download sample files
        pytest.skip("Requires sample MP3 file - add to test fixtures")

    def test_embed_extract_mp3(self, sample_mp3, sample_text, password, temp_dir):
        """Test MP3 embedding and extraction."""
        output_mp3 = temp_dir / "stego.mp3"

        # Embed
        embed_data_in_audio(
            str(sample_mp3),
            str(output_mp3),
            password=password,
            message=sample_text
        )

        # Extract
        output_file = temp_dir / "extracted.txt"
        extract_data_from_audio(str(output_mp3), str(output_file), password=password)

        assert output_file.read_text() == sample_text
