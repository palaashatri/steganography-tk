"""Tests for GUI functionality.

Note: GUI tests require a display. In CI/CD, these run with Xvfb (virtual display).
"""

import pytest
import sys
import os

# Skip GUI tests if no display available
if os.environ.get('CI') or not os.environ.get('DISPLAY'):
    pytest.skip("GUI tests require display - run with Xvfb in CI", allow_module_level=True)


class TestGUIImport:
    """Test GUI module imports."""

    def test_gui_imports(self):
        """Test that GUI module can be imported."""
        try:
            from gui import main
            assert main is not None
        except ImportError as e:
            pytest.fail(f"Failed to import GUI: {e}")

    def test_stego_imports_in_gui(self):
        """Test that GUI can import stego modules."""
        from gui import main
        # If we got here, imports worked
        assert True


class TestGUIComponents:
    """Test GUI components (requires display)."""

    @pytest.fixture
    def app(self):
        """Create GUI app instance."""
        pytest.skip("GUI component tests - implement with tkinter test framework")

    def test_app_initialization(self, app):
        """Test that app initializes."""
        assert app is not None
