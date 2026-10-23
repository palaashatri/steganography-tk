"""GUI implementation for Steganography Suite.

Native macOS/Windows/Linux interface using tk/ttk.
"""

from __future__ import annotations

import sys
import subprocess
import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional, Callable
from datetime import datetime
from dataclasses import dataclass
import logging

# Add parent directory to path to find stego module (development mode only)
# PyInstaller bundles everything, so this is only needed when running from source
if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).parent.parent))

# Core steganography operations imported from stego package
from stego import (
    load_image,
    embed_stego_data_in_image, extract_stego_data_from_image,
    build_stego_payload, parse_stego_payload,
    embed_data_in_gif, extract_data_from_gif,
    embed_data_in_video_frame, extract_data_from_video_frame,
    embed_data_in_audio, extract_data_from_audio,
    embed_data_in_video, extract_data_from_video,
    embed_data_in_pdf, extract_data_from_pdf,
    generate_qr_code, create_portable_decoder,
    max_payload_bytes, make_rng,
    AUDIO_EXT_LIST, VIDEO_EXT_LIST,
    AUDIO_EXTS, VIDEO_EXTS,
)


def gui_main() -> None:
    # Import tkinter here to avoid module-level initialization
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from PIL import ImageTk, ImageFont

    # Try to import tkinterdnd2
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        dnd_available = True
    except (ImportError, RuntimeError, Exception):
        dnd_available = False
        DND_FILES = None
        TkinterDnD = None

    # Spacing constants - 4px grid system
    PADDING_SMALL = 8
    PADDING_MEDIUM = 12
    PADDING_LARGE = 16
    PADDING_XL = 20
    PADDING_XXL = 24
    BUTTON_WIDTH = 12
    BUTTON_WIDTH_LARGE = 16

    class PlaceholderEntry(ttk.Entry):
        """Entry widget with placeholder text support."""
        def __init__(self, parent, placeholder="", **kwargs):
            # Extract textvariable if provided
            self._string_var = kwargs.pop('textvariable', None)
            super().__init__(parent, **kwargs)
            self.placeholder = placeholder
            self.placeholder_color = "#999999"
            # Use platform-appropriate default text color
            if sys.platform == "win32":
                self.default_color = "SystemWindowText"
            else:
                self.default_color = "black"
            self._has_placeholder = False
            self._ignore_trace = False

            # Set up trace on the variable if provided
            if self._string_var:
                self._string_var.trace_add("write", self._on_var_changed)

            if placeholder:
                self._show_placeholder()

            self.bind("<FocusIn>", self._on_focus_in)
            self.bind("<FocusOut>", self._on_focus_out)
            self.bind("<KeyRelease>", self._on_key_release)

        def _on_var_changed(self, *args):
            """Handle external changes to the StringVar."""
            if not self._ignore_trace and self._string_var:
                value = self._string_var.get()
                if not value and not self._has_placeholder:
                    self._show_placeholder()

        def _on_key_release(self, *args):
            """Update StringVar when user types (without placeholder)."""
            if not self._has_placeholder and self._string_var:
                self._ignore_trace = True
                self._string_var.set(self.get())
                self._ignore_trace = False

        def _show_placeholder(self, *args):
            if not self.get():
                self._has_placeholder = True
                self.insert(0, self.placeholder)
                self.config(foreground=self.placeholder_color)
                # Don't set placeholder in the StringVar
                if self._string_var:
                    self._ignore_trace = True
                    self._string_var.set("")
                    self._ignore_trace = False

        def _on_focus_in(self, *args):
            if self._has_placeholder:
                self.delete(0, tk.END)
                self.config(foreground=self.default_color)
                self._has_placeholder = False

        def _on_focus_out(self, *args):
            # Update StringVar with actual value
            if not self._has_placeholder and self._string_var:
                self._ignore_trace = True
                self._string_var.set(self.get())
                self._ignore_trace = False

            if not self.get():
                self._show_placeholder()

        def get_value(self):
            """Get the actual value, returning empty string if showing placeholder."""
            if self._has_placeholder:
                return ""
            return self.get()
            """Get actual value without placeholder."""
            return "" if self._has_placeholder else self.get()

    class PasswordEntry(ttk.Frame):
        """Password entry with show/hide toggle."""
        def __init__(self, parent, textvariable=None, **kwargs):
            super().__init__(parent)
            self.var = textvariable or tk.StringVar(master=parent)
            self.showing = False

            self.entry = ttk.Entry(self, textvariable=self.var, show="●", **kwargs)
            self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

            self.toggle_btn = ttk.Button(self, text="👁", width=3, command=self._toggle_visibility)
            self.toggle_btn.pack(side=tk.LEFT, padx=(4, 0))

        def _toggle_visibility(self):
            self.showing = not self.showing
            self.entry.config(show="" if self.showing else "●")
            self.toggle_btn.config(text="👁" if not self.showing else "✕")

    class CapacityCalculator:
        @staticmethod
        def image_lsb_capacity(path: str) -> int:
            try:
                img = Image.open(path)
                pixels = img.width * img.height * len(img.getbands())
                return max(0, (pixels // 8) - 100)
            except Exception:
                return 0

        @staticmethod
        def format_bytes(value: int) -> str:
            size = float(value)
            for unit in ["B", "KB", "MB", "GB", "TB"]:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} PB"

    class PasswordValidator:
        @staticmethod
        def check_strength(password: str) -> tuple[str, str]:
            if not password:
                return ("none", "No password")

            score = 0
            if len(password) >= 12:
                score += 1
            if len(password) >= 20:
                score += 1
            if any(c.isupper() for c in password):
                score += 1
            if any(c.islower() for c in password):
                score += 1
            if any(c.isdigit() for c in password):
                score += 1
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                score += 1

            levels = {
                0: ("none", "No password"),
                1: ("weak", "Weak"),
                2: ("fair", "Fair"),
                3: ("good", "Good"),
                4: ("strong", "Strong"),
                5: ("strong", "Strong"),
                6: ("very_strong", "Very Strong"),
            }
            return levels.get(score, ("very_strong", "Very Strong"))

    def compute_psnr(img_a: Image.Image, img_b: Image.Image) -> float:
        diff = ImageChops.difference(img_a, img_b)
        stat = ImageStat.Stat(diff)
        mse = sum((v ** 2 for v in stat.mean)) / len(stat.mean)
        if mse == 0:
            return float("inf")
        return 20 * (255.0 / (mse ** 0.5))

    def normalize_dnd_files(data: str, widget: tk.Widget) -> list[str]:
        if not data:
            return []
        return list(widget.tk.splitlist(data))

    class Tooltip:
        def __init__(self, widget: tk.Widget, text: str):
            self.widget = widget
            self.text = text
            self.tip: Optional[tk.Toplevel] = None
            widget.bind("<Enter>", self.show)
            widget.bind("<Leave>", self.hide)

        def show(self, _event=None):
            if self.tip or not self.text:
                return
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 10
            self.tip = tip = tk.Toplevel(self.widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{x}+{y}")
            # Tooltips always use a light background for readability
            tip.configure(bg="#f0f0f0")
            label = tk.Label(tip, text=self.text, bg="#f0f0f0", fg="#000000",
                           padx=8, pady=4, relief=tk.SOLID, borderwidth=1)
            label.pack()

        def hide(self, _event=None):
            if self.tip:
                self.tip.destroy()
                self.tip = None

    @dataclass
    class HistoryItem:
        timestamp: str
        action: str
        status: str
        details: str

    class StatusBar(ttk.Frame):
        def __init__(self, parent: tk.Widget):
            super().__init__(parent, relief=tk.RAISED, borderwidth=1)
            self.message = ttk.Label(self, text="Ready", font=("TkDefaultFont", 9))
            self.message.pack(side=tk.LEFT, padx=(PADDING_MEDIUM, PADDING_MEDIUM))

            ttk.Separator(self, orient=tk.VERTICAL).pack(side=tk.RIGHT, fill=tk.Y, padx=4)

            self.time_label = ttk.Label(self, text="", font=("TkDefaultFont", 9))
            self.time_label.pack(side=tk.RIGHT, padx=(0, PADDING_SMALL))

            self.progress = ttk.Progressbar(self, mode="indeterminate", length=200)
            self.progress.pack(side=tk.RIGHT, padx=PADDING_SMALL, pady=2)

            self.start_time = None

        def set_status(self, text: str, status_type: str = "info") -> None:
            """Set status with optional type (info/success/error/warning)."""
            prefix = ""
            if status_type == "success":
                prefix = "✓ "
            elif status_type == "error":
                prefix = "✗ "
            elif status_type == "warning":
                prefix = "⚠ "
            self.message.config(text=prefix + text)

        def start(self) -> None:
            self.progress.start(10)
            self.start_time = time.time()
            self._update_elapsed()

        def stop(self) -> None:
            self.progress.stop()
            self.start_time = None
            self.time_label.config(text="")

        def _update_elapsed(self):
            if self.start_time:
                elapsed = int(time.time() - self.start_time)
                mins, secs = divmod(elapsed, 60)
                self.time_label.config(text=f"{mins:02d}:{secs:02d}")
                self.after(1000, self._update_elapsed)

    class SteganographyGUI:
        def __init__(self, root: tk.Tk):
            self.root = root
            self.root.title("Steganography Suite")

            # Disable macOS window tabbing to prevent "tk" tab
            if sys.platform == "darwin":
                try:
                    # Removed moveableModal - it breaks window controls
                    # Also try to prevent automatic tab creation
                    self.root.createcommand('::tk::mac::ShowPreferences', lambda: None)
                except Exception:
                    pass

            # Enable DPI awareness on Windows
            if sys.platform == "win32":
                try:
                    from ctypes import windll
                    windll.shcore.SetProcessDpiAwareness(1)
                except Exception:
                    pass

            self.root.geometry("1400x920")
            self.root.minsize(1100, 750)
            self.history: list[HistoryItem] = []
            self.preview_visible = tk.BooleanVar(master=self.root, value=True)
            self.recent_files: list[str] = []
            self.preferences = self._load_preferences()

            # Restore window geometry
            if "geometry" in self.preferences:
                try:
                    self.root.geometry(self.preferences["geometry"])
                except Exception:
                    pass

            # Build UI first, then apply theme
            self._build_ui()
            self._apply_native_theme()
            self._setup_keyboard_shortcuts()

            # Save window geometry on close
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        def _apply_native_theme(self) -> None:
            """Apply native OS theme with dark mode detection."""
            style = ttk.Style()

            if sys.platform == "darwin":
                # Detect macOS dark mode and apply appearance
                dark_mode = self._detect_dark_mode()
                try:
                    appearance = "darkAqua" if dark_mode else "aqua"
                    self.root.tk.call("::tk::unsupported::MacWindowStyle", "appearance", self.root._w, appearance)
                except Exception:
                    pass

                # Apply aqua theme
                if "aqua" in style.theme_names():
                    style.theme_use("aqua")

            elif sys.platform == "win32":
                # Detect Windows dark mode
                dark_mode = self._detect_dark_mode()

                if dark_mode:
                    # Use alt/clam theme for better dark mode support
                    if "alt" in style.theme_names():
                        style.theme_use("alt")
                    elif "clam" in style.theme_names():
                        style.theme_use("clam")

                    # Apply dark colors
                    bg_color = "#2b2b2b"
                    fg_color = "#ffffff"
                    select_bg = "#0078d7"

                    style.configure(".", background=bg_color, foreground=fg_color,
                                  fieldbackground="#3c3c3c", selectbackground=select_bg,
                                  selectforeground="#ffffff", bordercolor=bg_color,
                                  darkcolor=bg_color, lightcolor=bg_color)

                    style.map(".", background=[("active", "#3c3c3c")],
                             foreground=[("active", fg_color)])

                    style.configure("TFrame", background=bg_color)
                    style.configure("TLabel", background=bg_color, foreground=fg_color)
                    style.configure("TLabelframe", background=bg_color, bordercolor=bg_color)
                    style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
                    style.configure("Header.TLabel", background=bg_color, foreground=fg_color)

                    style.configure("TButton", background="#3c3c3c", foreground=fg_color,
                                  bordercolor="#3c3c3c", lightcolor="#3c3c3c", darkcolor="#3c3c3c")
                    style.map("TButton", background=[("active", "#4c4c4c"), ("pressed", "#1e1e1e")])

                    style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
                    style.map("TCheckbutton", background=[("active", bg_color)])

                    style.configure("TRadiobutton", background=bg_color, foreground=fg_color)
                    style.map("TRadiobutton", background=[("active", bg_color)])

                    style.configure("TNotebook", background=bg_color, bordercolor=bg_color)
                    style.configure("TNotebook.Tab", background="#3c3c3c", foreground=fg_color)
                    style.map("TNotebook.Tab", background=[("selected", "#4c4c4c")])

                    style.configure("TEntry", fieldbackground="#3c3c3c", foreground=fg_color,
                                  bordercolor=bg_color, lightcolor=bg_color, darkcolor=bg_color)

                    self.root.configure(bg=bg_color)

                    # Try to set title bar to dark mode (Windows 10 build 17763+)
                    try:
                        import ctypes
                        hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                        ctypes.windll.dwmapi.DwmSetWindowAttribute(
                            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                            ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
                        )
                    except Exception:
                        pass
                else:
                    # Light mode: use native Windows theme
                    for name in ("vista", "xpnative", "winnative"):
                        if name in style.theme_names():
                            style.theme_use(name)
                            break

            # Apply standard styling
            style.configure("Primary.TButton", padding=(PADDING_MEDIUM, PADDING_SMALL))
            style.configure("TLabelframe.Label", font=("TkDefaultFont", 10, "bold"))
            style.configure("Header.TLabel", font=("TkDefaultFont", 16, "bold"))

        def _detect_dark_mode(self) -> bool:
            try:
                if sys.platform == "win32":
                    import winreg

                    key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                        return value == 0
                if sys.platform == "darwin":
                    result = subprocess.run(
                        ["defaults", "read", "-g", "AppleInterfaceStyle"],
                        capture_output=True,
                        text=True,
                    )
                    return result.returncode == 0 and "Dark" in result.stdout
            except Exception:
                return False
            return False

        def _build_ui(self) -> None:
            # Header with title and toolbar
            header = ttk.Frame(self.root)
            header.pack(side=tk.TOP, fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            title_frame = ttk.Frame(header)
            title_frame.pack(side=tk.TOP, fill=tk.X, pady=(PADDING_SMALL, 0))
            ttk.Label(title_frame, text="Steganography Suite", style="Header.TLabel").pack(side=tk.LEFT)

            # Quick action toolbar
            toolbar = ttk.Frame(title_frame)
            toolbar.pack(side=tk.RIGHT)
            ttk.Button(toolbar, text="Open", width=8, command=self._quick_open).pack(side=tk.LEFT, padx=2)
            ttk.Button(toolbar, text="Settings", width=8, command=self._show_settings).pack(side=tk.LEFT, padx=2)
            ttk.Checkbutton(toolbar, text="Preview", variable=self.preview_visible,
                          command=self._toggle_preview).pack(side=tk.LEFT, padx=PADDING_SMALL)

            ttk.Separator(header, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(PADDING_SMALL, 0))

            # Recent files bar
            self.recent_bar = ttk.Frame(header)
            self.recent_bar.pack(side=tk.TOP, fill=tk.X, pady=(4, 0))
            self._update_recent_files_ui()

            # Main content area
            content = ttk.Frame(self.root)
            content.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)
            content.columnconfigure(0, weight=1)
            content.columnconfigure(1, minsize=340)
            content.rowconfigure(0, weight=1)

            main_center = ttk.Frame(content)
            main_center.grid(row=0, column=0, sticky="nsew", padx=(0, PADDING_SMALL))
            main_center.rowconfigure(0, weight=1)
            main_center.columnconfigure(0, weight=1)

            self.notebook = ttk.Notebook(main_center)
            self.notebook.grid(row=0, column=0, sticky="nsew")

            # Clear any default tabs created by ttk.Notebook
            for tab_id in list(self.notebook.tabs()):
                self.notebook.forget(tab_id)

            # Preview panel (collapsible)
            self.preview_frame = ttk.Labelframe(content, text="Preview & Info")
            self.preview_frame.grid(row=0, column=1, sticky="nsew", pady=0)
            self.preview_frame.columnconfigure(0, weight=1)
            self.preview_frame.rowconfigure(0, weight=1)

            self._preview_image_ref = None
            self._preview_video_ref = None

            preview_scroll = ttk.Frame(self.preview_frame)
            preview_scroll.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            image_box = ttk.Labelframe(preview_scroll, text="Image")
            image_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_image = ttk.Label(image_box, text="No image selected", anchor=tk.CENTER)
            self.preview_image.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # File info display
            self.file_info_label = ttk.Label(image_box, text="", font=("TkDefaultFont", 8), foreground="#666")
            self.file_info_label.pack(fill=tk.X, padx=PADDING_SMALL, pady=(0, PADDING_SMALL))

            audio_box = ttk.Labelframe(preview_scroll, text="Audio")
            audio_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_audio = ttk.Label(audio_box, text="No audio selected", wraplength=300, justify=tk.LEFT)
            self.preview_audio.pack(fill=tk.X, padx=PADDING_SMALL, pady=PADDING_SMALL)

            video_box = ttk.Labelframe(preview_scroll, text="Video")
            video_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_video = ttk.Label(video_box, text="No video selected", anchor=tk.CENTER)
            self.preview_video.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            pdf_box = ttk.Labelframe(preview_scroll, text="PDF")
            pdf_box.pack(fill=tk.X, pady=(0, PADDING_SMALL))
            self.preview_pdf = ttk.Label(pdf_box, text="No PDF selected", wraplength=300, justify=tk.LEFT)
            self.preview_pdf.pack(fill=tk.X, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # Reorganized tabs by workflow - Create frames NOT as children of notebook yet
            tab_frames = {
                "Hide Data": ttk.Frame(self.root),
                "Reveal Data": ttk.Frame(self.root),
                "Advanced": ttk.Frame(self.root),
                "Batch Operations": ttk.Frame(self.root),
                "Analysis & Tools": ttk.Frame(self.root),
                "History": ttk.Frame(self.root),
            }

            # Now add them to the notebook
            for name, frame in tab_frames.items():
                self.notebook.add(frame, text=name)

            self.tabs = tab_frames

            # Final cleanup - remove any tabs that shouldn't be there
            for tab_id in list(self.notebook.tabs()):
                try:
                    tab_text = self.notebook.tab(tab_id, "text")
                    if tab_text not in self.tabs.keys():
                        self.notebook.forget(tab_id)
                except:
                    self.notebook.forget(tab_id)

            # Build main tabs with sub-notebooks
            self._build_hide_data_tab(self.tabs["Hide Data"])
            self._build_reveal_data_tab(self.tabs["Reveal Data"])
            self._build_advanced_tab(self.tabs["Advanced"])
            self._build_batch_tab(self.tabs["Batch Operations"])
            self._build_tools_tab(self.tabs["Analysis & Tools"])
            self._build_history_tab(self.tabs["History"])

            self.status = StatusBar(self.root)
            self.status.pack(side=tk.BOTTOM, fill=tk.X)

        def _setup_keyboard_shortcuts(self) -> None:
            """Setup keyboard shortcuts for common actions."""
            self.root.bind("<Control-o>", lambda e: self._quick_open())
            self.root.bind("<Control-s>", lambda e: self._quick_save())
            self.root.bind("<Control-comma>", lambda e: self._show_settings())
            self.root.bind("<F1>", lambda e: self._show_help())
            self.root.bind("<Control-h>", lambda e: self.notebook.select(self.tabs["History"]))

        def _toggle_preview(self) -> None:
            """Toggle preview panel visibility."""
            if self.preview_visible.get():
                self.preview_frame.grid()
                self.root.update_idletasks()  # Force layout update
            else:
                self.preview_frame.grid_remove()
                self.root.update_idletasks()  # Force layout update

        def _quick_open(self) -> None:
            """Quick file open dialog."""
            path = filedialog.askopenfilename(
                title="Open File",
                filetypes=[
                    ("All Supported", "*.png *.jpg *.jpeg *.gif *.mp3 *.mp4 *.pdf"),
                    ("Images", "*.png *.jpg *.jpeg *.gif"),
                    ("Audio", "*.mp3 *.mp4 *.m4a"),
                    ("Video", "*.mp4 *.mov *.avi *.mkv"),
                    ("PDF", "*.pdf"),
                    ("All Files", "*.*"),
                ]
            )
            if path:
                self._add_recent_file(path)
                self._load_file_to_appropriate_tab(path)

        def _quick_save(self) -> None:
            pass  # Placeholder for quick save

        def _show_help(self) -> None:
            """Show help dialog."""
            help_text = """Steganography Suite - Quick Help

Keyboard Shortcuts:
  Ctrl+O: Open file
  Ctrl+S: Quick save
  Ctrl+H: View history
  Ctrl+,: Settings
  F1: Help

Workflow:
1. Hide Data: Embed secret data in images, audio, video, or PDFs
2. Reveal Data: Extract hidden data from files
3. Advanced: Frame-level embedding and GIF support
4. Batch Operations: Process multiple files at once
5. Analysis & Tools: Analyze images, detect steganography

Tips:
- Use PNG format for images (best quality)
- Enable encryption for sensitive data
- PRNG methods are more secure but need a key
- Check capacity before embedding large files
"""
            win = tk.Toplevel(self.root)
            win.title("Help")
            win.geometry("600x500")
            win.transient(self.root)

            # Apply theme based on mode
            if self._detect_dark_mode():
                win.configure(bg="#2b2d31")
                text = tk.Text(win, wrap=tk.WORD, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM,
                             bg="#2b2d31", fg="#dcddde", insertbackground="#dcddde", borderwidth=0)
            else:
                win.configure(bg="SystemButtonFace")
                text = tk.Text(win, wrap=tk.WORD, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM,
                             bg="white", fg="black", insertbackground="black")
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(tk.END, help_text)
            text.config(state=tk.DISABLED)

            ttk.Button(win, text="Close", command=win.destroy, style="Primary.TButton").pack(pady=PADDING_SMALL)

        def _load_preferences(self) -> dict:
            """Load user preferences."""
            pref_path = Path.home() / ".steg_preferences.json"
            if pref_path.exists():
                try:
                    return json.loads(pref_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
            return {}

        def _save_preferences(self) -> None:
            """Save user preferences."""
            pref_path = Path.home() / ".steg_preferences.json"
            self.preferences["geometry"] = self.root.geometry()
            self.preferences["recent_files"] = self.recent_files[:10]
            pref_path.write_text(json.dumps(self.preferences, indent=2), encoding="utf-8")

        def _on_close(self) -> None:
            """Handle window close event."""
            self._save_preferences()
            self.root.destroy()

        def _add_recent_file(self, path: str) -> None:
            """Add file to recent files list."""
            if path in self.recent_files:
                self.recent_files.remove(path)
            self.recent_files.insert(0, path)
            self.recent_files = self.recent_files[:10]
            self._update_recent_files_ui()

        def _update_recent_files_ui(self) -> None:
            """Update recent files display."""
            for widget in self.recent_bar.winfo_children():
                widget.destroy()

            if not self.recent_files:
                ttk.Label(self.recent_bar, text="Recent: None", font=("TkDefaultFont", 8)).pack(side=tk.LEFT)
                return

            ttk.Label(self.recent_bar, text="Recent:", font=("TkDefaultFont", 8)).pack(side=tk.LEFT, padx=(0, PADDING_SMALL))
            for i, path in enumerate(self.recent_files[:5]):
                name = Path(path).name
                if len(name) > 25:
                    name = name[:22] + "..."
                btn = ttk.Button(self.recent_bar, text=name, width=max(8, len(name)),
                               command=lambda p=path: self._load_file_to_appropriate_tab(p))
                btn.pack(side=tk.LEFT, padx=2)
                Tooltip(btn, path)

        def _load_file_to_appropriate_tab(self, path: str) -> None:
            """Load file into the appropriate tab based on extension."""
            ext = Path(path).suffix.lower()
            if ext in (".png", ".jpg", ".jpeg", ".gif"):
                self.notebook.select(self.tabs["Hide Data"])
            elif ext in AUDIO_EXTS:
                self.notebook.select(self.tabs["Hide Data"])
            elif ext in VIDEO_EXTS:
                self.notebook.select(self.tabs["Hide Data"])
            elif ext == ".pdf":
                self.notebook.select(self.tabs["Hide Data"])

        def _show_settings(self) -> None:
            """Show settings dialog."""
            settings = tk.Toplevel(self.root)
            settings.title("Settings")
            settings.geometry("500x400")
            settings.transient(self.root)
            settings.grab_set()

            # Apply theme colors to toplevel window
            if self._detect_dark_mode():
                settings.configure(bg="#2b2d31")
            else:
                settings.configure(bg="SystemButtonFace")

            notebook = ttk.Notebook(settings)
            notebook.pack(fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM)

            # Clear any default tabs
            for tab_id in list(notebook.tabs()):
                notebook.forget(tab_id)

            # General settings
            general = ttk.Frame(notebook)
            notebook.add(general, text="General")

            ttk.Label(general, text="Default Compression:").pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_MEDIUM, 0))
            compress_var = tk.BooleanVar(master=self.root, value=self.preferences.get("default_compress", False))
            ttk.Checkbutton(general, text="Enable compression by default", variable=compress_var).pack(anchor=tk.W, padx=PADDING_MEDIUM)

            ttk.Label(general, text="Default Method:").pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_MEDIUM, 0))
            method_var = tk.StringVar(master=self.root, value=self.preferences.get("default_method", "lsb"))
            ttk.Radiobutton(general, text="LSB (Simple)", variable=method_var, value="lsb").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            ttk.Radiobutton(general, text="LSB-PRNG (Randomized)", variable=method_var, value="lsb-prng").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            ttk.Radiobutton(general, text="LSB-Match (Most Secure)", variable=method_var, value="lsb-match-prng").pack(anchor=tk.W, padx=PADDING_MEDIUM)

            ttk.Separator(general, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM)

            ttk.Checkbutton(general, text="Show preview panel by default",
                          variable=self.preview_visible).pack(anchor=tk.W, padx=PADDING_MEDIUM)

            # Appearance settings
            appearance = ttk.Frame(notebook)
            notebook.add(appearance, text="Appearance")

            ttk.Label(appearance, text="Theme:").pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_MEDIUM, 0))
            ttk.Label(appearance, text="Using system theme (Light/Dark mode)",
                     foreground="gray").pack(anchor=tk.W, padx=PADDING_MEDIUM)

            # Save button
            btn_frame = ttk.Frame(settings)
            btn_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM)

            def save_settings():
                self.preferences["default_compress"] = compress_var.get()
                self.preferences["default_method"] = method_var.get()
                self._save_preferences()
                messagebox.showinfo("Settings", "Settings saved successfully!")
                settings.destroy()

            ttk.Button(btn_frame, text="Save", command=save_settings, width=BUTTON_WIDTH).pack(side=tk.RIGHT)
            ttk.Button(btn_frame, text="Cancel", command=settings.destroy, width=BUTTON_WIDTH).pack(side=tk.RIGHT, padx=(0, PADDING_SMALL))

        def _build_hide_data_tab(self, parent: ttk.Frame) -> None:
            """Main 'Hide Data' tab with sub-tabs for different file types."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            image_frame = ttk.Frame(sub_notebook)
            audio_frame = ttk.Frame(sub_notebook)
            video_frame = ttk.Frame(sub_notebook)
            pdf_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(image_frame, text="Images")
            sub_notebook.add(audio_frame, text="Audio")
            sub_notebook.add(video_frame, text="Video")
            sub_notebook.add(pdf_frame, text="PDF")

            self._build_image_tab(image_frame)
            self._build_audio_tab(audio_frame)
            self._build_video_tab(video_frame)
            self._build_pdf_tab(pdf_frame)

        def _build_reveal_data_tab(self, parent: ttk.Frame) -> None:
            """Main 'Reveal Data' tab for extraction."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            image_frame = ttk.Frame(sub_notebook)
            audio_frame = ttk.Frame(sub_notebook)
            video_frame = ttk.Frame(sub_notebook)
            pdf_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(image_frame, text="Images")
            sub_notebook.add(audio_frame, text="Audio")
            sub_notebook.add(video_frame, text="Video")
            sub_notebook.add(pdf_frame, text="PDF")

            self._build_image_decode_only(image_frame)
            self._build_audio_decode_only(audio_frame)
            self._build_video_decode_only(video_frame)
            self._build_pdf_decode_only(pdf_frame)

        def _build_advanced_tab(self, parent: ttk.Frame) -> None:
            """Advanced features: video frames and GIFs."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            vf_frame = ttk.Frame(sub_notebook)
            gif_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(vf_frame, text="Video Frames")
            sub_notebook.add(gif_frame, text="GIF")

            self._build_video_frames_tab(vf_frame)
            self._build_gif_tab(gif_frame)

        def _build_image_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM)

            encode = ttk.Labelframe(container, text="Encode Image")
            encode.pack(fill=tk.X, pady=(0, PADDING_MEDIUM))

            cover_var = tk.StringVar(master=self.root)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            convert_var = tk.BooleanVar(master=self.root, value=True)
            watermark_var = tk.StringVar(master=self.root)
            nest_var = tk.IntVar(master=self.root, value=1)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)
            capacity_var = tk.StringVar(master=self.root, value="Capacity: ")
            strength_var = tk.StringVar(master=self.root, value="Strength: ")

            self.image_vars = {
                "method": method_var,
                "prng_key": prng_var,
                "compress": compress_var,
                "auto_convert": convert_var,
                "watermark": watermark_var,
                "nest_levels": nest_var,
            }

            self._file_row(
                encode,
                "Cover image",
                cover_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
                on_change=self._update_image_preview,
            )
            ttk.Label(encode, textvariable=capacity_var, foreground="#666").pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            ttk.Separator(encode, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            msg_entry = PlaceholderEntry(encode, textvariable=msg_var, placeholder="Enter secret message...")
            msg_entry.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            paste_btn = ttk.Button(encode, text="Paste from Clipboard", command=lambda: msg_var.set(self._paste_clipboard()), width=BUTTON_WIDTH_LARGE)
            paste_btn.pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            Tooltip(paste_btn, "Paste text from the system clipboard")

            self._file_row(encode, "Payload file (optional)", payload_file_var, filetypes=[("All Files", "*.*")])

            ttk.Separator(encode, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            pwd_entry_frame = PasswordEntry(encode, textvariable=pwd_var)
            pwd_entry_frame.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, 4))
            ttk.Label(encode, textvariable=strength_var, font=("TkDefaultFont", 8), foreground="#666").pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            method_row = ttk.Frame(encode)
            method_row.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            method_box = ttk.Combobox(method_row, textvariable=method_var, state="readonly",
                                      values=["lsb", "lsb-prng", "lsb-match-prng"], width=18)
            method_box.pack(side=tk.LEFT, padx=PADDING_SMALL)
            Tooltip(method_box, "LSB: simple. PRNG: randomized. LSB-match: less detectable.")

            ttk.Label(method_row, text="PRNG key").pack(side=tk.LEFT, padx=(PADDING_LARGE, 0))
            prng_entry = PlaceholderEntry(method_row, textvariable=prng_var, width=28, placeholder="Required for PRNG")
            prng_entry.pack(side=tk.LEFT, padx=PADDING_SMALL)
            Tooltip(prng_entry, "Required for PRNG methods")

            ttk.Separator(encode, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            options_row = ttk.Frame(encode)
            options_row.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Checkbutton(options_row, text="Compress payload", variable=compress_var).pack(side=tk.LEFT)
            ttk.Checkbutton(options_row, text="Auto-convert to PNG", variable=convert_var).pack(side=tk.LEFT, padx=(PADDING_MEDIUM, 0))
            ttk.Label(options_row, text="Nested levels").pack(side=tk.LEFT, padx=(PADDING_LARGE, 4))
            ttk.Spinbox(options_row, from_=1, to=5, textvariable=nest_var, width=4).pack(side=tk.LEFT)

            ttk.Label(encode, text="Watermark text (optional)").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            PlaceholderEntry(encode, textvariable=watermark_var, placeholder="Optional watermark").pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            PlaceholderEntry(encode, textvariable=comment_var, placeholder="Optional comment").pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            PlaceholderEntry(encode, textvariable=expires_var, placeholder="e.g., 2026-12-31").pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            self._save_row(encode, "Output file", out_var, def_ext=".png", filetypes=[("PNG", "*.png")])

            ttk.Button(
                encode,
                text="Embed Data",
                style="Primary.TButton",
                width=BUTTON_WIDTH_LARGE,
                command=lambda: self._encode_image(
                    cover_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    method_var.get(),
                    prng_var.get(),
                    compress_var.get(),
                    convert_var.get(),
                    watermark_var.get(),
                    nest_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_SMALL, PADDING_MEDIUM))

            def update_capacity(*_):
                if cover_var.get():
                    cap = CapacityCalculator.image_lsb_capacity(cover_var.get())
                    capacity_var.set(f"Capacity: {CapacityCalculator.format_bytes(cap)}")
                else:
                    capacity_var.set("Capacity: ")

            def update_strength(*_):
                _, label = PasswordValidator.check_strength(pwd_var.get())
                strength_var.set(f"Strength: {label}")

            cover_var.trace_add("write", update_capacity)
            pwd_var.trace_add("write", update_strength)

        def _build_image_decode_only(self, parent: ttk.Frame) -> None:
            """Image decode tab (for Reveal Data section)."""
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM)

            decode = ttk.Labelframe(container, text="Decode Image")
            decode.pack(fill=tk.X)

            stego_var = tk.StringVar(master=self.root)
            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_var = tk.StringVar(master=self.root)
            dec_method_var = tk.StringVar(master=self.root, value="lsb")
            dec_prng_var = tk.StringVar(master=self.root)

            self._file_row(
                decode,
                "Stego image",
                stego_var,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")],
                on_change=self._update_image_preview,
            )

            dec_method_row = ttk.Frame(decode)
            dec_method_row.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))
            ttk.Label(dec_method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                dec_method_row,
                textvariable=dec_method_var,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=PADDING_SMALL)
            ttk.Label(dec_method_row, text="PRNG key").pack(side=tk.LEFT, padx=(PADDING_LARGE, 0))
            PlaceholderEntry(dec_method_row, textvariable=dec_prng_var, width=28, placeholder="If PRNG was used").pack(side=tk.LEFT, padx=PADDING_SMALL)

            ttk.Separator(decode, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            pwd_frame = PasswordEntry(decode, textvariable=dec_pwd_var)
            pwd_frame.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            self._save_row(decode, "Output file (optional)", dec_out_var, def_ext=".txt", filetypes=[("All Files", "*.*")])

            ttk.Button(
                decode,
                text="Extract Data",
                style="Primary.TButton",
                width=BUTTON_WIDTH_LARGE,
                command=lambda: self._decode_image(
                    stego_var.get(),
                    dec_pwd_var.get(),
                    dec_out_var.get(),
                    dec_method_var.get(),
                    dec_prng_var.get(),
                ),
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_SMALL, PADDING_MEDIUM))

        def _build_audio_decode_only(self, parent: ttk.Frame) -> None:
            """Audio decode tab."""
            audio_patterns = " ".join([f"*{ext}" for ext in AUDIO_EXT_LIST])
            filetypes = [("Audio files", audio_patterns), ("All Files", "*.*")]
            self._build_decode_only_tab(parent, media_type="audio", label="Audio", filetypes=filetypes)

        def _build_video_decode_only(self, parent: ttk.Frame) -> None:
            """Video decode tab."""
            video_patterns = " ".join([f"*{ext}" for ext in VIDEO_EXT_LIST])
            filetypes = [("Video files", video_patterns), ("All Files", "*.*")]
            self._build_decode_only_tab(parent, media_type="video", label="Video", filetypes=filetypes)

        def _build_pdf_decode_only(self, parent: ttk.Frame) -> None:
            """PDF decode tab."""
            self._build_decode_only_tab(parent, media_type="pdf", label="PDF", filetypes=[("PDF", "*.pdf")])

        def _build_decode_only_tab(self, parent: ttk.Frame, media_type: str, label: str, filetypes: list) -> None:
            """Generic decode-only tab."""
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=PADDING_MEDIUM, pady=PADDING_MEDIUM)

            decode = ttk.Labelframe(container, text=f"Decode {label}")
            decode.pack(fill=tk.X)

            stego_var = tk.StringVar(master=self.root)
            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_var = tk.StringVar(master=self.root)

            preview_func = None
            if media_type == "audio":
                preview_func = self._update_audio_preview
            elif media_type == "video":
                preview_func = self._update_video_preview
            elif media_type == "pdf":
                preview_func = self._update_pdf_preview

            self._file_row(decode, f"{label} file", stego_var, filetypes=filetypes, on_change=preview_func)

            ttk.Separator(decode, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=PADDING_MEDIUM, pady=PADDING_SMALL)

            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=PADDING_MEDIUM)
            pwd_frame = PasswordEntry(decode, textvariable=dec_pwd_var)
            pwd_frame.pack(fill=tk.X, padx=PADDING_MEDIUM, pady=(0, PADDING_SMALL))

            self._save_row(decode, "Output file", dec_out_var, def_ext=".bin", filetypes=[("All Files", "*.*")])

            ttk.Button(
                decode,
                text="Extract Data",
                style="Primary.TButton",
                width=BUTTON_WIDTH_LARGE,
                command=lambda: self._decode_media(media_type, stego_var.get(), dec_pwd_var.get(), dec_out_var.get()),
            ).pack(anchor=tk.W, padx=PADDING_MEDIUM, pady=(PADDING_SMALL, PADDING_MEDIUM))

        def _build_audio_tab(self, parent: ttk.Frame) -> None:
            audio_patterns = " ".join([f"*{ext}" for ext in AUDIO_EXT_LIST])
            filetypes = [("Audio files", audio_patterns), ("All Files", "*.*")]
            self._build_media_tab(parent, media_type="audio", label="Audio", filetypes=filetypes, def_ext=".mp3",
                                  preview_func=self._update_audio_preview)

        def _build_video_tab(self, parent: ttk.Frame) -> None:
            video_patterns = " ".join([f"*{ext}" for ext in VIDEO_EXT_LIST])
            filetypes = [("Video files", video_patterns), ("All Files", "*.*")]
            self._build_media_tab(parent, media_type="video", label="Video", filetypes=filetypes, def_ext=".mp4",
                                  preview_func=self._update_video_preview)

        def _build_video_frames_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text="Encode Video Frame")
            encode.pack(fill=tk.X, pady=(0, 12))

            video_var = tk.StringVar(master=self.root)
            frame_var = tk.IntVar(master=self.root, value=0)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            video_patterns = " ".join([f"*{ext}" for ext in VIDEO_EXT_LIST])
            video_filetypes = [("Video files", video_patterns), ("All Files", "*.*")]
            self._file_row(encode, "Video file", video_var, filetypes=video_filetypes, on_change=self._update_video_preview)
            frame_row = ttk.Frame(encode)
            frame_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(frame_row, text="Frame index").pack(side=tk.LEFT)
            ttk.Spinbox(frame_row, from_=0, to=1_000_000, textvariable=frame_var, width=8).pack(side=tk.LEFT, padx=8)

            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(fill=tk.X, padx=10, pady=(0, 8))
            self._file_row(encode, "Payload file (optional)", payload_file_var, filetypes=[("All Files", "*.*")])

            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))

            method_row = ttk.Frame(encode)
            method_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(method_row, textvariable=method_var, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(method_row, textvariable=prng_var, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Checkbutton(encode, text="Compress payload", variable=compress_var).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=expires_var).pack(fill=tk.X, padx=10, pady=(0, 8))

            self._save_row(encode, "Output video", out_var, def_ext=".mp4", filetypes=video_filetypes)

            ttk.Button(
                encode,
                text="Embed in Frame",
                command=lambda: self._encode_video_frame(
                    video_var.get(),
                    frame_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    method_var.get(),
                    prng_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text="Decode Video Frame")
            decode.pack(fill=tk.X)

            dec_video = tk.StringVar(master=self.root)
            dec_frame = tk.IntVar(master=self.root, value=0)
            dec_pwd = tk.StringVar(master=self.root)
            dec_out = tk.StringVar(master=self.root)
            dec_method = tk.StringVar(master=self.root, value="lsb")
            dec_prng = tk.StringVar(master=self.root)

            self._file_row(decode, "Video file", dec_video, filetypes=video_filetypes, on_change=self._update_video_preview)
            dec_row = ttk.Frame(decode)
            dec_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(dec_row, text="Frame index").pack(side=tk.LEFT)
            ttk.Spinbox(dec_row, from_=0, to=1_000_000, textvariable=dec_frame, width=8).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_row, text="Method").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Combobox(dec_row, textvariable=dec_method, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(dec_row, textvariable=dec_prng, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))
            self._save_row(decode, "Output file", dec_out, def_ext=".bin", filetypes=[("All Files", "*.*")])

            ttk.Button(
                decode,
                text="Extract from Frame",
                command=lambda: self._decode_video_frame(
                    dec_video.get(),
                    dec_frame.get(),
                    dec_pwd.get(),
                    dec_out.get(),
                    dec_method.get(),
                    dec_prng.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_gif_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text="Encode GIF")
            encode.pack(fill=tk.X, pady=(0, 12))

            gif_var = tk.StringVar(master=self.root)
            frame_var = tk.IntVar(master=self.root, value=0)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            self._file_row(encode, "GIF file", gif_var, filetypes=[("GIF", "*.gif")])
            frame_row = ttk.Frame(encode)
            frame_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(frame_row, text="Frame index").pack(side=tk.LEFT)
            ttk.Spinbox(frame_row, from_=0, to=10_000, textvariable=frame_var, width=8).pack(side=tk.LEFT, padx=8)

            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(fill=tk.X, padx=10, pady=(0, 8))
            self._file_row(encode, "Payload file (optional)", payload_file_var, filetypes=[("All Files", "*.*")])

            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))

            method_row = ttk.Frame(encode)
            method_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(method_row, textvariable=method_var, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(method_row, textvariable=prng_var, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Checkbutton(encode, text="Compress payload", variable=compress_var).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=expires_var).pack(fill=tk.X, padx=10, pady=(0, 8))

            self._save_row(encode, "Output GIF", out_var, def_ext=".gif", filetypes=[("GIF", "*.gif")])

            ttk.Button(
                encode,
                text="Embed in Frame",
                command=lambda: self._encode_gif(
                    gif_var.get(),
                    frame_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    method_var.get(),
                    prng_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text="Decode GIF")
            decode.pack(fill=tk.X)

            dec_gif = tk.StringVar(master=self.root)
            dec_frame = tk.IntVar(master=self.root, value=0)
            dec_pwd = tk.StringVar(master=self.root)
            dec_out = tk.StringVar(master=self.root)
            dec_method = tk.StringVar(master=self.root, value="lsb")
            dec_prng = tk.StringVar(master=self.root)

            self._file_row(decode, "GIF file", dec_gif, filetypes=[("GIF", "*.gif")])
            dec_row = ttk.Frame(decode)
            dec_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(dec_row, text="Frame index").pack(side=tk.LEFT)
            ttk.Spinbox(dec_row, from_=0, to=10_000, textvariable=dec_frame, width=8).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_row, text="Method").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Combobox(dec_row, textvariable=dec_method, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(dec_row, textvariable=dec_prng, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))
            self._save_row(decode, "Output file", dec_out, def_ext=".bin", filetypes=[("All Files", "*.*")])

            ttk.Button(
                decode,
                text="Extract from Frame",
                command=lambda: self._decode_gif(
                    dec_gif.get(),
                    dec_frame.get(),
                    dec_pwd.get(),
                    dec_out.get(),
                    dec_method.get(),
                    dec_prng.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_pdf_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text="Encode PDF")
            encode.pack(fill=tk.X, pady=(0, 12))

            pdf_var = tk.StringVar(master=self.root)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            self._file_row(encode, "PDF file", pdf_var, filetypes=[("PDF", "*.pdf")], on_change=self._update_pdf_preview)
            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(fill=tk.X, padx=10, pady=(0, 8))
            self._file_row(encode, "Payload file (optional)", payload_file_var, filetypes=[("All Files", "*.*")])
            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Checkbutton(encode, text="Compress payload", variable=compress_var).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=expires_var).pack(fill=tk.X, padx=10, pady=(0, 8))
            self._save_row(encode, "Output PDF", out_var, def_ext=".pdf", filetypes=[("PDF", "*.pdf")])

            ttk.Button(
                encode,
                text="Embed in PDF",
                command=lambda: self._encode_pdf(
                    pdf_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text="Decode PDF")
            decode.pack(fill=tk.X)

            dec_pdf = tk.StringVar(master=self.root)
            dec_pwd = tk.StringVar(master=self.root)
            dec_out = tk.StringVar(master=self.root)
            self._file_row(decode, "PDF file", dec_pdf, filetypes=[("PDF", "*.pdf")], on_change=self._update_pdf_preview)
            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))
            self._save_row(decode, "Output file (optional)", dec_out, def_ext=".bin", filetypes=[("All Files", "*.*")])

            ttk.Button(
                decode,
                text="Extract from PDF",
                command=lambda: self._decode_pdf(dec_pdf.get(), dec_pwd.get(), dec_out.get()),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_media_tab(self, parent: ttk.Frame, media_type: str, label: str,
                     filetypes: list[tuple[str, str]], def_ext: str,
                     preview_func: Callable[[str], None] | None = None) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            encode = ttk.Labelframe(container, text=f"Encode {label}")
            encode.pack(fill=tk.X, pady=(0, 12))

            input_var = tk.StringVar(master=self.root)
            msg_var = tk.StringVar(master=self.root)
            payload_file_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)
            comment_var = tk.StringVar(master=self.root)
            expires_var = tk.StringVar(master=self.root)

            self._file_row(encode, f"{label} file", input_var, filetypes=filetypes, on_change=preview_func)
            ttk.Label(encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=msg_var).pack(fill=tk.X, padx=10, pady=(0, 8))
            self._file_row(encode, "Payload file (optional)", payload_file_var, filetypes=[("All Files", "*.*")])
            ttk.Label(encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Checkbutton(encode, text="Compress payload", variable=compress_var).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(encode, text="Comment (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=comment_var).pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(encode, text="Expires (YYYY-MM-DD or ISO datetime)").pack(anchor=tk.W, padx=10)
            ttk.Entry(encode, textvariable=expires_var).pack(fill=tk.X, padx=10, pady=(0, 8))
            self._save_row(encode, "Output file", out_var, def_ext=def_ext, filetypes=filetypes)

            ttk.Button(
                encode,
                text="Embed Data",
                command=lambda: self._encode_media(
                    media_type,
                    input_var.get(),
                    msg_var.get(),
                    payload_file_var.get(),
                    pwd_var.get(),
                    out_var.get(),
                    compress_var.get(),
                    comment_var.get(),
                    expires_var.get(),
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            decode = ttk.Labelframe(container, text=f"Decode {label}")
            decode.pack(fill=tk.X)

            stego_var = tk.StringVar(master=self.root)
            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_var = tk.StringVar(master=self.root)
            self._file_row(decode, f"{label} file", stego_var, filetypes=filetypes, on_change=preview_func)
            ttk.Label(decode, text="Password (if needed)").pack(anchor=tk.W, padx=10)
            ttk.Entry(decode, textvariable=dec_pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 8))
            self._save_row(decode, "Output file", dec_out_var, def_ext=".bin", filetypes=[("All Files", "*.*")])

            ttk.Button(
                decode,
                text="Extract Data",
                command=lambda: self._decode_media(media_type, stego_var.get(), dec_pwd_var.get(), dec_out_var.get()),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_tools_tab(self, parent: ttk.Frame) -> None:
            """Analysis & Tools tab with sub-tabs."""
            sub_notebook = ttk.Notebook(parent)
            sub_notebook.pack(fill=tk.BOTH, expand=True, padx=PADDING_SMALL, pady=PADDING_SMALL)

            # Clear default tabs
            for tab_id in list(sub_notebook.tabs()):
                sub_notebook.forget(tab_id)

            tools_frame = ttk.Frame(sub_notebook)
            analysis_frame = ttk.Frame(sub_notebook)

            sub_notebook.add(tools_frame, text="Tools")
            sub_notebook.add(analysis_frame, text="Analysis")

            self._build_tools_only(tools_frame)
            self._build_analyze_tab(analysis_frame)

        def _build_tools_only(self, parent: ttk.Frame) -> None:
            """Just the tools without analysis."""
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            help_box = ttk.Labelframe(container, text="Help")
            help_box.pack(fill=tk.X, pady=(0, 12))
            info = (
                "Use PNG for image steganography, select strong passwords, and test extraction before sharing files. "
                "PRNG methods require a key. Compression can increase capacity at the cost of predictability."
            )
            ttk.Label(help_box, text=info, wraplength=900, justify=tk.LEFT).pack(padx=10, pady=8)

            cap_box = ttk.Labelframe(container, text="Capacity Calculator")
            cap_box.pack(fill=tk.X)

            img_var = tk.StringVar(master=self.root)
            cap_var = tk.StringVar(master=self.root, value="Capacity: ")
            self._file_row(cap_box, "Image file", img_var, filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
            ttk.Label(cap_box, textvariable=cap_var).pack(anchor=tk.W, padx=10, pady=(0, 8))

            def update_cap(*_):
                if img_var.get():
                    cap = CapacityCalculator.image_lsb_capacity(img_var.get())
                    cap_var.set(f"Capacity: {CapacityCalculator.format_bytes(cap)}")
                else:
                    cap_var.set("Capacity: ")

            img_var.trace_add("write", update_cap)

            vault_box = ttk.Labelframe(container, text="Key Vault")
            vault_box.pack(fill=tk.X, pady=(12, 0))

            key_name = tk.StringVar(master=self.root)
            key_value = tk.StringVar(master=self.root)
            master_pwd = tk.StringVar(master=self.root)

            ttk.Label(vault_box, text="Key name").pack(anchor=tk.W, padx=10, pady=(6, 0))
            ttk.Entry(vault_box, textvariable=key_name).pack(fill=tk.X, padx=10)
            ttk.Label(vault_box, text="Key value").pack(anchor=tk.W, padx=10, pady=(6, 0))
            ttk.Entry(vault_box, textvariable=key_value).pack(fill=tk.X, padx=10)
            ttk.Label(vault_box, text="Master password").pack(anchor=tk.W, padx=10, pady=(6, 0))
            ttk.Entry(vault_box, textvariable=master_pwd, show="*").pack(fill=tk.X, padx=10)

            vault_btns = ttk.Frame(vault_box)
            vault_btns.pack(fill=tk.X, padx=10, pady=8)

            def save_key():
                if not key_name.get() or not key_value.get() or not master_pwd.get():
                    messagebox.showerror("Error", "Provide key name, key value, and master password.")
                    return
                try:
                    keys = self._load_vault(master_pwd.get())
                except Exception:
                    keys = {}
                keys[key_name.get()] = key_value.get()
                self._save_vault(master_pwd.get(), keys)
                messagebox.showinfo("Success", "Key saved.")

            def load_key():
                if not key_name.get() or not master_pwd.get():
                    messagebox.showerror("Error", "Provide key name and master password.")
                    return
                keys = self._load_vault(master_pwd.get())
                if key_name.get() not in keys:
                    messagebox.showerror("Error", "Key not found in vault.")
                    return
                value = keys[key_name.get()]
                key_value.set(value)
                self._copy_to_clipboard(value)
                messagebox.showinfo("Success", "Key loaded and copied to clipboard.")

            ttk.Button(vault_btns, text="Save Key", command=save_key).pack(side=tk.LEFT)
            ttk.Button(vault_btns, text="Load Key", command=load_key).pack(side=tk.LEFT, padx=6)

            templates_box = ttk.Labelframe(container, text="Templates")
            templates_box.pack(fill=tk.X, pady=(12, 0))

            template_name = tk.StringVar(master=self.root)
            ttk.Label(templates_box, text="Template name").pack(anchor=tk.W, padx=10, pady=(6, 0))
            ttk.Entry(templates_box, textvariable=template_name).pack(fill=tk.X, padx=10)

            tmpl_btns = ttk.Frame(templates_box)
            tmpl_btns.pack(fill=tk.X, padx=10, pady=8)

            def save_template():
                if not template_name.get():
                    messagebox.showerror("Error", "Provide a template name.")
                    return
                templates = self._load_templates()
                if not hasattr(self, "image_vars"):
                    messagebox.showerror("Error", "Image tab is not initialized.")
                    return
                templates[template_name.get()] = {
                    "method": self.image_vars["method"].get(),
                    "prng_key": self.image_vars["prng_key"].get(),
                    "compress": str(self.image_vars["compress"].get()),
                    "auto_convert": str(self.image_vars["auto_convert"].get()),
                    "watermark": self.image_vars["watermark"].get(),
                    "nest_levels": str(self.image_vars["nest_levels"].get()),
                }
                self._save_templates(templates)
                messagebox.showinfo("Success", "Template saved.")

            def load_template():
                if not template_name.get():
                    messagebox.showerror("Error", "Provide a template name.")
                    return
                templates = self._load_templates()
                if template_name.get() not in templates:
                    messagebox.showerror("Error", "Template not found.")
                    return
                if not hasattr(self, "image_vars"):
                    messagebox.showerror("Error", "Image tab is not initialized.")
                    return
                values = templates[template_name.get()]
                self.image_vars["method"].set(values.get("method", "lsb"))
                self.image_vars["prng_key"].set(values.get("prng_key", ""))
                self.image_vars["compress"].set(values.get("compress", "False") == "True")
                self.image_vars["auto_convert"].set(values.get("auto_convert", "True") == "True")
                self.image_vars["watermark"].set(values.get("watermark", ""))
                try:
                    self.image_vars["nest_levels"].set(int(values.get("nest_levels", "1")))
                except ValueError:
                    self.image_vars["nest_levels"].set(1)
                messagebox.showinfo("Success", "Template loaded into Image tab.")

            ttk.Button(tmpl_btns, text="Save Template", command=save_template).pack(side=tk.LEFT)
            ttk.Button(tmpl_btns, text="Load Template", command=load_template).pack(side=tk.LEFT, padx=6)

            qr_box = ttk.Labelframe(container, text="QR Code Generator")
            qr_box.pack(fill=tk.X, pady=(12, 0))
            qr_text = tk.StringVar(master=self.root)
            qr_out = tk.StringVar(master=self.root)
            ttk.Label(qr_box, text="Text").pack(anchor=tk.W, padx=10, pady=(6, 0))
            ttk.Entry(qr_box, textvariable=qr_text).pack(fill=tk.X, padx=10)
            self._save_row(qr_box, "Output PNG", qr_out, def_ext=".png", filetypes=[("PNG", "*.png")])

            ttk.Button(
                qr_box,
                text="Generate QR",
                command=lambda: self._run_command(
                    ["python", str(Path(__file__).parent.parent / "app.py"), "qr-generate",
                     "--text", qr_text.get(), "--out", qr_out.get()],
                    "QR generate",
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            portable_box = ttk.Labelframe(container, text="Portable Decoder")
            portable_box.pack(fill=tk.X, pady=(12, 0))
            port_in = tk.StringVar(master=self.root)
            port_out = tk.StringVar(master=self.root)
            port_method = tk.StringVar(master=self.root, value="lsb")
            port_prng = tk.StringVar(master=self.root)
            port_pwd = tk.StringVar(master=self.root)
            port_frame = tk.StringVar(master=self.root)

            self._file_row(portable_box, "Stego file", port_in, filetypes=[("All Files", "*.*")])
            self._save_row(portable_box, "Output ZIP", port_out, def_ext=".zip", filetypes=[("ZIP", "*.zip")])
            port_row = ttk.Frame(portable_box)
            port_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(port_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(port_row, textvariable=port_method, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(port_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(port_row, textvariable=port_prng, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Label(portable_box, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(portable_box, textvariable=port_pwd, show="*").pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(portable_box, text="Frame index (GIF/Video frames)").pack(anchor=tk.W, padx=10)
            ttk.Entry(portable_box, textvariable=port_frame).pack(fill=tk.X, padx=10, pady=(0, 8))

            def run_portable():
                cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "portable-decoder",
                       "--input", port_in.get(), "--out", port_out.get()]
                if port_method.get():
                    cmd.extend(["--method", port_method.get()])
                if port_prng.get():
                    cmd.extend(["--prng-key", port_prng.get()])
                if port_pwd.get():
                    cmd.extend(["--password", port_pwd.get()])
                if port_frame.get():
                    cmd.extend(["--frame", port_frame.get()])
                self._run_command(cmd, "Portable decoder")

            ttk.Button(portable_box, text="Create Decoder", command=run_portable).pack(anchor=tk.W, padx=10, pady=(0, 10))

            assoc_box = ttk.Labelframe(container, text="File Association (Windows)")
            assoc_box.pack(fill=tk.X, pady=(12, 0))
            assoc_out = tk.StringVar(master=self.root)
            self._save_row(assoc_box, "Output .reg", assoc_out, def_ext=".reg", filetypes=[("Registry", "*.reg")])
            ttk.Button(
                assoc_box,
                text="Generate .reg",
                command=lambda: self._run_command(
                    ["python", str(Path(__file__).parent.parent / "app.py"), "file-assoc", "--out", assoc_out.get()],
                    "File association",
                ),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            meta_box = ttk.Labelframe(container, text="Metadata Viewer")
            meta_box.pack(fill=tk.X, pady=(12, 0))
            meta_file = tk.StringVar(master=self.root)
            self._file_row(meta_box, "File", meta_file, filetypes=[("All Files", "*.*")])
            meta_text = tk.StringVar(master=self.root, value="")

            def view_meta():
                path = meta_file.get()
                if not path:
                    messagebox.showerror("Error", "Select a file.")
                    return
                info = []
                try:
                    size = Path(path).stat().st_size
                    info.append(f"Size: {CapacityCalculator.format_bytes(size)}")
                except Exception:
                    pass
                ext = Path(path).suffix.lower()
                try:
                    if ext in (".png", ".jpg", ".jpeg", ".gif"):
                        img = Image.open(path)
                        info.append(f"Image: {img.size[0]}x{img.size[1]}")
                        if ext == ".gif":
                            info.append(f"Frames: {sum(1 for _ in ImageSequence.Iterator(img))}")
                    elif ext == ".mp3":
                        tags = ID3(path)
                        info.append(f"MP3 tags: {len(tags.keys())}")
                    elif ext == ".mp4":
                        tags = MP4(path)
                        info.append(f"MP4 tags: {len(tags.keys())}")
                    elif ext == ".pdf":
                        reader = PdfReader(path)
                        info.append(f"Pages: {len(reader.pages)}")
                except Exception as exc:
                    info.append(f"Metadata error: {exc}")
                meta_text.set(" | ".join(info))

            ttk.Button(meta_box, text="View Metadata", command=view_meta).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(meta_box, textvariable=meta_text).pack(anchor=tk.W, padx=10, pady=(0, 8))

            hash_box = ttk.Labelframe(container, text="Data Integrity Check (SHA256)")
            hash_box.pack(fill=tk.X, pady=(12, 0))
            hash_file = tk.StringVar(master=self.root)
            hash_result = tk.StringVar(master=self.root, value="")
            self._file_row(hash_box, "File", hash_file, filetypes=[("All Files", "*.*")])

            def calc_hash():
                path = hash_file.get()
                if not path:
                    messagebox.showerror("Error", "Select a file.")
                    return
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                hash_result.set(h.hexdigest())

            ttk.Button(hash_box, text="Compute Hash", command=calc_hash).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Entry(hash_box, textvariable=hash_result).pack(fill=tk.X, padx=10, pady=(0, 8))

            browser_box = ttk.Labelframe(container, text="File Browser")
            browser_box.pack(fill=tk.BOTH, expand=True, pady=(12, 0))
            dir_var = tk.StringVar(master=self.root, value=str(Path.home()))

            dir_row = ttk.Frame(browser_box)
            dir_row.pack(fill=tk.X, padx=10, pady=(6, 6))
            ttk.Label(dir_row, text="Folder").pack(side=tk.LEFT)
            ttk.Entry(dir_row, textvariable=dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
            ttk.Button(dir_row, text="Browse", command=lambda: dir_var.set(filedialog.askdirectory())).pack(side=tk.LEFT)

            file_list = tk.Listbox(browser_box, height=6)
            file_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

            def refresh_list(*_):
                file_list.delete(0, tk.END)
                try:
                    for name in sorted(os.listdir(dir_var.get())):
                        file_list.insert(tk.END, name)
                except Exception as exc:
                    file_list.insert(tk.END, f"Error: {exc}")

            dir_var.trace_add("write", refresh_list)
            refresh_list()

            gallery_box = ttk.Labelframe(container, text="Gallery Builder")
            gallery_box.pack(fill=tk.X, pady=(12, 0))

            gallery_files: list[str] = []
            gallery_list = tk.Listbox(gallery_box, height=5)
            gallery_list.pack(fill=tk.X, padx=10, pady=6)

            def add_gallery_files():
                paths = filedialog.askopenfilenames(filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
                for p in paths:
                    if p not in gallery_files:
                        gallery_files.append(p)
                        gallery_list.insert(tk.END, p)

            def remove_gallery_files():
                sel = gallery_list.curselection()
                for idx in reversed(sel):
                    gallery_files.pop(idx)
                    gallery_list.delete(idx)

            gallery_btns = ttk.Frame(gallery_box)
            gallery_btns.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Button(gallery_btns, text="Add Images", command=add_gallery_files).pack(side=tk.LEFT)
            ttk.Button(gallery_btns, text="Remove Selected", command=remove_gallery_files).pack(side=tk.LEFT, padx=6)

            gallery_out = tk.StringVar(master=self.root)
            self._save_row(gallery_box, "Output ZIP", gallery_out, def_ext=".zip", filetypes=[("ZIP", "*.zip")])

            def build_gallery():
                if not gallery_files:
                    messagebox.showerror("Error", "Add at least one image.")
                    return
                if not gallery_out.get():
                    messagebox.showerror("Error", "Select an output zip.")
                    return
                with zipfile.ZipFile(gallery_out.get(), "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for p in gallery_files:
                        zf.write(p, arcname=Path(p).name)
                messagebox.showinfo("Success", "Gallery zip created. Embed it as a payload file.")

            ttk.Button(gallery_box, text="Create Gallery ZIP", command=build_gallery).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_batch_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            batch_encode = ttk.Labelframe(container, text="Batch Encode Images")
            batch_encode.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

            files_var = []
            listbox = tk.Listbox(batch_encode, height=6)
            listbox.pack(fill=tk.X, padx=10, pady=6)

            def add_files():
                paths = filedialog.askopenfilenames(filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
                for p in paths:
                    if p not in files_var:
                        files_var.append(p)
                        listbox.insert(tk.END, p)

            def remove_selected():
                sel = listbox.curselection()
                for idx in reversed(sel):
                    files_var.pop(idx)
                    listbox.delete(idx)

            btn_row = ttk.Frame(batch_encode)
            btn_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Button(btn_row, text="Add Files", command=add_files).pack(side=tk.LEFT)
            ttk.Button(btn_row, text="Remove Selected", command=remove_selected).pack(side=tk.LEFT, padx=6)

            msg_var = tk.StringVar(master=self.root)
            pwd_var = tk.StringVar(master=self.root)
            out_dir_var = tk.StringVar(master=self.root)
            method_var = tk.StringVar(master=self.root, value="lsb")
            prng_var = tk.StringVar(master=self.root)
            compress_var = tk.BooleanVar(master=self.root, value=False)

            ttk.Label(batch_encode, text="Message").pack(anchor=tk.W, padx=10)
            ttk.Entry(batch_encode, textvariable=msg_var).pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(batch_encode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(batch_encode, textvariable=pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 6))

            method_row = ttk.Frame(batch_encode)
            method_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(method_row, textvariable=method_var, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(method_row, textvariable=prng_var, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Checkbutton(batch_encode, text="Compress payload", variable=compress_var).pack(anchor=tk.W, padx=10)

            out_row = ttk.Frame(batch_encode)
            out_row.pack(fill=tk.X, padx=10, pady=(6, 8))
            ttk.Label(out_row, text="Output folder").pack(side=tk.LEFT)
            ttk.Entry(out_row, textvariable=out_dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
            ttk.Button(out_row, text="Browse", command=lambda: out_dir_var.set(filedialog.askdirectory())).pack(side=tk.LEFT)

            ttk.Button(
                batch_encode,
                text="Run Batch Encode",
                command=lambda: self._batch_encode_images(files_var, msg_var.get(), pwd_var.get(), out_dir_var.get(),
                                                          method_var.get(), prng_var.get(), compress_var.get()),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            batch_decode = ttk.Labelframe(container, text="Batch Decode Images")
            batch_decode.pack(fill=tk.BOTH, expand=True)

            dec_files = []
            dec_list = tk.Listbox(batch_decode, height=6)
            dec_list.pack(fill=tk.X, padx=10, pady=6)

            def add_dec_files():
                paths = filedialog.askopenfilenames(filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
                for p in paths:
                    if p not in dec_files:
                        dec_files.append(p)
                        dec_list.insert(tk.END, p)

            def remove_dec_selected():
                sel = dec_list.curselection()
                for idx in reversed(sel):
                    dec_files.pop(idx)
                    dec_list.delete(idx)

            dec_btn_row = ttk.Frame(batch_decode)
            dec_btn_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Button(dec_btn_row, text="Add Files", command=add_dec_files).pack(side=tk.LEFT)
            ttk.Button(dec_btn_row, text="Remove Selected", command=remove_dec_selected).pack(side=tk.LEFT, padx=6)

            dec_pwd_var = tk.StringVar(master=self.root)
            dec_out_dir = tk.StringVar(master=self.root)
            dec_method = tk.StringVar(master=self.root, value="lsb")
            dec_prng = tk.StringVar(master=self.root)

            ttk.Label(batch_decode, text="Password (optional)").pack(anchor=tk.W, padx=10)
            ttk.Entry(batch_decode, textvariable=dec_pwd_var, show="*").pack(fill=tk.X, padx=10, pady=(0, 6))

            dec_method_row = ttk.Frame(batch_decode)
            dec_method_row.pack(fill=tk.X, padx=10, pady=(0, 6))
            ttk.Label(dec_method_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(dec_method_row, textvariable=dec_method, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(dec_method_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(dec_method_row, textvariable=dec_prng, width=28).pack(side=tk.LEFT, padx=8)

            out_dec_row = ttk.Frame(batch_decode)
            out_dec_row.pack(fill=tk.X, padx=10, pady=(6, 8))
            ttk.Label(out_dec_row, text="Output folder").pack(side=tk.LEFT)
            ttk.Entry(out_dec_row, textvariable=dec_out_dir).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
            ttk.Button(out_dec_row, text="Browse", command=lambda: dec_out_dir.set(filedialog.askdirectory())).pack(side=tk.LEFT)

            ttk.Button(
                batch_decode,
                text="Run Batch Decode",
                command=lambda: self._batch_decode_images(dec_files, dec_pwd_var.get(), dec_out_dir.get(),
                                                          dec_method.get(), dec_prng.get()),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

        def _build_analyze_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            compare = ttk.Labelframe(container, text="Image Comparison")
            compare.pack(fill=tk.X)

            original_var = tk.StringVar(master=self.root)
            stego_var = tk.StringVar(master=self.root)
            diff_out = tk.StringVar(master=self.root)
            result_var = tk.StringVar(master=self.root, value="")

            self._file_row(compare, "Original image", original_var, filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
            self._file_row(compare, "Stego image", stego_var, filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
            self._save_row(compare, "Diff output (optional)", diff_out, def_ext=".png", filetypes=[("PNG", "*.png")])

            ttk.Button(
                compare,
                text="Analyze",
                command=lambda: self._analyze_images(original_var.get(), stego_var.get(), diff_out.get(), result_var),
            ).pack(anchor=tk.W, padx=10, pady=(0, 10))

            ttk.Label(compare, textvariable=result_var).pack(anchor=tk.W, padx=10, pady=(0, 10))

            detect = ttk.Labelframe(container, text="Stego Detection")
            detect.pack(fill=tk.X, pady=(12, 0))

            detect_image = tk.StringVar(master=self.root)
            detect_method = tk.StringVar(master=self.root, value="lsb")
            detect_prng = tk.StringVar(master=self.root)
            detect_result = tk.StringVar(master=self.root, value="")

            self._file_row(detect, "Image", detect_image, filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])

            detect_row = ttk.Frame(detect)
            detect_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(detect_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(
                detect_row,
                textvariable=detect_method,
                state="readonly",
                values=["lsb", "lsb-prng", "lsb-match-prng"],
                width=18,
            ).pack(side=tk.LEFT, padx=8)
            ttk.Label(detect_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(detect_row, textvariable=detect_prng, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Button(
                detect,
                text="Detect",
                command=lambda: self._detect_image(detect_image.get(), detect_method.get(), detect_prng.get(), detect_result),
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))

            ttk.Label(detect, textvariable=detect_result).pack(anchor=tk.W, padx=10, pady=(0, 8))

            security = ttk.Labelframe(container, text="Security Analysis")
            security.pack(fill=tk.X, pady=(12, 0))

            sec_image = tk.StringVar(master=self.root)
            sec_method = tk.StringVar(master=self.root, value="lsb")
            sec_prng = tk.StringVar(master=self.root)
            sec_result = tk.StringVar(master=self.root, value="")

            self._file_row(security, "Image", sec_image, filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")])
            sec_row = ttk.Frame(security)
            sec_row.pack(fill=tk.X, padx=10, pady=(0, 8))
            ttk.Label(sec_row, text="Method").pack(side=tk.LEFT)
            ttk.Combobox(sec_row, textvariable=sec_method, state="readonly",
                         values=["lsb", "lsb-prng", "lsb-match-prng"], width=18).pack(side=tk.LEFT, padx=8)
            ttk.Label(sec_row, text="PRNG key").pack(side=tk.LEFT, padx=(16, 0))
            ttk.Entry(sec_row, textvariable=sec_prng, width=28).pack(side=tk.LEFT, padx=8)

            ttk.Button(
                security,
                text="Rate Security",
                command=lambda: self._security_analysis(sec_image.get(), sec_method.get(), sec_prng.get(), sec_result),
            ).pack(anchor=tk.W, padx=10, pady=(0, 8))
            ttk.Label(security, textvariable=sec_result).pack(anchor=tk.W, padx=10, pady=(0, 8))

        def _update_image_preview(self, path: str) -> None:
            if not path:
                self.preview_image.configure(text="No image selected", image="")
                self._preview_image_ref = None
                return
            try:
                img = Image.open(path)
                img.thumbnail((260, 200))
                tk_img = ImageTk.PhotoImage(img)
                self.preview_image.configure(image=tk_img, text="")
                self._preview_image_ref = tk_img
            except Exception:
                self.preview_image.configure(text="Preview unavailable", image="")
                self._preview_image_ref = None

        def _update_audio_preview(self, path: str) -> None:
            if not path:
                self.preview_audio.configure(text="No audio selected")
                return
            try:
                audio = MutagenFile(path)
                length = getattr(getattr(audio, "info", None), "length", None) if audio else None
                bitrate = getattr(getattr(audio, "info", None), "bitrate", None) if audio else None
                duration = f"{length:.1f}s" if length else "Unknown length"
                rate = f"{bitrate // 1000} kbps" if bitrate else ""
                name = Path(path).name
                info = f"{name}\n{duration} {rate}".strip()
                self.preview_audio.configure(text=info)
            except Exception:
                self.preview_audio.configure(text="Preview unavailable")

        def _update_video_preview(self, path: str) -> None:
            if not path:
                self.preview_video.configure(text="No video selected", image="")
                self._preview_video_ref = None
                return
            try:
                reader = imageio.get_reader(path)
                frame = reader.get_data(0)
                reader.close()
                img = Image.fromarray(frame)
                img.thumbnail((260, 160))
                tk_img = ImageTk.PhotoImage(img)
                self.preview_video.configure(image=tk_img, text="")
                self._preview_video_ref = tk_img
            except Exception:
                self.preview_video.configure(text="Preview unavailable", image="")
                self._preview_video_ref = None

        def _update_pdf_preview(self, path: str) -> None:
            if not path:
                self.preview_pdf.configure(text="No PDF selected")
                return
            try:
                reader = PdfReader(path)
                pages = len(reader.pages)
                snippet = ""
                if pages:
                    snippet = reader.pages[0].extract_text() or ""
                    snippet = " ".join(snippet.split())[:280]
                name = Path(path).name
                info = f"{name}\nPages: {pages}"
                if snippet:
                    info += f"\n{snippet}"
                self.preview_pdf.configure(text=info)
            except Exception:
                self.preview_pdf.configure(text="Preview unavailable")

        def _build_history_tab(self, parent: ttk.Frame) -> None:
            container = ttk.Frame(parent)
            container.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            self.history_view = ttk.Treeview(container, columns=("time", "action", "status", "details"), show="headings")
            for col, width in [("time", 160), ("action", 160), ("status", 100), ("details", 700)]:
                self.history_view.heading(col, text=col.title())
                self.history_view.column(col, width=width, anchor=tk.W)
            self.history_view.pack(fill=tk.BOTH, expand=True)

            btn_row = ttk.Frame(container)
            btn_row.pack(fill=tk.X, pady=8)
            ttk.Button(btn_row, text="Clear History", command=self._clear_history).pack(side=tk.LEFT)

        def _file_row(self, parent: ttk.Frame, label: str, var: tk.StringVar, filetypes=None,
                      on_change=None) -> None:
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, padx=10, pady=6)
            ttk.Label(row, text=label).pack(side=tk.LEFT)
            entry = ttk.Entry(row, textvariable=var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
            ttk.Button(row, text="Browse", command=lambda: self._pick_file(var, filetypes)).pack(side=tk.LEFT)

            if on_change is not None:
                var.trace_add("write", lambda *_: on_change(var.get()))

            if dnd_available:
                entry.drop_target_register(DND_FILES)
                entry.dnd_bind("<<Drop>>", lambda e: self._handle_drop(e, var))

        def _save_row(self, parent: ttk.Frame, label: str, var: tk.StringVar, def_ext: str, filetypes=None) -> None:
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, padx=10, pady=6)
            ttk.Label(row, text=label).pack(side=tk.LEFT)
            ttk.Entry(row, textvariable=var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
            ttk.Button(
                row,
                text="Save As",
                command=lambda: self._save_file(var, def_ext, filetypes),
            ).pack(side=tk.LEFT)

        def _pick_file(self, var: tk.StringVar, filetypes=None) -> None:
            path = filedialog.askopenfilename(filetypes=filetypes or [("All Files", "*.*")])
            if path:
                var.set(path)

        def _save_file(self, var: tk.StringVar, def_ext: str, filetypes=None) -> None:
            path = filedialog.asksaveasfilename(defaultextension=def_ext, filetypes=filetypes or [("All Files", "*.*")])
            if path:
                var.set(path)

        def _handle_drop(self, event, var: tk.StringVar) -> None:
            files = normalize_dnd_files(event.data, event.widget)
            if files:
                var.set(files[0])

        def _paste_clipboard(self) -> str:
            try:
                return self.root.clipboard_get()
            except Exception:
                return ""

        def _set_status(self, text: str) -> None:
            self.status.set_status(text)

        def _add_history(self, action: str, status: str, details: str) -> None:
            item = HistoryItem(time.strftime("%Y-%m-%d %H:%M:%S"), action, status, details)
            self.history.append(item)
            self.history_view.insert("", tk.END, values=(item.timestamp, item.action, item.status, item.details))

        def _clear_history(self) -> None:
            self.history.clear()
            for row in self.history_view.get_children():
                self.history_view.delete(row)

        def _vault_path(self) -> Path:
            return Path.home() / ".steg_keys.json"

        def _load_vault(self, master_password: str) -> dict[str, str]:
            path = self._vault_path()
            if not path.exists():
                return {}
            data = json.loads(path.read_text(encoding="utf-8"))
            salt = base64.b64decode(data["salt"])
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])
            key = derive_key(master_password, salt)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, b"vault")
            return json.loads(plaintext.decode("utf-8"))

        def _save_vault(self, master_password: str, payload: dict[str, str]) -> None:
            path = self._vault_path()
            salt = os.urandom(DEFAULT_SALT_LEN)
            nonce = os.urandom(DEFAULT_NONCE_LEN)
            key = derive_key(master_password, salt)
            plaintext = json.dumps(payload).encode("utf-8")
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"vault")
            data = {
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        def _templates_path(self) -> Path:
            return Path.home() / ".steg_templates.json"

        def _load_templates(self) -> dict[str, dict[str, str]]:
            path = self._templates_path()
            if not path.exists():
                return {}
            return json.loads(path.read_text(encoding="utf-8"))

        def _save_templates(self, templates: dict[str, dict[str, str]]) -> None:
            path = self._templates_path()
            path.write_text(json.dumps(templates, indent=2), encoding="utf-8")

        def _run_command(self, cmd: list[str], action: str, on_success: Optional[Callable[[str], None]] = None) -> None:
            def task():
                self.root.after(0, lambda: self._set_status(f"{action} in progress"))
                self.root.after(0, self.status.start)
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    stdout = result.stdout.strip()
                    stderr = result.stderr.strip()
                    if result.returncode == 0:
                        self.root.after(0, self.status.stop)
                        self.root.after(0, lambda: self._set_status(f"{action} complete"))
                        self.root.after(0, lambda: self._add_history(action, "Success", stdout or "OK"))
                        if on_success:
                            self.root.after(0, lambda: on_success(stdout))
                    else:
                        msg = stderr or stdout or "Operation failed"
                        self.root.after(0, self.status.stop)
                        self.root.after(0, lambda: self._set_status(f"{action} failed"))
                        self.root.after(0, lambda: self._add_history(action, "Failed", msg[:200]))
                        self.root.after(0, lambda: messagebox.showerror("Error", msg))
                except Exception as exc:
                    self.root.after(0, self.status.stop)
                    self.root.after(0, lambda: self._set_status(f"{action} error"))
                    self.root.after(0, lambda: self._add_history(action, "Error", str(exc)))
                    self.root.after(0, lambda e=exc: messagebox.showerror("Error", str(e)))

            threading.Thread(target=task, daemon=True).start()

        def _encode_image(self, cover: str, message: str, payload_file: str, password: str, output: str,
                  method: str, prng_key: str, compress: bool, auto_convert: bool,
                  watermark_text: str, nest_levels: int, comment: str, expires: str) -> None:
            if not cover:
                messagebox.showerror("Error", "Select a cover image.")
                return
            if not message and not payload_file:
                messagebox.showerror("Error", "Enter a message or select a payload file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return
            if Path(output).suffix.lower() != ".png":
                messagebox.showerror("Error", "Output file must be PNG for image encoding.")
                return

            cover_path = cover
            temp_path = None
            if auto_convert and Path(cover).suffix.lower() != ".png":
                try:
                    image = Image.open(cover).convert("RGB")
                    temp_fd, temp_path = tempfile.mkstemp(suffix=".png")
                    os.close(temp_fd)
                    image.save(temp_path, format="PNG")
                    cover_path = temp_path
                except Exception as exc:
                    messagebox.showerror("Error", f"Could not convert image: {exc}")
                    return

            def build_cmd(input_img: str, out_img: str) -> list[str]:
                cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "encode",
                       "--image", input_img, "--out", out_img, "--method", method]
                if payload_file:
                    cmd.extend(["--in-file", payload_file])
                else:
                    cmd.extend(["--message", message])
                if password:
                    cmd.extend(["--password", password])
                if prng_key:
                    cmd.extend(["--prng-key", prng_key])
                if compress:
                    cmd.append("--compress")
                if comment:
                    cmd.extend(["--comment", comment])
                if expires:
                    cmd.extend(["--expires", expires])
                return cmd

            if nest_levels < 1:
                nest_levels = 1

            def run_nested():
                current_input = cover_path
                temp_files = []
                try:
                    for level in range(1, nest_levels + 1):
                        if level == nest_levels:
                            out_path = output
                        else:
                            fd, tmp = tempfile.mkstemp(suffix=".png")
                            os.close(fd)
                            temp_files.append(tmp)
                            out_path = tmp
                        cmd = build_cmd(current_input, out_path)
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                        if result.returncode != 0:
                            raise RuntimeError(result.stderr or result.stdout or "Nested encode failed")
                        current_input = out_path

                    if watermark_text:
                        try:
                            image = Image.open(output).convert("RGBA")
                            overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
                            draw = ImageDraw.Draw(overlay)
                            bbox = draw.textbbox((0, 0), watermark_text)
                            text_width = bbox[2] - bbox[0]
                            margin = 10
                            x = max(margin, image.size[0] - text_width - margin)
                            y = image.size[1] - 24 - margin
                            draw.text((x, y), watermark_text, fill=(255, 255, 255, 96))
                            combined = Image.alpha_composite(image, overlay).convert("RGB")
                            combined.save(output)
                        except Exception:
                            pass

                    if temp_path:
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass
                    for tmp in temp_files:
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass

                    self.root.after(0, self.status.stop)
                    self.root.after(0, lambda: self._set_status("Image encode complete"))
                    self.root.after(0, lambda: self._add_history("Image encode", "Success", f"Nested levels: {nest_levels}"))
                except Exception as exc:
                    self.root.after(0, self.status.stop)
                    self.root.after(0, lambda: self._set_status("Image encode failed"))
                    self.root.after(0, lambda: self._add_history("Image encode", "Failed", str(exc)))
                    self.root.after(0, lambda e=exc: messagebox.showerror("Error", str(e)))

            self.root.after(0, lambda: self._set_status("Image encode in progress"))
            self.root.after(0, self.status.start)
            threading.Thread(target=run_nested, daemon=True).start()

        def _decode_image(self, stego: str, password: str, output: str, method: str, prng_key: str) -> None:
            if not stego:
                messagebox.showerror("Error", "Select a stego image.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "decode",
                   "--image", stego, "--method", method]
            if password:
                cmd.extend(["--password", password])
            if prng_key:
                cmd.extend(["--prng-key", prng_key])
            if output:
                cmd.extend(["--out", output])

            def on_success(stdout: str):
                if output:
                    messagebox.showinfo("Success", f"Decoded output saved to {output}")
                    return
                self._show_text_output(stdout or "(No text output)")

            self._run_command(cmd, "Image decode", on_success)

        def _encode_media(self, media_type: str, input_path: str, message: str, payload_file: str,
                  password: str, output: str, compress: bool, comment: str, expires: str) -> None:
            if not input_path:
                messagebox.showerror("Error", f"Select a {media_type.upper()} file.")
                return
            if not message and not payload_file:
                messagebox.showerror("Error", "Enter a message or select a payload file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), f"{media_type}-encode",
                   f"--{media_type}", input_path, "--out", output]
            if payload_file:
                cmd.extend(["--in-file", payload_file])
            else:
                cmd.extend(["--message", message])
            if password:
                cmd.extend(["--password", password])
            if compress:
                cmd.append("--compress")
            if comment:
                cmd.extend(["--comment", comment])
            if expires:
                cmd.extend(["--expires", expires])

            self._run_command(cmd, f"{media_type.upper()} encode")

        def _decode_media(self, media_type: str, input_path: str, password: str, output: str) -> None:
            if not input_path:
                messagebox.showerror("Error", f"Select a {media_type.upper()} file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output file.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), f"{media_type}-decode",
                   f"--{media_type}", input_path, "--out", output]
            if password:
                cmd.extend(["--password", password])

            self._run_command(cmd, f"{media_type.upper()} decode")

        def _encode_pdf(self, pdf_path: str, message: str, payload_file: str, password: str,
                        output: str, compress: bool, comment: str, expires: str) -> None:
            if not pdf_path:
                messagebox.showerror("Error", "Select a PDF file.")
                return
            if not message and not payload_file:
                messagebox.showerror("Error", "Enter a message or select a payload file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output PDF.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "pdf-encode",
                   "--pdf", pdf_path, "--out", output]
            if payload_file:
                cmd.extend(["--in-file", payload_file])
            else:
                cmd.extend(["--message", message])
            if password:
                cmd.extend(["--password", password])
            if compress:
                cmd.append("--compress")
            if comment:
                cmd.extend(["--comment", comment])
            if expires:
                cmd.extend(["--expires", expires])

            self._run_command(cmd, "PDF encode")

        def _decode_pdf(self, pdf_path: str, password: str, output: str) -> None:
            if not pdf_path:
                messagebox.showerror("Error", "Select a PDF file.")
                return
            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "pdf-decode", "--pdf", pdf_path]
            if output:
                cmd.extend(["--out", output])
            if password:
                cmd.extend(["--password", password])

            def on_success(stdout: str):
                if output:
                    messagebox.showinfo("Success", f"Decoded output saved to {output}")
                else:
                    self._show_text_output(stdout or "(No text output)")

            self._run_command(cmd, "PDF decode", on_success)

        def _encode_gif(self, gif_path: str, frame_index: int, message: str, payload_file: str,
                        password: str, output: str, method: str, prng_key: str,
                        compress: bool, comment: str, expires: str) -> None:
            if not gif_path:
                messagebox.showerror("Error", "Select a GIF file.")
                return
            if not message and not payload_file:
                messagebox.showerror("Error", "Enter a message or select a payload file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output GIF.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "gif-encode",
                   "--gif", gif_path, "--out", output, "--frame", str(frame_index), "--method", method]
            if payload_file:
                cmd.extend(["--in-file", payload_file])
            else:
                cmd.extend(["--message", message])
            if password:
                cmd.extend(["--password", password])
            if prng_key:
                cmd.extend(["--prng-key", prng_key])
            if compress:
                cmd.append("--compress")
            if comment:
                cmd.extend(["--comment", comment])
            if expires:
                cmd.extend(["--expires", expires])

            self._run_command(cmd, "GIF encode")

        def _decode_gif(self, gif_path: str, frame_index: int, password: str, output: str,
                        method: str, prng_key: str) -> None:
            if not gif_path:
                messagebox.showerror("Error", "Select a GIF file.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "gif-decode",
                   "--gif", gif_path, "--frame", str(frame_index), "--method", method]
            if output:
                cmd.extend(["--out", output])
            if password:
                cmd.extend(["--password", password])
            if prng_key:
                cmd.extend(["--prng-key", prng_key])

            def on_success(stdout: str):
                if output:
                    messagebox.showinfo("Success", f"Decoded output saved to {output}")
                else:
                    self._show_text_output(stdout or "(No text output)")

            self._run_command(cmd, "GIF decode", on_success)

        def _encode_video_frame(self, video_path: str, frame_index: int, message: str, payload_file: str,
                                password: str, output: str, method: str, prng_key: str,
                                compress: bool, comment: str, expires: str) -> None:
            if not video_path:
                messagebox.showerror("Error", "Select a video file.")
                return
            if not message and not payload_file:
                messagebox.showerror("Error", "Enter a message or select a payload file.")
                return
            if not output:
                messagebox.showerror("Error", "Select an output video.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "video-frame-encode",
                   "--video", video_path, "--out", output, "--frame", str(frame_index), "--method", method]
            if payload_file:
                cmd.extend(["--in-file", payload_file])
            else:
                cmd.extend(["--message", message])
            if password:
                cmd.extend(["--password", password])
            if prng_key:
                cmd.extend(["--prng-key", prng_key])
            if compress:
                cmd.append("--compress")
            if comment:
                cmd.extend(["--comment", comment])
            if expires:
                cmd.extend(["--expires", expires])

            self._run_command(cmd, "Video frame encode")

        def _decode_video_frame(self, video_path: str, frame_index: int, password: str, output: str,
                                method: str, prng_key: str) -> None:
            if not video_path:
                messagebox.showerror("Error", "Select a video file.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "video-frame-decode",
                   "--video", video_path, "--frame", str(frame_index), "--method", method]
            if output:
                cmd.extend(["--out", output])
            if password:
                cmd.extend(["--password", password])
            if prng_key:
                cmd.extend(["--prng-key", prng_key])

            def on_success(stdout: str):
                if output:
                    messagebox.showinfo("Success", f"Decoded output saved to {output}")
                else:
                    self._show_text_output(stdout or "(No text output)")

            self._run_command(cmd, "Video frame decode", on_success)

        def _batch_encode_images(self, files: list[str], message: str, password: str, output_dir: str,
                                 method: str, prng_key: str, compress: bool) -> None:
            if not files:
                messagebox.showerror("Error", "Add at least one image file.")
                return
            if not message:
                messagebox.showerror("Error", "Enter a message to embed.")
                return
            if not output_dir:
                messagebox.showerror("Error", "Select an output folder.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            def task():
                self.root.after(0, self.status.start)
                self.root.after(0, lambda: self._set_status("Batch encode in progress"))
                for idx, path in enumerate(files, start=1):
                    out_path = Path(output_dir) / f"{Path(path).stem}_stego.png"
                    cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "encode",
                           "--image", path, "--out", str(out_path), "--message", message,
                           "--method", method]
                    if password:
                        cmd.extend(["--password", password])
                    if prng_key:
                        cmd.extend(["--prng-key", prng_key])
                    if compress:
                        cmd.append("--compress")

                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        self.root.after(0, lambda m=result.stderr: messagebox.showerror("Error", m))
                        self.root.after(0, self.status.stop)
                        self.root.after(0, lambda: self._set_status("Batch encode failed"))
                        return
                    self.root.after(0, lambda: self._set_status(f"Batch encode {idx}/{len(files)}"))

                self.root.after(0, self.status.stop)
                self.root.after(0, lambda: self._set_status("Batch encode complete"))
                self.root.after(0, lambda: self._add_history("Batch encode", "Success", f"{len(files)} files"))

            threading.Thread(target=task, daemon=True).start()

        def _batch_decode_images(self, files: list[str], password: str, output_dir: str,
                                 method: str, prng_key: str) -> None:
            if not files:
                messagebox.showerror("Error", "Add at least one image file.")
                return
            if not output_dir:
                messagebox.showerror("Error", "Select an output folder.")
                return
            if method in ("lsb-prng", "lsb-match-prng") and not prng_key:
                messagebox.showerror("Error", "PRNG key is required for the selected method.")
                return

            def task():
                self.root.after(0, self.status.start)
                self.root.after(0, lambda: self._set_status("Batch decode in progress"))
                for idx, path in enumerate(files, start=1):
                    out_path = Path(output_dir) / f"{Path(path).stem}_decoded.bin"
                    cmd = ["python", str(Path(__file__).parent.parent / "app.py"), "decode",
                           "--image", path, "--out", str(out_path), "--method", method]
                    if password:
                        cmd.extend(["--password", password])
                    if prng_key:
                        cmd.extend(["--prng-key", prng_key])

                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        self.root.after(0, lambda m=result.stderr: messagebox.showerror("Error", m))
                        self.root.after(0, self.status.stop)
                        self.root.after(0, lambda: self._set_status("Batch decode failed"))
                        return
                    self.root.after(0, lambda: self._set_status(f"Batch decode {idx}/{len(files)}"))

                self.root.after(0, self.status.stop)
                self.root.after(0, lambda: self._set_status("Batch decode complete"))
                self.root.after(0, lambda: self._add_history("Batch decode", "Success", f"{len(files)} files"))

            threading.Thread(target=task, daemon=True).start()

        def _analyze_images(self, original: str, stego: str, diff_out: str, result_var: tk.StringVar) -> None:
            if not original or not stego:
                messagebox.showerror("Error", "Select both original and stego images.")
                return
            try:
                img_a = Image.open(original).convert("RGB")
                img_b = Image.open(stego).convert("RGB")
                if img_a.size != img_b.size:
                    messagebox.showerror("Error", "Images must be the same size for comparison.")
                    return
                diff = ImageChops.difference(img_a, img_b)
                psnr = compute_psnr(img_a, img_b)
                if diff_out:
                    diff.save(diff_out)
                result = f"PSNR: {psnr:.2f} dB"
                if diff_out:
                    result += f" | Diff saved: {diff_out}"
                result_var.set(result)
                self._add_history("Analyze", "Success", result)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def _detect_image(self, image_path: str, method: str, prng_key: str, result_var: tk.StringVar) -> None:
            if not image_path:
                messagebox.showerror("Error", "Select an image.")
                return
            try:
                image = load_image(image_path)
                channels_len = len(flatten_channels(image))
                if method == "lsb":
                    all_bits = extract_bits(image, channels_len)
                elif method in ("lsb-prng", "lsb-match-prng"):
                    if not prng_key:
                        messagebox.showerror("Error", "PRNG key required for PRNG methods.")
                        return
                    rng = make_rng(prng_key)
                    all_bits = extract_bits_prng(image, channels_len, rng)
                else:
                    raise ValueError("Unknown method")

                def read_bytes_from_bits(num_bytes: int) -> bytes:
                    bits = all_bits[: num_bytes * 8]
                    if len(bits) < num_bytes * 8:
                        return b""
                    return bits_to_bytes(bits)

                header_prefix = read_bytes_from_bits(12)
                if len(header_prefix) < 12:
                    result_var.set("No stego header detected")
                    return
                try:
                    salt_len = header_prefix[6]
                    nonce_len = header_prefix[7]
                    extra_len = salt_len + nonce_len
                    if extra_len:
                        extra_bits = all_bits[12 * 8: (12 + extra_len) * 8]
                        extra_header = bits_to_bytes(extra_bits)
                    else:
                        extra_header = b""
                    header = parse_header(header_prefix + extra_header)
                except Exception:
                    result_var.set("No stego header detected")
                    return

                flags = []
                if header.flags & FLAG_ENCRYPTED:
                    flags.append("Encrypted")
                if header.flags & FLAG_PRNG:
                    flags.append("PRNG")
                if header.flags & FLAG_LSB_MATCH:
                    flags.append("LSB-match")
                if header.flags & FLAG_COMPRESSED:
                    flags.append("Compressed")
                payload = "Image" if (header.flags & FLAG_PAYLOAD_IMAGE) else "Text/File"
                result = f"Stego detected | Payload: {payload} | Flags: {', '.join(flags) or 'None'}"
                result_var.set(result)
                self._add_history("Detect", "Success", result)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def _security_analysis(self, image_path: str, method: str, prng_key: str, result_var: tk.StringVar) -> None:
            if not image_path:
                messagebox.showerror("Error", "Select an image.")
                return
            try:
                image = load_image(image_path)
                stego_data = extract_stego_data_from_image(image, method, prng_key)
                flags, _plaintext, _meta = parse_stego_payload(stego_data, password=None)
                score = 0
                if flags & FLAG_ENCRYPTED:
                    score += 2
                if flags & FLAG_PRNG:
                    score += 2
                if flags & FLAG_LSB_MATCH:
                    score += 1
                if flags & FLAG_COMPRESSED:
                    score += 1
                rating = "Low"
                if score >= 4:
                    rating = "High"
                elif score >= 2:
                    rating = "Medium"
                result = f"Security rating: {rating} (score {score})"
                result_var.set(result)
                self._add_history("Security analysis", "Success", result)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def _show_text_output(self, text: str) -> None:
            win = tk.Toplevel(self.root)
            win.title("Decoded Text")
            win.geometry("700x400")

            # Apply theme based on mode
            if self._detect_dark_mode():
                win.configure(bg="#2b2d31")
                txt = tk.Text(win, wrap=tk.WORD, bg="#1e1f22", fg="#dcddde",
                            insertbackground="#dcddde", borderwidth=0, padx=8, pady=8)
            else:
                win.configure(bg="SystemButtonFace")
                txt = tk.Text(win, wrap=tk.WORD, bg="white", fg="black",
                            insertbackground="black", padx=8, pady=8)
            txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
            txt.insert(tk.END, text)
            txt.config(state=tk.DISABLED)

            btn_row = ttk.Frame(win)
            btn_row.pack(fill=tk.X, padx=8, pady=(0, 8))
            ttk.Button(btn_row, text="Copy to Clipboard", command=lambda: self._copy_to_clipboard(text)).pack(side=tk.LEFT)

        def _copy_to_clipboard(self, text: str) -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

    # Create root window
    # Note: TkinterDnD creates an extra "tk" window on macOS, so we disable it there
    # Users on macOS can still use Browse buttons for file selection
    if sys.platform == "darwin":
        root = tk.Tk()
        dnd_available = False  # Disable drag-and-drop on macOS
    else:
        # Other platforms: Try to use drag-and-drop if available
        root = None
        if dnd_available:
            try:
                root = TkinterDnD.Tk()
                # Test if tkdnd is actually available at runtime
                root.tk.call('package', 'require', 'tkdnd')
            except Exception:
                # tkdnd library not available at runtime - fall back to standard Tk
                if root is not None:
                    root.destroy()
                root = None
                dnd_available = False

        if root is None:
            root = tk.Tk()
            dnd_available = False

    root.title("Steganography Suite")
    SteganographyGUI(root)
    root.mainloop()


if __name__ == "__main__":
    gui_main()
