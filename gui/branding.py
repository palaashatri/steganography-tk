"""Application identity: logo assets, brand palette, and per-platform icon wiring.

The goal is that the app never shows the default Python/Tk icon:

* Windows  - ``iconbitmap`` with the ICO plus an explicit AppUserModelID so the
  taskbar groups under this app instead of ``python.exe``.
* Linux    - ``iconphoto`` with several PNG sizes and a matching WM class.
* macOS    - ``iconphoto`` for the window and ``NSApplication`` for the Dock
  icon and menu-bar application name.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from pathlib import Path
from typing import Any

APP_NAME = "Steganography Suite"
APP_ID = "atri.palaash.steganography-tk"

BRAND_DIR = Path(__file__).resolve().parent.parent / "assets" / "brand"

# Palette sampled from the logo: violet glass tile with a gold key.
VIOLET = "#9D66F0"
VIOLET_DEEP = "#3A1F78"
VIOLET_NIGHT = "#1B1233"
VIOLET_MIST = "#EFE7FD"
GOLD = "#F5B83D"
INK = "#101720"
PAPER = "#F4F7FC"

ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


def asset_path(name: str) -> Path | None:
    """Return a brand asset path if it exists."""
    path = BRAND_DIR / name
    return path if path.is_file() else None


class _ObjC:
    """Tiny Objective-C runtime bridge (ctypes only; no pyobjc dependency)."""

    def __init__(self) -> None:
        objc_path = ctypes.util.find_library("objc")
        if not objc_path:
            raise OSError("Objective-C runtime unavailable")
        self.lib = ctypes.cdll.LoadLibrary(objc_path)
        ctypes.cdll.LoadLibrary("/System/Library/Frameworks/AppKit.framework/AppKit")
        self.lib.objc_getClass.restype = ctypes.c_void_p
        self.lib.objc_getClass.argtypes = [ctypes.c_char_p]
        self.lib.sel_registerName.restype = ctypes.c_void_p
        self.lib.sel_registerName.argtypes = [ctypes.c_char_p]
        self._send = ctypes.cast(self.lib.objc_msgSend, ctypes.c_void_p).value

    def cls(self, name: str) -> int:
        return self.lib.objc_getClass(name.encode())

    def msg(self, restype: Any, receiver: int, selector: str, *args: Any) -> Any:
        proto = ctypes.CFUNCTYPE(
            restype, ctypes.c_void_p, ctypes.c_void_p, *[ctypes.c_void_p] * len(args)
        )
        return proto(self._send)(
            receiver, self.lib.sel_registerName(selector.encode()), *args
        )

    def nsstring(self, text: str) -> int:
        return self.msg(
            ctypes.c_void_p,
            self.cls("NSString"),
            "stringWithUTF8String:",
            ctypes.cast(ctypes.c_char_p(text.encode()), ctypes.c_void_p),
        )


def prepare_macos_app_name() -> None:
    """Name the app in the menu bar (otherwise "python"). Call before ``Tk()``."""
    if sys.platform != "darwin":
        return
    try:
        objc = _ObjC()
        bundle = objc.msg(ctypes.c_void_p, objc.cls("NSBundle"), "mainBundle")
        info = objc.msg(ctypes.c_void_p, bundle, "infoDictionary") if bundle else None
        if info:
            for key in ("CFBundleName", "CFBundleDisplayName"):
                objc.msg(
                    None,
                    info,
                    "setObject:forKey:",
                    objc.nsstring(APP_NAME),
                    objc.nsstring(key),
                )
    except Exception:
        pass


def _mac_set_dock_icon(png_path: Path) -> None:
    """Set the Dock / app-switcher icon through NSApplication."""
    objc = _ObjC()
    image = objc.msg(ctypes.c_void_p, objc.cls("NSImage"), "alloc")
    image = objc.msg(
        ctypes.c_void_p,
        image,
        "initWithContentsOfFile:",
        objc.nsstring(str(png_path)),
    )
    if image:
        app = objc.msg(ctypes.c_void_p, objc.cls("NSApplication"), "sharedApplication")
        objc.msg(None, app, "setApplicationIconImage:", image)


def apply_app_identity(root: Any) -> list[Any]:
    """Install the app logo on ``root``; returns PhotoImages that must stay referenced."""
    import tkinter as tk

    refs: list[Any] = []

    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        except Exception:
            pass
        ico = asset_path("icon.ico")
        if ico:
            try:
                root.iconbitmap(default=str(ico))
            except tk.TclError:
                pass

    photos = []
    for size in ICON_SIZES:
        png = asset_path(f"icon-{size}.png")
        if png is None:
            continue
        try:
            photos.append(tk.PhotoImage(master=root, file=str(png)))
        except tk.TclError:
            continue
    if photos:
        try:
            root.iconphoto(True, *photos)
        except tk.TclError:
            pass
        refs.extend(photos)

    if sys.platform == "darwin":
        png = asset_path("icon-512.png") or asset_path("icon-256.png")
        if png:
            try:
                _mac_set_dock_icon(png)
            except Exception:
                pass
    return refs


def load_logo(root: Any, size: int = 40) -> Any | None:
    """Return a smoothly scaled PhotoImage of the logo, ``size`` pixels square."""
    import tkinter as tk

    source = asset_path("icon-512.png") or asset_path("icon-128.png")
    if source is None:
        return None
    try:
        from PIL import Image, ImageTk

        with Image.open(source) as img:
            scaled = img.convert("RGBA").resize((size, size), Image.LANCZOS)
        return ImageTk.PhotoImage(scaled, master=root)
    except Exception:
        try:
            return tk.PhotoImage(master=root, file=str(source))
        except tk.TclError:
            return None
