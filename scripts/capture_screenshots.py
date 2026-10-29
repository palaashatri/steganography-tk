"""Capture the macOS GUI screenshots used in docs/screenshots (macOS only).

Usage: python scripts/capture_screenshots.py [output_dir]
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tkinter as tk  # noqa: E402

from PIL import Image  # noqa: E402


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "screenshots"
    out.mkdir(parents=True, exist_ok=True)
    import gui.main as app

    captured: dict[str, object] = {}
    real_tk = tk.Tk

    def make_root(*a, **k):
        root = real_tk(*a, **k)
        captured["root"] = root
        return root

    tk.Tk = make_root  # type: ignore[misc]
    root_holder: list[tk.Tk] = []

    def grab(name: str) -> None:
        root = root_holder[0]
        root.geometry("1280x840+60+70")
        root.lift()
        root.attributes("-topmost", True)
        root.update()
        subprocess.run(
            [
                "osascript",
                "-e",
                'tell application "System Events" to set frontmost of '
                f"(first process whose unix id is {os.getpid()}) to true",
            ],
            check=False,
        )
        root.after(500)
        root.update()
        x, y, w, h = (
            root.winfo_rootx(),
            root.winfo_rooty(),
            root.winfo_width(),
            root.winfo_height(),
        )
        tmp = Path(tempfile.mkstemp(suffix=".png")[1])
        # include the title bar (~28pt) above the content area
        subprocess.run(
            ["screencapture", "-x", "-R", f"{x},{y - 28},{w},{h + 28}", str(tmp)],
            check=True,
        )
        Image.open(tmp).convert("RGB").save(out / f"{name}.png", optimize=True)
        tmp.unlink()
        if name == "hide-data":
            strip = Path(tempfile.mkstemp(suffix=".png")[1])
            subprocess.run(
                ["screencapture", "-x", "-R", "0,0,700,30", str(strip)], check=True
            )
            Image.open(strip).convert("RGB").save(out / "menu-bar.png", optimize=True)
            strip.unlink()

    tabs = {
        "hide-data": "Hide Data",
        "reveal-data": "Reveal Data",
        "advanced": "Advanced",
        "batch": "Batch Operations",
        "analysis-tools": "Analysis & Tools",
        "history": "History",
    }

    def drive() -> None:
        root = captured["root"]
        root_holder.append(root)  # type: ignore[arg-type]
        gui_obj = [w for w in [root]][0]
        root.update()
        notebook = None

        def find(widget):
            from tkinter import ttk

            if isinstance(widget, ttk.Notebook) and len(widget.tabs()) >= 6:
                return widget
            for child in widget.winfo_children():
                r = find(child)
                if r:
                    return r
            return None

        notebook = find(root)
        names = {notebook.tab(t, "text"): t for t in notebook.tabs()}
        steps = list(tabs.items())

        def step(i: int = 0) -> None:
            if i >= len(steps):
                root.destroy()
                return
            slug, label = steps[i]
            notebook.select(names[label])
            root.after(700, lambda: (grab(slug), root.after(200, lambda: step(i + 1))))

        root.after(1500, step)

    original_after = None
    root_ready = tk.Tk.__init__

    def patched_mainloop(self, n=0):
        self.after(500, drive)
        return tk.Misc.mainloop(self, n)

    real_tk.mainloop = patched_mainloop  # type: ignore[assignment]
    app.gui_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
