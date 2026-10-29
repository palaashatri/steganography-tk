"""Brand theme: palettes derived from the logo, native OS integration, and brand widgets.

The brand identity features a sculpted violet 3D glass tile with a gold key.
Controls use the platform's native widget set (Aqua on macOS following Apple HIG,
native Windows/Linux controls) paired with the brand header banner, brand accent
colors, and dark/light mode support.
"""

from __future__ import annotations

import sys
import tkinter as tk
import tkinter.font as tkfont
from dataclasses import dataclass
from tkinter import ttk
from typing import Any

from gui import branding


@dataclass(frozen=True)
class Palette:
    name: str
    bg: str  # window / surfaces
    raised: str  # banner, tab strip, headings
    field: str  # inputs
    button: str  # secondary button
    button_hover: str
    border: str
    text: str
    muted: str
    accent: str  # primary action / focus
    accent_hover: str
    accent_pressed: str
    accent_text: str  # accent colour usable as text on bg
    on_accent: str
    gold: str
    select: str
    banner_from: str
    banner_to: str


DARK = Palette(
    name="dark",
    bg="#2c2c2e" if sys.platform == "darwin" else "#171225",
    raised="#3a3a3c" if sys.platform == "darwin" else "#1F1834",
    field="#1c1c1e" if sys.platform == "darwin" else "#241C3F",
    button="#3a3a3c" if sys.platform == "darwin" else "#2E2450",
    button_hover="#48484a" if sys.platform == "darwin" else "#3B2E66",
    border="#545458" if sys.platform == "darwin" else "#3D3068",
    text="#FFFFFF" if sys.platform == "darwin" else "#F4F7FC",
    muted="#8e8e93" if sys.platform == "darwin" else "#A99CCB",
    accent="#9D66F0",
    accent_hover="#B38AF6",
    accent_pressed="#7F4FD0",
    accent_text="#C2A3FA",
    on_accent="#FFFFFF",
    gold=branding.GOLD,
    select="#5A3CA6",
    banner_from="#1B1233",
    banner_to="#5B34B4",
)

LIGHT = Palette(
    name="light",
    bg="#f2f2f7" if sys.platform == "darwin" else "#F7F4FD",
    raised="#e5e5ea" if sys.platform == "darwin" else "#EEE8FA",
    field="#FFFFFF",
    button="#e5e5ea" if sys.platform == "darwin" else "#E6DDF8",
    button_hover="#d1d1d6" if sys.platform == "darwin" else "#D9CCF3",
    border="#c7c7cc" if sys.platform == "darwin" else "#D3C7EE",
    text="#000000" if sys.platform == "darwin" else "#1B1233",
    muted="#8e8e93" if sys.platform == "darwin" else "#6B5E8C",
    accent="#7C45D6",
    accent_hover="#8E5BE6",
    accent_pressed="#6633BD",
    accent_text="#6633BD",
    on_accent="#FFFFFF",
    gold="#E0A21A",
    select="#D9C8F7",
    banner_from="#2A1A55",
    banner_to="#7C45D6",
)

CURRENT: Palette = DARK


def font_family() -> str:
    if sys.platform == "darwin":
        return ".AppleSystemUIFont"
    if sys.platform == "win32":
        return "Segoe UI"
    return "TkDefaultFont"


def _configure_fonts(root: tk.Misc) -> None:
    family = font_family()
    size = 13 if sys.platform == "darwin" else 10
    for name, delta, weight in (
        ("TkDefaultFont", 0, "normal"),
        ("TkTextFont", 0, "normal"),
        ("TkMenuFont", 0, "normal"),
        ("TkHeadingFont", 0, "bold"),
        ("TkCaptionFont", 0, "bold"),
        ("TkSmallCaptionFont", -1, "normal"),
        ("TkTooltipFont", -1, "normal"),
    ):
        try:
            font = tkfont.nametofont(name, root=root)
            if family != "TkDefaultFont":
                font.configure(family=family)
            font.configure(size=size + delta, weight=weight)
        except tk.TclError:
            pass


def apply(root: tk.Misc, mode: str = "dark") -> Palette:
    """Apply native theme and configure appearance and typography."""
    global CURRENT
    p = DARK if mode == "dark" else LIGHT
    CURRENT = p

    _configure_fonts(root)
    style = ttk.Style(root)

    if sys.platform == "darwin":
        appearance = "darkaqua" if mode == "dark" else "aqua"
        try:
            root.tk.call(
                "::tk::unsupported::MacWindowStyle",
                "appearance",
                root._w,
                appearance,
            )
        except Exception:
            pass
        if "aqua" in style.theme_names():
            style.theme_use("aqua")
        try:
            root.configure(bg="systemWindowBackgroundColor")
        except tk.TclError:
            pass
    elif sys.platform == "win32":
        if mode == "dark":
            if "alt" in style.theme_names():
                style.theme_use("alt")
            elif "clam" in style.theme_names():
                style.theme_use("clam")
        else:
            for name in ("vista", "xpnative", "winnative"):
                if name in style.theme_names():
                    style.theme_use(name)
                    break
        try:
            root.configure(bg=p.bg)
        except tk.TclError:
            pass
    else:
        if "clam" in style.theme_names():
            style.theme_use("clam")
        try:
            root.configure(bg=p.bg)
        except tk.TclError:
            pass

    # Native buttons:
    # Use native platform push buttons (Apple HIG Aqua buttons on macOS).
    # Configure Primary.TButton typography and padding:
    bold = tkfont.nametofont("TkDefaultFont", root=root).copy()
    bold.configure(weight="bold")
    style.configure("Primary.TButton", font=bold)
    style.configure("Header.TLabel", font=("TkDefaultFont", 16, "bold"))
    style.configure("Muted.TLabel", foreground=p.muted)

    return p


def text_options(p: Palette | None = None) -> dict[str, Any]:
    """Options for classic ``tk.Text`` widgets so they match the appearance."""
    p = p or CURRENT
    if sys.platform == "darwin":
        return {
            "bg": "#1e1e1e" if p.name == "dark" else "#ffffff",
            "fg": "#f0f0f0" if p.name == "dark" else "#000000",
            "insertbackground": p.accent,
            "selectbackground": p.select,
            "selectforeground": "#ffffff" if p.name == "dark" else "#000000",
            "relief": "flat",
            "borderwidth": 0,
            "highlightthickness": 1,
            "highlightbackground": "#3a3a3c" if p.name == "dark" else "#d1d1d6",
            "highlightcolor": p.accent,
            "font": tkfont.nametofont("TkTextFont"),
        }
    return {
        "bg": p.field,
        "fg": p.text,
        "insertbackground": p.accent,
        "selectbackground": p.select,
        "selectforeground": p.text,
        "relief": "flat",
        "borderwidth": 0,
        "highlightthickness": 1,
        "highlightbackground": p.border,
        "highlightcolor": p.accent,
        "font": tkfont.nametofont("TkTextFont"),
    }


def promote_primary_buttons(widget: tk.Misc) -> None:
    """Retained for API compatibility."""
    pass


def recolor_classic_widgets(widget: tk.Misc, p: Palette | None = None) -> None:
    """Recolor tk (non-ttk) widgets after a live theme switch."""
    p = p or CURRENT
    for child in widget.winfo_children():
        try:
            if isinstance(child, tk.Text):
                child.configure(**text_options(p))
            elif isinstance(child, tk.Toplevel):
                bg = "systemWindowBackgroundColor" if sys.platform == "darwin" else p.bg
                child.configure(bg=bg)
            elif hasattr(child, "placeholder_color"):
                child.default_color = p.text
                child.placeholder_color = p.muted
                child.configure(
                    foreground=p.muted if child._has_placeholder else p.text
                )
            elif hasattr(child, "recolor"):
                child.recolor()
        except tk.TclError:
            pass
        recolor_classic_widgets(child, p)


class BrandBanner(tk.Canvas):
    """Gradient header carrying the logo, product name and tagline."""

    def __init__(self, parent: tk.Misc, logo: Any | None, height: int = 84):
        super().__init__(
            parent, height=height, highlightthickness=0, bd=0, bg=CURRENT.banner_from
        )
        self._logo = logo
        self._gradient = None
        self.bind("<Configure>", lambda e: self._render(e.width))

    def recolor(self) -> None:
        self._render(self.winfo_width())

    def _render(self, width: int) -> None:
        if width < 10:
            return
        from PIL import Image, ImageTk

        height = int(self.cget("height"))
        p = CURRENT
        c1 = tuple(int(p.banner_from[i : i + 2], 16) for i in (1, 3, 5))
        c2 = tuple(int(p.banner_to[i : i + 2], 16) for i in (1, 3, 5))
        strip = Image.new("RGB", (width, 1))
        px = strip.load()
        for x in range(width):
            t = (x / max(1, width - 1)) ** 1.6
            px[x, 0] = tuple(round(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))
        self._gradient = ImageTk.PhotoImage(strip.resize((width, height)), master=self)
        self.delete("all")
        self.create_image(0, 0, image=self._gradient, anchor="nw")
        # gold rule along the bottom edge, echoing the key in the logo
        self.create_rectangle(0, height - 3, width, height, fill=p.gold, width=0)
        x = 20
        if self._logo is not None:
            self.create_image(x, (height - 3) // 2, image=self._logo, anchor="w")
            x += self._logo.width() + 16
        title = tkfont.nametofont("TkDefaultFont").copy()
        title.configure(size=title.cget("size") + 7, weight="bold")
        sub = tkfont.nametofont("TkDefaultFont").copy()
        sub.configure(size=max(9, sub.cget("size") - 1))
        self._fonts = (title, sub)
        self.create_text(
            x,
            height // 2 - 13,
            text=branding.APP_NAME,
            fill="#FFFFFF",
            font=title,
            anchor="w",
        )
        self.create_text(
            x,
            height // 2 + 15,
            text="Hide and reveal data in images, video frames and documents",
            fill=p.gold if p.name == "dark" else "#FFD98A",
            font=sub,
            anchor="w",
        )


class ScrollFrame(ttk.Frame):
    """Vertically scrollable container; put children in ``.interior``."""

    def __init__(self, parent: tk.Misc, **kwargs: Any):
        super().__init__(parent, **kwargs)
        bg = "systemWindowBackgroundColor" if sys.platform == "darwin" else CURRENT.bg
        self._canvas = tk.Canvas(
            self, highlightthickness=0, bd=0, bg=bg, takefocus=0
        )
        self._bar = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._bar.set)
        self._bar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self.interior = ttk.Frame(self._canvas)
        self._window = self._canvas.create_window(
            (0, 0), window=self.interior, anchor="nw"
        )
        self.interior.bind("<Configure>", self._on_interior)
        self._canvas.bind("<Configure>", self._on_canvas)
        for widget in (self._canvas, self.interior):
            widget.bind("<Enter>", self._bind_wheel)
            widget.bind("<Leave>", self._unbind_wheel)

    def recolor(self) -> None:
        bg = "systemWindowBackgroundColor" if sys.platform == "darwin" else CURRENT.bg
        self._canvas.configure(bg=bg)

    def _on_interior(self, _event: Any) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        self._update_bar()

    def _on_canvas(self, event: Any) -> None:
        self._canvas.itemconfigure(self._window, width=event.width)
        self._update_bar()

    def _update_bar(self) -> None:
        needed = self.interior.winfo_reqheight() > self._canvas.winfo_height()
        if needed and not self._bar.winfo_ismapped():
            self._bar.pack(side="right", fill="y", before=self._canvas)
        elif not needed and self._bar.winfo_ismapped():
            self._bar.pack_forget()

    def _bind_wheel(self, _event: Any) -> None:
        self.bind_all("<MouseWheel>", self._on_wheel)
        self.bind_all("<Button-4>", self._on_wheel)
        self.bind_all("<Button-5>", self._on_wheel)

    def _unbind_wheel(self, _event: Any) -> None:
        self.unbind_all("<MouseWheel>")
        self.unbind_all("<Button-4>")
        self.unbind_all("<Button-5>")

    def _on_wheel(self, event: Any) -> None:
        if self.interior.winfo_reqheight() <= self._canvas.winfo_height():
            return
        if getattr(event, "num", 0) == 4:
            delta = -1
        elif getattr(event, "num", 0) == 5:
            delta = 1
        elif sys.platform == "darwin":
            delta = -int(event.delta)
        else:
            delta = -int(event.delta / 120)
        self._canvas.yview_scroll(delta, "units")
