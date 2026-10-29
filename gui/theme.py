"""Brand theme: palettes derived from the logo and a complete ttk style sheet.

The logo is a violet glass tile with a gold key. The UI language follows it:
deep violet surfaces, a vivid violet accent for primary actions and focus,
and a gold highlight for selection and key moments. Both a dark and a light
palette are provided and either can follow the system appearance.
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
    bg="#171225",
    raised="#1F1834",
    field="#241C3F",
    button="#2E2450",
    button_hover="#3B2E66",
    border="#3D3068",
    text="#F4F7FC",
    muted="#A99CCB",
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
    bg="#F7F4FD",
    raised="#EEE8FA",
    field="#FFFFFF",
    button="#E6DDF8",
    button_hover="#D9CCF3",
    border="#D3C7EE",
    text="#1B1233",
    muted="#6B5E8C",
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
    """Apply the brand style sheet. ``mode`` is ``"dark"`` or ``"light"``."""
    global CURRENT
    p = DARK if mode == "dark" else LIGHT
    CURRENT = p

    _configure_fonts(root)
    style = ttk.Style(root)
    style.theme_use("clam")
    base = tkfont.nametofont("TkDefaultFont", root=root)
    bold = base.copy()
    bold.configure(weight="bold")
    big = base.copy()
    big.configure(size=base.cget("size") + 5, weight="bold")

    try:
        root.configure(bg=p.bg)
    except tk.TclError:
        pass

    style.configure(
        ".",
        background=p.bg,
        foreground=p.text,
        fieldbackground=p.field,
        troughcolor=p.field,
        bordercolor=p.border,
        lightcolor=p.border,
        darkcolor=p.border,
        selectbackground=p.select,
        selectforeground=p.text,
        insertcolor=p.text,
        focuscolor=p.accent,
        font=base,
    )
    style.map(
        ".",
        foreground=[("disabled", p.muted)],
        background=[("disabled", p.bg)],
    )

    style.configure("TFrame", background=p.bg)
    style.configure("TLabel", background=p.bg, foreground=p.text)
    style.configure("Header.TLabel", font=big, foreground=p.text)
    style.configure("Muted.TLabel", foreground=p.muted)
    style.configure("TSeparator", background=p.border)

    # Buttons ---------------------------------------------------------------
    style.configure(
        "TButton",
        background=p.button,
        foreground=p.text,
        bordercolor=p.border,
        lightcolor=p.button,
        darkcolor=p.button,
        borderwidth=1,
        relief="flat",
        padding=(14, 7),
        anchor="center",
    )
    style.map(
        "TButton",
        background=[("pressed", p.accent_pressed), ("active", p.button_hover)],
        foreground=[("pressed", p.on_accent), ("disabled", p.muted)],
        bordercolor=[("focus", p.accent), ("active", p.accent)],
        lightcolor=[("pressed", p.accent_pressed), ("active", p.button_hover)],
        darkcolor=[("pressed", p.accent_pressed), ("active", p.button_hover)],
    )
    style.configure(
        "Primary.TButton",
        background=p.accent,
        foreground=p.on_accent,
        bordercolor=p.accent,
        lightcolor=p.accent,
        darkcolor=p.accent,
        font=bold,
        padding=(18, 8),
    )
    style.map(
        "Primary.TButton",
        background=[("pressed", p.accent_pressed), ("active", p.accent_hover)],
        lightcolor=[("pressed", p.accent_pressed), ("active", p.accent_hover)],
        darkcolor=[("pressed", p.accent_pressed), ("active", p.accent_hover)],
        bordercolor=[("active", p.gold), ("focus", p.gold)],
        foreground=[("disabled", p.muted)],
    )
    style.configure(
        "Chip.TButton",
        padding=(10, 3),
        background=p.raised,
        lightcolor=p.raised,
        darkcolor=p.raised,
        font=tkfont.nametofont("TkSmallCaptionFont", root=root),
    )

    # Inputs ----------------------------------------------------------------
    for name in ("TEntry", "TSpinbox"):
        style.configure(
            name,
            fieldbackground=p.field,
            foreground=p.text,
            bordercolor=p.border,
            lightcolor=p.field,
            darkcolor=p.field,
            padding=7,
            insertcolor=p.text,
        )
        style.map(
            name,
            bordercolor=[("focus", p.accent), ("hover", p.accent_text)],
            lightcolor=[("focus", p.accent)],
            darkcolor=[("focus", p.accent)],
        )
    style.configure(
        "TCombobox",
        fieldbackground=p.field,
        background=p.button,
        foreground=p.text,
        arrowcolor=p.text,
        bordercolor=p.border,
        lightcolor=p.field,
        darkcolor=p.field,
        padding=6,
        selectbackground=p.field,
        selectforeground=p.text,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", p.field)],
        selectbackground=[("readonly", p.field)],
        selectforeground=[("readonly", p.text)],
        bordercolor=[("focus", p.accent)],
        arrowcolor=[("active", p.accent_text)],
        background=[("active", p.button_hover)],
    )
    root.option_add("*TCombobox*Listbox.background", p.field)
    root.option_add("*TCombobox*Listbox.foreground", p.text)
    root.option_add("*TCombobox*Listbox.selectBackground", p.accent)
    root.option_add("*TCombobox*Listbox.selectForeground", p.on_accent)
    root.option_add("*TCombobox*Listbox.borderWidth", 0)

    # Toggles ---------------------------------------------------------------
    for name in ("TCheckbutton", "TRadiobutton"):
        style.configure(
            name,
            background=p.bg,
            foreground=p.text,
            indicatorbackground=p.field,
            indicatorforeground=p.on_accent,
            indicatorcolor=p.field,
            bordercolor=p.border,
            lightcolor=p.field,
            darkcolor=p.field,
            padding=3,
        )
        style.map(
            name,
            background=[("active", p.bg)],
            indicatorcolor=[
                ("selected", p.accent),
                ("!selected", p.field),
            ],
            indicatorforeground=[("selected", p.on_accent), ("!selected", p.field)],
            indicatorbackground=[("selected", p.accent), ("!selected", p.field)],
            bordercolor=[("selected", p.accent), ("focus", p.accent)],
            lightcolor=[("selected", p.accent)],
            darkcolor=[("selected", p.accent)],
        )

    # Notebook (tabs) -------------------------------------------------------
    style.configure(
        "TNotebook",
        background=p.bg,
        borderwidth=0,
        bordercolor=p.border,
        lightcolor=p.bg,
        darkcolor=p.bg,
        tabmargins=(2, 4, 2, 0),
    )
    style.configure(
        "TNotebook.Tab",
        background=p.raised,
        foreground=p.muted,
        padding=(18, 9),
        borderwidth=1,
        bordercolor=p.border,
        lightcolor=p.raised,
        darkcolor=p.raised,
        font=base,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", p.bg), ("active", p.button)],
        foreground=[("selected", p.accent_text), ("active", p.text)],
        lightcolor=[("selected", p.gold)],
        bordercolor=[("selected", p.border)],
    )

    # Cards -----------------------------------------------------------------
    style.configure(
        "TLabelframe",
        background=p.bg,
        bordercolor=p.border,
        lightcolor=p.bg,
        darkcolor=p.border,
        relief="solid",
        borderwidth=1,
        padding=6,
    )
    style.configure(
        "TLabelframe.Label",
        background=p.bg,
        foreground=p.accent_text,
        font=bold,
    )

    # Progress, scrollbars, tree --------------------------------------------
    style.configure(
        "TProgressbar",
        background=p.accent,
        troughcolor=p.field,
        bordercolor=p.border,
        lightcolor=p.gold,
        darkcolor=p.accent,
        thickness=8,
    )
    style.configure(
        "TScrollbar",
        background=p.button,
        troughcolor=p.bg,
        bordercolor=p.bg,
        lightcolor=p.button,
        darkcolor=p.button,
        arrowcolor=p.text,
        gripcount=0,
        relief="flat",
    )
    style.map("TScrollbar", background=[("active", p.accent)])
    style.configure(
        "Treeview",
        background=p.field,
        fieldbackground=p.field,
        foreground=p.text,
        bordercolor=p.border,
        lightcolor=p.field,
        darkcolor=p.field,
        rowheight=30,
    )
    style.map(
        "Treeview",
        background=[("selected", p.select)],
        foreground=[("selected", p.text)],
    )
    style.configure(
        "Treeview.Heading",
        background=p.raised,
        foreground=p.accent_text,
        relief="flat",
        padding=(8, 7),
        font=bold,
        bordercolor=p.border,
        lightcolor=p.raised,
        darkcolor=p.raised,
    )
    style.map("Treeview.Heading", background=[("active", p.button)])
    style.configure("TScale", background=p.bg, troughcolor=p.field)
    style.configure("TPanedwindow", background=p.bg)

    root.option_add("*Listbox.background", p.field)
    root.option_add("*Listbox.foreground", p.text)
    root.option_add("*Listbox.selectBackground", p.accent)
    root.option_add("*Listbox.selectForeground", p.on_accent)
    root.option_add("*Listbox.relief", "flat")
    root.option_add("*Listbox.borderWidth", 0)
    root.option_add("*Listbox.highlightThickness", 1)
    root.option_add("*Listbox.highlightBackground", p.border)
    root.option_add("*Listbox.highlightColor", p.accent)
    root.option_add("*Listbox.activeStyle", "none")

    # Plain tk menus follow the palette on platforms that allow it (not macOS).
    if sys.platform != "darwin":
        root.option_add("*Menu.background", p.raised)
        root.option_add("*Menu.foreground", p.text)
        root.option_add("*Menu.activeBackground", p.accent)
        root.option_add("*Menu.activeForeground", p.on_accent)
        root.option_add("*Menu.borderWidth", 0)

    return p


def text_options(p: Palette | None = None) -> dict[str, Any]:
    """Options for classic ``tk.Text`` widgets so they match the theme."""
    p = p or CURRENT
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


PRIMARY_PREFIXES = (
    "Embed",
    "Extract",
    "Run Batch",
    "Analyze",
    "Detect",
    "Generate",
    "Create",
    "Calculate",
)


def promote_primary_buttons(widget: tk.Misc) -> None:
    """Give the main action buttons the accent style."""
    for child in widget.winfo_children():
        if isinstance(child, ttk.Button):
            try:
                text = str(child.cget("text"))
                if text.startswith(PRIMARY_PREFIXES):
                    child.configure(style="Primary.TButton")
            except tk.TclError:
                pass
        promote_primary_buttons(child)


def recolor_classic_widgets(widget: tk.Misc, p: Palette | None = None) -> None:
    """Recolor tk (non-ttk) widgets after a live theme switch."""
    p = p or CURRENT
    for child in widget.winfo_children():
        try:
            if isinstance(child, tk.Text):
                child.configure(**text_options(p))
            elif isinstance(child, tk.Listbox):
                child.configure(
                    bg=p.field,
                    fg=p.text,
                    selectbackground=p.accent,
                    selectforeground=p.on_accent,
                    highlightbackground=p.border,
                    highlightcolor=p.accent,
                )
            elif isinstance(child, tk.Toplevel):
                child.configure(bg=p.bg)
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
        # gold rule along the bottom edge, echoing the key
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
        self._canvas = tk.Canvas(
            self, highlightthickness=0, bd=0, bg=CURRENT.bg, takefocus=0
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
        self._canvas.configure(bg=CURRENT.bg)

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
