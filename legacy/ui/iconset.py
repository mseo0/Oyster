"""Runtime icon loader: tint the white Lucide PNG masters to any colour.

Each master in ui/assets/*.png is a white glyph on transparency. We keep the
alpha (the shape) and swap in whatever RGB the theme asks for, then wrap it as a
CTkImage with separate light/dark colours so icons stay legible in both modes.
"""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

import customtkinter as ctk
from PIL import Image, ImageColor

if getattr(sys, "frozen", False):
    # PyInstaller bundles ui/assets at <bundle>/ui_assets (see oyster.spec)
    _ASSETS = Path(sys._MEIPASS) / "ui_assets"
else:
    _ASSETS = Path(__file__).resolve().parent / "assets"


@lru_cache(maxsize=None)
def _master(name: str) -> Image.Image:
    return Image.open(_ASSETS / f"{name}.png").convert("RGBA")


def _tint(name: str, hex_color: str) -> Image.Image:
    base = _master(name)
    r, g, b = ImageColor.getrgb(hex_color)
    out = Image.new("RGBA", base.size, (r, g, b, 0))
    out.putalpha(base.getchannel("A"))
    return out


def icon(name: str, light_hex: str, dark_hex: str | None = None,
         size: int = 18) -> ctk.CTkImage:
    """A CTkImage of `name` tinted for light (and optionally dark) appearance."""
    return ctk.CTkImage(
        light_image=_tint(name, light_hex),
        dark_image=_tint(name, dark_hex or light_hex),
        size=(size, size),
    )
