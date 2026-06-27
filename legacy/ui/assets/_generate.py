"""Dev-time: rasterize the Lucide SVG icons (MIT/ISC) into white PNG masters.

The app tints these white masters to any colour at runtime (see ui/iconset.py),
so we only need one render per icon. Re-run after adding an SVG to _svg/:

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib \\
        .venv/bin/python ui/assets/_generate.py

Requires cairosvg (which needs the system cairo lib: `brew install cairo`).
"""
import os
from pathlib import Path

os.environ.setdefault("DYLD_FALLBACK_LIBRARY_PATH", "/opt/homebrew/lib")
import cairosvg  # noqa: E402

HERE = Path(__file__).resolve().parent
SVG = HERE / "_svg"
SIZE = 64  # generous master; downscaled to ~18px at runtime for crispness

for svg_path in sorted(SVG.glob("*.svg")):
    svg = svg_path.read_text().replace("currentColor", "#FFFFFF")
    out = HERE / f"{svg_path.stem}.png"
    cairosvg.svg2png(bytestring=svg.encode(), write_to=str(out),
                     output_width=SIZE, output_height=SIZE)
    print("wrote", out.name)
