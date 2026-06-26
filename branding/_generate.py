"""Generate Oyster's app icons + in-app brand mark from one vector source.

The mark is an abstract oyster/eye: a top shell arc, a centred pearl, and a
bottom shell arc. Recreated as SVG so it stays crisp at every icon size.

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib \\
        .venv/bin/python branding/_generate.py

Outputs:
    branding/Oyster.icns          — macOS app icon (via iconutil)
    branding/oyster.ico           — Windows app icon
    branding/oyster.png           — 512px reference
    ui/assets/oyster-mark.png     — white glyph, tinted at runtime for the UI
"""
import os
import subprocess
from pathlib import Path

os.environ.setdefault("DYLD_FALLBACK_LIBRARY_PATH", "/opt/homebrew/lib")
import cairosvg  # noqa: E402
from PIL import Image  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# the motif (matches Oyster.dc): two bracket-style shell arcs + a centred pearl.
# Design source viewBox is 0 0 64 64; scaled x16 to a 1024 canvas here.
MOTIF = """
  <g fill="none" stroke="{c}" stroke-width="104"
     stroke-linecap="round" stroke-linejoin="round">
    <path d="M256 416 V368 Q256 224 512 224 Q768 224 768 368 V416"/>
    <path d="M256 608 V656 Q256 800 512 800 Q768 800 768 656 V608"/>
  </g>
  <circle cx="512" cy="512" r="86" fill="{c}"/>
"""


def full_svg() -> bytes:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">'
            f'<rect width="1024" height="1024" rx="224" ry="224" fill="#FFFFFF"/>'
            f'{MOTIF.format(c="#0F0F0F")}</svg>').encode()


def mark_svg(color: str) -> bytes:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">'
            f'{MOTIF.format(c=color)}</svg>').encode()


# --- macOS .icns -----------------------------------------------------------
iconset = HERE / "Oyster.iconset"
iconset.mkdir(exist_ok=True)
full = full_svg()
for s in (16, 32, 128, 256, 512):
    cairosvg.svg2png(bytestring=full, output_width=s, output_height=s,
                     write_to=str(iconset / f"icon_{s}x{s}.png"))
    cairosvg.svg2png(bytestring=full, output_width=s * 2, output_height=s * 2,
                     write_to=str(iconset / f"icon_{s}x{s}@2x.png"))
subprocess.run(["iconutil", "-c", "icns", str(iconset),
                "-o", str(HERE / "Oyster.icns")], check=True)
print("wrote Oyster.icns")

# --- reference PNG + Windows .ico ------------------------------------------
cairosvg.svg2png(bytestring=full, output_width=512, output_height=512,
                 write_to=str(HERE / "oyster.png"))
Image.open(HERE / "oyster.png").save(
    HERE / "oyster.ico",
    sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("wrote oyster.ico + oyster.png")

# --- in-app brand mark (white on transparent; tinted at runtime) -----------
cairosvg.svg2png(bytestring=mark_svg("#FFFFFF"), output_width=128,
                 output_height=128,
                 write_to=str(ROOT / "ui" / "assets" / "oyster-mark.png"))
print("wrote ui/assets/oyster-mark.png")
