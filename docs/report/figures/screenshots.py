"""Console screenshots for Figures 4.2 and 4.3: crop to the content area (no sidebar, top bar or
empty margins), greyscale (body ink stays black), thin grey border. Source: docs/gateway/screenshots
(Simple view, seeded e2e tenant; no secrets or tokens visible)."""
from pathlib import Path

from PIL import Image, ImageOps

HERE = Path(__file__).resolve().parent
SRC = HERE.parents[1] / "gateway/screenshots/human-readable"
JOBS = [("run-simple.png", "fig4_2_console_run.png", (256, 62, 1424, 790)),
        ("approval-simple.png", "fig4_3_console_approval.png", (256, 62, 1424, 575))]
for src, dst, box in JOBS:
    im = Image.open(SRC / src).convert("L").crop(box)
    im = ImageOps.expand(im, border=2, fill=150)
    im.save(HERE / dst, dpi=(300, 300))
    print("wrote", dst, im.size)
