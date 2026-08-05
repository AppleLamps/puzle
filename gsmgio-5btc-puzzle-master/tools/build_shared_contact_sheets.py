from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "artifacts" / "shared_wayback"
MANIFEST = BASE / "manifest.json"


def main() -> None:
    report = json.loads(MANIFEST.read_text(encoding="utf-8"))
    font = ImageFont.load_default(size=16)
    thumb_w, thumb_h = 420, 300
    label_h = 58
    cols, rows_per_sheet = 2, 4
    per_sheet = cols * rows_per_sheet

    dimensions = []
    for asset in report["assets"]:
        path = ROOT / asset["path"]
        with Image.open(path) as image:
            dimensions.append({"index": asset["index"], "width": image.width, "height": image.height})

    for start in range(0, len(report["assets"]), per_sheet):
        batch = report["assets"][start : start + per_sheet]
        sheet = Image.new("RGB", (cols * thumb_w, rows_per_sheet * (thumb_h + label_h)), "white")
        draw = ImageDraw.Draw(sheet)
        for offset, asset in enumerate(batch):
            row, col = divmod(offset, cols)
            x, y = col * thumb_w, row * (thumb_h + label_h)
            path = ROOT / asset["path"]
            with Image.open(path) as image:
                image = image.convert("RGB")
                image.thumbnail((thumb_w - 10, thumb_h - 10))
                px = x + (thumb_w - image.width) // 2
                py = y + (thumb_h - image.height) // 2
                sheet.paste(image, (px, py))
            label = f"#{asset['index']:02d} {asset['timestamp']}\n{asset['original'].rsplit('/', 1)[-1]}"
            draw.multiline_text((x + 6, y + thumb_h + 4), label, fill="black", font=font, spacing=2)
        number = start // per_sheet + 1
        sheet.save(BASE / f"contact_sheet_{number:02d}.png")

    report["dimensions"] = dimensions
    MANIFEST.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
