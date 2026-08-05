from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from rapidocr_onnxruntime import RapidOCR


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "telegram_hints_pr16"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("hints_dir", type=Path)
    args = parser.parse_args()
    files = sorted(path for path in args.hints_dir.iterdir() if path.suffix.lower() in {".png", ".jpg", ".jpeg"})
    OUT.mkdir(parents=True, exist_ok=True)
    ocr = RapidOCR()
    records = []
    for index, path in enumerate(files, 1):
        result, _ = ocr(str(path))
        lines = []
        for entry in result or []:
            box, text, confidence = entry
            lines.append({"text": text, "confidence": float(confidence), "box": box})
        with Image.open(path) as image:
            dimensions = [image.width, image.height]
        records.append(
            {
                "index": index,
                "name": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
                "dimensions": dimensions,
                "raw_ocr_lines": lines,
                "raw_ocr_text": "\n".join(line["text"] for line in lines),
            }
        )
        print(f"[{index:02d}/{len(files):02d}] {path.name}: {len(lines)} OCR lines", flush=True)
    (OUT / "raw_ocr.json").write_text(json.dumps({"records": records}, indent=2) + "\n", encoding="utf-8")

    font = ImageFont.load_default(size=15)
    cell_w, image_h, label_h = 560, 400, 62
    cols, rows = 2, 3
    per_sheet = cols * rows
    for start in range(0, len(files), per_sheet):
        sheet = Image.new("RGB", (cols * cell_w, rows * (image_h + label_h)), "white")
        draw = ImageDraw.Draw(sheet)
        for offset, path in enumerate(files[start : start + per_sheet]):
            row, col = divmod(offset, cols)
            x, y = col * cell_w, row * (image_h + label_h)
            with Image.open(path) as source:
                image = source.convert("RGB")
                image.thumbnail((cell_w - 10, image_h - 10))
                sheet.paste(image, (x + (cell_w - image.width) // 2, y + (image_h - image.height) // 2))
            draw.text((x + 6, y + image_h + 5), f"#{start + offset + 1:02d} {path.name}", fill="black", font=font)
        sheet.save(OUT / f"contact_sheet_{start // per_sheet + 1:02d}.png")


if __name__ == "__main__":
    main()
