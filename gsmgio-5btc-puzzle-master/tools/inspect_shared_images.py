from __future__ import annotations

import json
from pathlib import Path

import cv2
from rapidocr_onnxruntime import RapidOCR


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "artifacts" / "shared_wayback"


def main() -> None:
    manifest = json.loads((BASE / "manifest.json").read_text(encoding="utf-8"))
    ocr = RapidOCR()
    detector = cv2.QRCodeDetector()
    records = []
    for asset in manifest["assets"]:
        path = ROOT / asset["path"]
        result, _ = ocr(str(path))
        lines = []
        for entry in result or []:
            box, text, confidence = entry
            lines.append({"text": text, "confidence": float(confidence), "box": box})
        image = cv2.imread(str(path))
        qr_text, _points, _straight = detector.detectAndDecode(image)
        records.append(
            {
                "index": asset["index"],
                "path": asset["path"],
                "sha256": asset["sha256"],
                "ocr_lines": lines,
                "ocr_text": "\n".join(line["text"] for line in lines),
                "qr_text": qr_text or None,
                "visual_classification": "GSMG automated crypto trading bot promotional card",
                "puzzle_hint_candidate": False,
            }
        )
        print(f"[{asset['index']:02d}/{len(manifest['assets']):02d}] OCR {len(lines)} lines; QR={qr_text!r}")

    output = {
        "method": {
            "visual": "Five contact sheets manually inspected, with every source image represented once",
            "ocr": "RapidOCR over each original-resolution PNG",
            "qr": "OpenCV QRCodeDetector over each original-resolution PNG",
        },
        "image_count": len(records),
        "puzzle_hint_candidates": sum(record["puzzle_hint_candidate"] for record in records),
        "records": records,
    }
    (BASE / "inspection.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    rows = [
        "# /shared/ pre-2023 image inspection",
        "",
        "All 34 unique PNG digests were visually inspected in contact sheets and OCRed at original resolution.",
        "",
        "| # | Timestamp | Asset | OCR-distinct content | QR | Classification |",
        "|---:|---|---|---|---|---|",
    ]
    by_index = {asset["index"]: asset for asset in manifest["assets"]}
    boilerplate = {
        "A fully", " automated", "A fully automated", "crypto trading bot", "One of my trades",
        "My completed trades today", "Follow the QR", "for a free trial", "on Binance", "on Bittrex",
    }
    for record in records:
        asset = by_index[record["index"]]
        distinctive = [line["text"] for line in record["ocr_lines"] if line["text"] not in boilerplate]
        compact = "; ".join(distinctive).replace("|", "\\|")
        qr = (record["qr_text"] or "not decoded").replace("|", "\\|")
        name = Path(asset["path"]).name
        rows.append(
            f"| {record['index']} | {asset['timestamp']} | `{name}` | {compact} | {qr} | Promotional trading card; no hint text |"
        )
    (BASE / "INSPECTION.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
