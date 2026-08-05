from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import cv2
from rapidocr_onnxruntime import RapidOCR


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = cv2.imread(str(args.image))
    gray = cv2.cvtColor(source, cv2.COLOR_BGR2GRAY)
    # The white Telegram message rectangle contains the binary text at x=62..515.
    crop = gray[56:751, 58:520]
    mask = crop < 110
    row_ink = mask.sum(axis=1)
    bands = []
    start = None
    for y, count in enumerate(row_ink):
        if count >= 8 and start is None:
            start = y
        elif count < 8 and start is not None:
            if y - start >= 5:
                bands.append((start, y))
            start = None
    if start is not None:
        bands.append((start, len(row_ink)))

    # Keep only binary rows; header/footer bands are rejected by token validation.
    ocr = RapidOCR()
    rows = []
    for y0, y1 in bands:
        line = crop[max(0, y0 - 3) : min(crop.shape[0], y1 + 3), :]
        line = cv2.resize(line, None, fx=5, fy=5, interpolation=cv2.INTER_CUBIC)
        result, _ = ocr(line)
        text = " ".join(entry[1] for entry in (result or []))
        tokens = re.findall(r"[01]{8}", text.replace(" ", ""))
        # Prefer whitespace-delimited extraction where OCR preserved groups.
        spaced = re.findall(r"(?<![01])[01]{8}(?![01])", text)
        if spaced:
            tokens = spaced
        if tokens:
            rows.append({"source_y": [y0 + 56, y1 + 56], "ocr": text, "tokens": tokens})

    tokens = [token for row in rows for token in row["tokens"]]
    forward_bit_reversed = "".join(chr(int(token[::-1], 2)) for token in tokens)
    reverse_bytes_then_bits = "".join(chr(int(token[::-1], 2)) for token in reversed(tokens))
    output = {
        "image": str(args.image),
        "rows": rows,
        "token_count": len(tokens),
        "tokens": tokens,
        "forward_bit_reversed": forward_bit_reversed,
        "reverse_bytes_then_bits": reverse_bytes_then_bits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"bands": len(bands), "binary_rows": len(rows), "tokens": len(tokens)}))
    print("forward:", repr(forward_bit_reversed))
    print("reverse:", repr(reverse_bytes_then_bits))


if __name__ == "__main__":
    main()
