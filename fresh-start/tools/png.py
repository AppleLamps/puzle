"""Minimal pure-Python PNG reader.

Enough of the format to read the puzzle's PNGs (palette, greyscale, truecolour,
with or without alpha; bit depths 1/2/4/8) without requiring Pillow, so the
image stages run on a bare Python 3 install.

`read_rgb(path)` returns (width, height, rows) where each row is a list of
(r, g, b) tuples.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

SIGNATURE = b"\x89PNG\r\n\x1a\n"

# colour type -> samples per pixel
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def _chunks(data: bytes):
    offset = 8
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        yield kind, body
        offset += 12 + length


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _unfilter(raw: bytes, height: int, stride: int, bpp: int) -> bytearray:
    out = bytearray()
    previous = bytearray(stride)
    offset = 0
    for _ in range(height):
        filter_type = raw[offset]
        line = bytearray(raw[offset + 1:offset + 1 + stride])
        offset += 1 + stride
        for i in range(stride):
            left = line[i - bpp] if i >= bpp else 0
            up = previous[i]
            upleft = previous[i - bpp] if i >= bpp else 0
            if filter_type == 1:
                line[i] = (line[i] + left) & 0xFF
            elif filter_type == 2:
                line[i] = (line[i] + up) & 0xFF
            elif filter_type == 3:
                line[i] = (line[i] + (left + up) // 2) & 0xFF
            elif filter_type == 4:
                line[i] = (line[i] + _paeth(left, up, upleft)) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"unknown PNG filter {filter_type}")
        out += line
        previous = line
    return out


def _samples(line: bytes, depth: int, count: int) -> list[int]:
    if depth == 8:
        return list(line[:count])
    per_byte = 8 // depth
    mask = (1 << depth) - 1
    values = []
    for byte in line:
        for shift in range(8 - depth, -1, -depth):
            values.append((byte >> shift) & mask)
            if len(values) == count:
                return values
    return values[:count]


def read_rgb(path: str | Path) -> tuple[int, int, list[list[tuple[int, int, int]]]]:
    data = Path(path).read_bytes()
    if data[:8] != SIGNATURE:
        raise ValueError("not a PNG")

    palette: list[tuple[int, int, int]] = []
    idat = b""
    width = height = depth = colour = 0
    for kind, body in _chunks(data):
        if kind == b"IHDR":
            width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", body)
            if interlace:
                raise ValueError("interlaced PNG not supported")
        elif kind == b"PLTE":
            palette = [tuple(body[i:i + 3]) for i in range(0, len(body), 3)]
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break

    channels = CHANNELS[colour]
    stride = (width * channels * depth + 7) // 8
    bpp = max(1, channels * depth // 8)
    flat = _unfilter(zlib.decompress(idat), height, stride, bpp)

    rows = []
    for y in range(height):
        line = flat[y * stride:(y + 1) * stride]
        values = _samples(line, depth, width * channels)
        row = []
        for x in range(width):
            chunk = values[x * channels:(x + 1) * channels]
            if colour == 3:
                row.append(palette[chunk[0]])
            elif colour in (0, 4):
                scale = 255 // ((1 << depth) - 1)
                grey = chunk[0] * scale
                row.append((grey, grey, grey))
            else:
                row.append(tuple(chunk[:3]))
        rows.append(row)
    return width, height, rows
