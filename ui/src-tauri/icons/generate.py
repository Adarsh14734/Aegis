#!/usr/bin/env python3
"""Draw the Aegis app icon, and every size the bundle needs, from one source.

    python3 ui/src-tauri/icons/generate.py

WHY THIS FILE EXISTS

`icon.icns` was regenerated and the Dock still showed nothing. The icns was
never the problem: it was a faithful, well-formed, ten-entry icns of a picture
with nothing in it. Every pixel of `icon.png`, at every size, was the single
colour #1a2a3a — a flat dark square, which against a dark Dock is invisible and
against a light one is a blank tile. The generator had been fed a placeholder,
and every check that existed asked about the container (does it have the large
sizes? is it big enough? does Info.plist name it?) rather than the picture. All
of those passed.

So the artwork is drawn here, in code, from a description that can be read and
reviewed — rather than being a binary someone has to trust. Nothing is imported
that is not in the standard library, and `iconutil` (which ships with macOS)
assembles the .icns, so the container format is the platform's own.

WHAT IT DRAWS

A shield, because that is what "aegis" means, in the app's own palette:

  * a rounded square in the deep navy the design system already used, with the
    ~10% margin macOS icons are drawn inside,
  * a shield in --color-bg, the same near-white the window is painted with,
  * an inset ring in --color-accent.

It is deliberately one shape with one accent. The Dock renders this at 16
points in a Finder list and at 128 in the Dock itself, and interior detail that
survives the first does not exist. tests/bundle.py asserts the result is
actually a picture — several colours, a mark that covers a real fraction of the
canvas, and a difference between the middle and the corners — so a placeholder
can never ship silently again.
"""

import math
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from array import array
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# the drawing, in fractions of the canvas so every size is the same picture
# ---------------------------------------------------------------------------

# macOS draws its icons inside a margin; a full-bleed square reads as wrong
# next to every other icon in the Dock.
PLATE_INSET = 0.086
PLATE_RADIUS = 0.185          # ≈ 0.2237 of the plate, the Big Sur corner
PLATE_TOP = (0x22, 0x3a, 0x4e)
PLATE_BOTTOM = (0x0d, 0x1b, 0x27)

SHIELD_TOP = 0.232
SHIELD_SHOULDER = 0.470       # straight sides above here, sweep to a point below
SHIELD_BOTTOM = 0.805
SHIELD_HALF = 0.208
SHIELD_CORNER = 0.042
SHIELD_FILL = (0xf3, 0xf2, 0xf2)      # --color-bg

RING_INSET = 0.046            # inset of the accent ring inside the shield
RING_WIDTH = 0.021
RING_COLOR = (0x00, 0x88, 0xb0)       # --color-accent

VSAMPLES = 4                  # vertical supersamples per pixel row


def plate_half_width(y: float):
    """Half-width of the rounded plate at height y, or None above/below it."""
    top, bottom = PLATE_INSET, 1.0 - PLATE_INSET
    if y < top or y > bottom:
        return None
    half = (bottom - top) / 2.0
    r = min(PLATE_RADIUS, half)
    # Distance into the rounded corner band, if we are in one.
    if y < top + r:
        d = (top + r) - y
    elif y > bottom - r:
        d = y - (bottom - r)
    else:
        return half
    if d >= r:
        return None
    return half - r + math.sqrt(max(0.0, r * r - d * d))


def shield_half_width(y: float, grow: float = 0.0):
    """Half-width of the shield at height y, or None outside it.

    `grow` inflates the whole shape, which is how the accent ring is made: the
    ring is the shield inset by RING_INSET minus the same shape inset a little
    further. Deriving both from one function is what keeps the ring parallel to
    the edge instead of merely near it.
    """
    top = SHIELD_TOP - grow
    shoulder = SHIELD_SHOULDER
    bottom = SHIELD_BOTTOM + grow
    half = SHIELD_HALF + grow
    if half <= 0 or y < top or y > bottom:
        return None

    if y <= shoulder:
        r = min(SHIELD_CORNER, half)
        if y < top + r:
            d = (top + r) - y
            if d >= r:
                return None
            return half - r + math.sqrt(max(0.0, r * r - d * d))
        return half
    # Below the shoulder the sides sweep in to a point. A parabola, not a
    # quarter ellipse: an ellipse leaves the tip horizontal, which draws a
    # rounded U rather than a shield. This leaves the sides vertical where they
    # meet the straight part and converges at a real angle at the bottom.
    t = (y - shoulder) / (bottom - shoulder)
    if t > 1.0:
        return None
    return half * max(0.0, 1.0 - t * t)


def coverage(size: int, half_width_at) -> array:
    """Per-pixel coverage of a shape defined by a half-width function.

    Exact horizontally, supersampled vertically. The shapes here are all
    "an interval of x for each y", which is why this is enough — and why it is
    fast enough to run in pure Python at 1024x1024.
    """
    buf = array("f", bytes(4 * size * size))
    weight = 1.0 / VSAMPLES
    cx = 0.5 * size
    for row in range(size):
        base = row * size
        for s in range(VSAMPLES):
            y = (row + (s + 0.5) / VSAMPLES) / size
            hw = half_width_at(y)
            if hw is None or hw <= 0:
                continue
            xa, xb = cx - hw * size, cx + hw * size
            xa = max(0.0, xa)
            xb = min(float(size), xb)
            if xb <= xa:
                continue
            i0, i1 = int(xa), min(int(xb), size - 1)
            if i0 == i1:
                buf[base + i0] += (xb - xa) * weight
                continue
            buf[base + i0] += (i0 + 1 - xa) * weight
            buf[base + i1] += (xb - i1) * weight
            for i in range(i0 + 1, i1):
                buf[base + i] += weight
    return buf


def render(size: int) -> bytes:
    """The master image, as RGBA bytes."""
    plate = coverage(size, plate_half_width)
    shield = coverage(size, shield_half_width)
    ring_outer = coverage(size, lambda y: shield_half_width(y, -RING_INSET))
    ring_inner = coverage(size, lambda y: shield_half_width(y, -RING_INSET - RING_WIDTH))

    out = bytearray(4 * size * size)
    for row in range(size):
        # The plate's vertical gradient. Subtle on purpose: this is a flat
        # design system and a glossy icon would not belong to it.
        t = row / max(1, size - 1)
        pr = round(PLATE_TOP[0] + (PLATE_BOTTOM[0] - PLATE_TOP[0]) * t)
        pg = round(PLATE_TOP[1] + (PLATE_BOTTOM[1] - PLATE_TOP[1]) * t)
        pb = round(PLATE_TOP[2] + (PLATE_BOTTOM[2] - PLATE_TOP[2]) * t)
        base = row * size
        for col in range(size):
            i = base + col
            a_plate = min(1.0, plate[i])
            if a_plate <= 0.0:
                continue
            r, g, b = pr, pg, pb
            a_shield = min(1.0, shield[i])
            if a_shield > 0.0:
                r = r + (SHIELD_FILL[0] - r) * a_shield
                g = g + (SHIELD_FILL[1] - g) * a_shield
                b = b + (SHIELD_FILL[2] - b) * a_shield
            a_ring = min(1.0, max(0.0, ring_outer[i] - ring_inner[i]))
            if a_ring > 0.0:
                r = r + (RING_COLOR[0] - r) * a_ring
                g = g + (RING_COLOR[1] - g) * a_ring
                b = b + (RING_COLOR[2] - b) * a_ring
            o = 4 * i
            out[o] = int(r + 0.5)
            out[o + 1] = int(g + 0.5)
            out[o + 2] = int(b + 0.5)
            out[o + 3] = int(a_plate * 255 + 0.5)
    return bytes(out)


# ---------------------------------------------------------------------------
# resampling and PNG output — stdlib only
# ---------------------------------------------------------------------------


def resample(src: bytes, src_size: int, dst_size: int) -> bytes:
    """Area-average downscale. Premultiplied, or the transparent margin would
    bleed dark pixels into the rounded corners."""
    if dst_size == src_size:
        return src
    out = bytearray(4 * dst_size * dst_size)
    scale = src_size / dst_size
    for dy in range(dst_size):
        y0, y1 = int(dy * scale), max(int(dy * scale) + 1, int((dy + 1) * scale))
        for dx in range(dst_size):
            x0, x1 = int(dx * scale), max(int(dx * scale) + 1, int((dx + 1) * scale))
            r = g = b = a = 0.0
            n = 0
            for sy in range(y0, min(y1, src_size)):
                row = 4 * sy * src_size
                for sx in range(x0, min(x1, src_size)):
                    o = row + 4 * sx
                    sa = src[o + 3] / 255.0
                    r += src[o] * sa
                    g += src[o + 1] * sa
                    b += src[o + 2] * sa
                    a += sa
                    n += 1
            o = 4 * (dy * dst_size + dx)
            if n == 0 or a <= 0.0:
                continue
            out[o] = int(r / a + 0.5)
            out[o + 1] = int(g / a + 0.5)
            out[o + 2] = int(b / a + 0.5)
            out[o + 3] = int(a / n * 255 + 0.5)
    return bytes(out)


def png(rgba: bytes, size: int) -> bytes:
    raw = bytearray()
    stride = 4 * size
    for row in range(size):
        raw.append(0)  # filter: none
        raw += rgba[row * stride:(row + 1) * stride]

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def png_size(path: Path) -> int:
    return struct.unpack(">I", path.read_bytes()[16:20])[0]


def ico(pyramid, sizes) -> bytes:
    """A PNG-in-ICO container. Windows is not a build target today; the file
    exists so a blank one cannot ship if it becomes one."""
    entries, blobs, offset = b"", b"", 6 + 16 * len(sizes)
    for s in sizes:
        data = png(pyramid[s], s)
        entries += struct.pack("<BBBBHHII", s if s < 256 else 0, s if s < 256 else 0,
                               0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return struct.pack("<HHH", 0, 1, len(sizes)) + entries + blobs


MASTER = 1024
PYRAMID_SIZES = (1024, 512, 256, 128, 64, 32, 16)

# The .iconset names iconutil expects. Each maps to one icns entry type.
ICONSET = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
]


def main() -> int:
    print(f"drawing {MASTER}x{MASTER}…", flush=True)
    master = render(MASTER)

    pyramid = {MASTER: master}
    for s in PYRAMID_SIZES:
        if s != MASTER:
            pyramid[s] = resample(master, MASTER, s)

    def at(size: int) -> bytes:
        if size in pyramid:
            return pyramid[size]
        src = min((s for s in PYRAMID_SIZES if s >= size), default=MASTER)
        pyramid[size] = resample(pyramid[src], src, size)
        return pyramid[size]

    # Every PNG already in this tree, regenerated at its own size. Keeps the
    # Windows/Android/iOS sets in step with the one that ships today without
    # this script needing to know their naming conventions.
    pngs = sorted(HERE.rglob("*.png"))
    for path in pngs:
        size = png_size(path)
        path.write_bytes(png(at(size), size))
        print(f"  {path.relative_to(HERE)}  {size}x{size}")
    if not (HERE / "icon.png").exists():
        (HERE / "icon.png").write_bytes(png(at(512), 512))

    (HERE / "icon.ico").write_bytes(ico(pyramid, (16, 32, 48, 64, 128, 256)))
    print("  icon.ico")

    # iconutil is macOS's own icns assembler. Using it means the container is
    # never this script's opinion of the format.
    if not shutil.which("iconutil"):
        print("iconutil not found — icon.icns NOT regenerated", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "icon.iconset"
        iconset.mkdir()
        for name, size in ICONSET:
            (iconset / name).write_bytes(png(at(size), size))
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(HERE / "icon.icns")],
            check=True,
        )
    print(f"  icon.icns  ({(HERE / 'icon.icns').stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
