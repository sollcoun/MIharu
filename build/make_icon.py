"""Rebuild assets/logo.ico with multiple sizes for Windows shell."""
from __future__ import annotations

import struct
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    raise SystemExit("pip install pillow")


def _png_bytes(img: Image.Image) -> bytes:
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def write_ico(path: Path, images: list[Image.Image]) -> None:
    """Write a multi-size ICO with PNG-compressed frames (Vista+)."""
    frames: list[tuple[int, int, bytes]] = []
    for im in images:
        w, h = im.size
        data = _png_bytes(im)
        frames.append((w, h, data))

    # ICONDIR + ICONDIRENTRY * n + image data
    count = len(frames)
    header = struct.pack("<HHH", 0, 1, count)
    entries = []
    offset = 6 + 16 * count
    body = b""
    for w, h, data in frames:
        # 0 means 256 in ICONDIRENTRY
        bw = 0 if w >= 256 else w
        bh = 0 if h >= 256 else h
        entries.append(struct.pack(
            "<BBBBHHII",
            bw, bh,
            0,  # color palette
            0,  # reserved
            1,  # planes
            32,  # bitcount
            len(data),
            offset,
        ))
        body += data
        offset += len(data)

    path.write_bytes(header + b"".join(entries) + body)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    assets = root / "assets"
    candidates = [
        assets / "logo_source.png",
        assets / "logo.png",
        assets / "logo_64.png",
    ]
    src = next((p for p in candidates if p.exists() and p.stat().st_size > 2000), None)
    if src is None:
        raise SystemExit(f"No suitable PNG in {assets}")

    out = assets / "logo.ico"
    im = Image.open(src).convert("RGBA")
    print(f"source: {src}  size={im.size}  file={src.stat().st_size} bytes")

    # Max dimension for shell icons
    base = im.copy()
    base.thumbnail((256, 256), Image.Resampling.LANCZOS)

    sizes = [16, 32, 48, 64, 128, 256]
    images: list[Image.Image] = []
    for s in sizes:
        canvas = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        layer = base.copy()
        layer.thumbnail((s, s), Image.Resampling.LANCZOS)
        x = (s - layer.width) // 2
        y = (s - layer.height) // 2
        canvas.paste(layer, (x, y), layer)
        images.append(canvas)

    write_ico(out, images)
    nbytes = out.stat().st_size
    print(f"wrote {out}  {nbytes} bytes")
    if nbytes < 5000:
        raise SystemExit("ERROR: ico still too small")
    print("OK: multi-size ico ready")


if __name__ == "__main__":
    main()