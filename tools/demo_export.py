r"""生成一份**完全虚构**的演示导出，用来截 README 截图 / 调样式。

不会读微信、不联网、不碰任何真实聊天记录——数据全部写在这个文件里。
生成的页面和真实导出（`chat.html`）走同一套渲染代码，所以看起来是一样的。

用法：

```bash
python tools/demo_export.py                  # 输出到 docs/demo/
python tools/demo_export.py --out D:\tmp\demo
```

截图（Windows 自带 Edge）：

```bash
"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" ^
  --headless=new --disable-gpu --hide-scrollbars --window-size=1280,860 ^
  --screenshot=docs/screenshot.png "file:///E:/zmairc/wxoutput/docs/demo/chat.html"
```
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wxexport import exporter  # noqa: E402


def _png(width: int, height: int) -> bytes:
    """手搓一张渐变 PNG（演示用，避免依赖 Pillow）。"""
    rows = []
    for y in range(height):
        row = bytearray(b"\x00")
        for x in range(width):
            row += bytes((60 + x * 120 // width, 110 + y * 90 // height, 190))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def _entries() -> list[dict]:
    def e(day: str, hm: str, sender: str, text: str, kind: str = "text",
          is_self: bool = False, quote: str = "", media: list | None = None) -> dict:
        dt = datetime.strptime(f"{day} {hm}", "%Y-%m-%d %H:%M")
        return {"time": int(dt.timestamp()), "dt": dt, "sender": sender,
                "is_self": is_self, "kind": kind, "text": text,
                "quote": quote, "media": media or []}

    return [
        e("2026-10-18", "09:12", "", "你已添加了小林，现在可以开始聊天了。", kind="system"),
        e("2026-10-18", "09:13", "小林", "早，昨天的会议纪要发我一份？"),
        e("2026-10-18", "09:13", "我", "在整理，十分钟后给你。", is_self=True),
        e("2026-10-18", "09:21", "我", "好了，一共改了四处。", is_self=True,
          media=[{"kind": "file", "path": "media/00001_会议纪要.txt",
                  "name": "会议纪要.txt", "size": 2048}]),
        e("2026-10-18", "14:02", "小林", "现场照片，你可以参考下这个布局。",
          kind="image",
          media=[{"kind": "image", "path": "media/00002_现场.png", "decoded": True, "ext": "png"}]),
        e("2026-10-18", "14:25", "我", "这个布局可以，采光比上次那版好。", is_self=True),
    ]


def build(out_dir: str) -> str:
    media_dir = os.path.join(out_dir, "media")
    os.makedirs(media_dir, exist_ok=True)
    with open(os.path.join(media_dir, "00002_现场.png"), "wb") as f:
        f.write(_png(300, 160))
    with open(os.path.join(media_dir, "00001_会议纪要.txt"), "w", encoding="utf-8") as f:
        f.write("演示用附件，内容无关紧要。\n")

    entries = _entries()
    first = entries[0]["dt"].strftime("%Y-%m-%d")
    last = entries[-1]["dt"].strftime("%Y-%m-%d")
    path = os.path.join(out_dir, "chat.html")
    exporter.write_html(
        entries,
        "与小林的聊天记录（演示数据）",
        f"{len(entries)} 条 · {first} ~ {last} · 导出于 2026-10-25 14:30",
        path,
    )
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="生成虚构的演示导出（不读微信）")
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "demo"))
    args = ap.parse_args(argv)
    path = build(args.out)
    print(f"演示页面：{path}")
    print("注意：里面全是假数据，可以放心截图。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
