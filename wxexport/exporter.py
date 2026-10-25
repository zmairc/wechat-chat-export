"""把一段聊天记录导出成 HTML（可搜索、可打印）和 TXT。"""

from __future__ import annotations

import html
import os
import time
from datetime import datetime
from typing import Iterable

from . import wxmsg

TXT_SEP = "=" * 60


def _dt(ts: int) -> datetime:
    try:
        return datetime.fromtimestamp(int(ts))
    except (OverflowError, OSError, ValueError):
        return datetime(1970, 1, 1)


def _fmt_size(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return ""


def build_entries(store, item: dict, media=None, include_media: bool = True) -> list[dict]:
    """把消息渲染成导出用的条目列表。"""
    is_room = item["username"].endswith("@chatroom")
    msgs = store.messages(item)
    chat_hash = item["hash"]
    entries = []
    for m in msgs:
        r = wxmsg.render(m, is_chatroom=is_room)
        dt = _dt(m["time"])
        sender = store.display_name(m["sender"]) if m["sender"] else (
            store.display_name_self() if m["is_self"] else store.display_name(item["username"]))
        if m["is_self"]:
            sender = "我"
        month = dt.strftime("%Y-%m")
        media_files = []
        if include_media and media is not None:
            for md in r.get("media", []):
                if md["type"] == "image":
                    got = media.export_image(chat_hash, m.get("md5") or md.get("md5", ""), month)
                    if got.get("path"):
                        media_files.append({"kind": "image", "path": got["path"],
                                            "decoded": got.get("decoded", False),
                                            "ext": got.get("ext", "")})
                elif md["type"] == "file":
                    p = media.export_file(chat_hash, m.get("md5", ""), month,
                                          md.get("name", ""), md.get("size"))
                    if p:
                        media_files.append({"kind": "file", "path": p,
                                            "name": md.get("name", ""), "size": md.get("size")})
                elif md["type"] == "link":
                    media_files.append({"kind": "link", "url": md.get("url", ""),
                                        "title": md.get("title", "")})
        if include_media and media is not None and m["type"] == 43:
            got = media.export_video(chat_hash, m.get("md5", ""), month)
            if got:
                media_files.append({"kind": "video", "path": got["path"],
                                    "thumb_only": got.get("thumb_only", False)})
        entries.append({
            "time": m["time"],
            "dt": dt,
            "sender": sender,
            "is_self": m["is_self"],
            "kind": r["kind"],
            "text": r["text"],
            "quote": r.get("quote", ""),
            "media": media_files,
        })
    return entries


# ------------------------------------------------------------------- TXT

def write_txt(entries: list[dict], title: str, subtitle: str, path: str) -> None:
    lines = [TXT_SEP, title, subtitle, TXT_SEP, ""]
    last_date = None
    for e in entries:
        d = e["dt"].strftime("%Y-%m-%d")
        if d != last_date:
            lines.append("")
            lines.append(f"---------- {d} ----------")
            lines.append("")
            last_date = d
        head = e["dt"].strftime("%H:%M:%S")
        if e["kind"] == "system":
            lines.append(f"[{head}] · {e['text']}")
            lines.append("")
            continue
        who = e["sender"] or ("我" if e["is_self"] else "")
        text = e["text"]
        if e.get("quote"):
            text = f"「引用：{e['quote']}」\n{text}"
        media_note = []
        for m in e.get("media", []):
            if m["kind"] == "image":
                if m["decoded"]:
                    media_note.append(m["path"])
                elif m.get("ext") == "hevc":
                    media_note.append(f"{m['path']}（HEVC 封装原图，已解密保存）")
                else:
                    media_note.append(f"{m['path']}（微信加密格式，需密钥；可在微信里另存为原图）")
            elif m["kind"] == "file":
                media_note.append(f"附件：{m.get('name','')} -> {m['path']}")
            elif m["kind"] == "video":
                note = f"视频：{m['path']}"
                if m.get("thumb_only"):
                    note += "（仅封面）"
                media_note.append(note)
            elif m["kind"] == "link":
                media_note.append(f"链接：{m['url']}")
        if media_note:
            text = text + "\n" + "\n".join(media_note)
        body = "\n".join("    " + ln for ln in text.splitlines()) if "\n" in text else text
        lines.append(f"[{head}] {who}:")
        lines.append(f"    {body}" if "\n" not in text else body)
        lines.append("")
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines))


# ------------------------------------------------------------------ HTML

_CSS = """
:root{--bg:#f2f2f2;--card:#fff;--self:#95ec69;--other:#fff;--text:#1a1a1a;--muted:#8a8a8a;--line:#e3e3e3}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:var(--text)}
header{position:sticky;top:0;z-index:10;background:#fff;border-bottom:1px solid var(--line);padding:10px 16px;
  display:flex;flex-wrap:wrap;gap:12px;align-items:center;box-shadow:0 1px 4px rgba(0,0,0,.05)}
header h1{font-size:16px;margin:0;font-weight:600}
header .meta{color:var(--muted);font-size:12px}
header input{padding:6px 10px;border:1px solid var(--line);border-radius:16px;min-width:200px;outline:none}
header label{font-size:12px;color:var(--muted);display:flex;gap:4px;align-items:center;cursor:pointer}
#count{font-size:12px;color:var(--muted)}
main{max-width:900px;margin:0 auto;padding:16px 12px 60px}
.day{text-align:center;margin:22px 0 10px}
.day span{background:#dadada;color:#fff;font-size:12px;padding:2px 10px;border-radius:10px}
.row{display:flex;margin:10px 0;gap:8px}
.row.self{flex-direction:row-reverse}
.avatar{width:34px;height:34px;border-radius:4px;background:#c9c9c9;color:#fff;display:flex;
  align-items:center;justify-content:center;font-size:13px;flex:0 0 34px;user-select:none}
.bubble{max-width:min(78%,620px);background:var(--other);border-radius:8px;padding:8px 11px;
  box-shadow:0 1px 2px rgba(0,0,0,.05);white-space:pre-wrap;word-break:break-word;position:relative}
.row.self .bubble{background:var(--self)}
.bubble .who{font-size:12px;color:var(--muted);margin-bottom:2px}
.bubble .t{font-size:11px;color:var(--muted);margin-top:4px;text-align:right}
.bubble img{max-width:100%;max-height:420px;border-radius:6px;display:block;margin:4px 0;cursor:zoom-in}
.bubble .quote{border-left:3px solid #cfcfcf;background:rgba(0,0,0,.04);padding:4px 8px;margin:2px 0 6px;
  border-radius:4px;color:#555;font-size:13px;white-space:pre-wrap}
.bubble a.file{display:inline-flex;gap:6px;align-items:center;background:#eef3ff;color:#20489c;
  padding:6px 10px;border-radius:6px;text-decoration:none;margin:4px 0;font-size:13px}
.bubble a.video{color:#20489c}
.sys{text-align:center;margin:12px 0}
.sys span{display:inline-block;background:#e8e8e8;color:#777;font-size:12px;padding:3px 10px;border-radius:10px}
.raw{font-size:12px;color:#9a6a00;background:#fff7e0;padding:4px 8px;border-radius:4px;margin-top:4px}
.hidden{display:none}
footer{color:var(--muted);text-align:center;font-size:12px;padding:24px}
@media print{header{position:static;box-shadow:none}header input,header label{display:none}body{background:#fff}}
"""

_JS = """
const q = document.getElementById('q');
const onlyImg = document.getElementById('onlyImg');
const rows = Array.from(document.querySelectorAll('.row, .sys'));
const countEl = document.getElementById('count');
function apply(){
  const kw = (q.value||'').trim().toLowerCase();
  let n = 0;
  for (const r of rows){
    let ok = true;
    if (kw) ok = (r.dataset.text||'').includes(kw);
    if (ok && onlyImg.checked) ok = r.dataset.img === '1';
    r.classList.toggle('hidden', !ok);
    if (ok) n++;
  }
  countEl.textContent = '显示 ' + n + ' / ' + rows.length + ' 条';
}
q.addEventListener('input', apply);
onlyImg.addEventListener('change', apply);
document.querySelectorAll('.bubble img').forEach(img=>{
  img.addEventListener('click', ()=>window.open(img.src, '_blank'));
  img.addEventListener('error', ()=>{img.style.display='none';});
});
apply();
"""


def _esc(s: str) -> str:
    return html.escape(s or "", quote=False)


def _initial(name: str) -> str:
    name = (name or "").strip()
    return name[:1].upper() if name else "?"


def write_html(entries: list[dict], title: str, subtitle: str, path: str) -> None:
    parts = [
        "<!DOCTYPE html>",
        '<html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{_esc(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head><body>",
        "<header>",
        f"<h1>{_esc(title)}</h1>",
        f'<span class="meta">{_esc(subtitle)}</span>',
        '<input id="q" type="search" placeholder="搜索聊天内容…">',
        '<label><input id="onlyImg" type="checkbox">只看带图片的</label>',
        '<span id="count"></span>',
        "</header>",
        "<main>",
    ]
    last_date = None
    for e in entries:
        d = e["dt"].strftime("%Y-%m-%d")
        if d != last_date:
            parts.append(f'<div class="day"><span>{d}</span></div>')
            last_date = d
        t = e["dt"].strftime("%H:%M")
        text = _esc(e["text"])
        has_img = any(m["kind"] == "image" for m in e.get("media", []))
        search_text = f"{e['sender']} {e['text']}".lower()

        if e["kind"] == "system":
            parts.append(
                f'<div class="sys" data-text="{html.escape(search_text)}">'
                f"<span>{text}</span></div>"
            )
            continue

        inner = []
        if e.get("quote"):
            inner.append(f'<div class="quote">{_esc(e["quote"])}</div>')
        inner.append(f'<div class="txt">{text}</div>')
        for m in e.get("media", []):
            if m["kind"] == "image":
                if m["decoded"]:
                    inner.append(
                        f'<a href="{html.escape(m["path"])}" target="_blank">'
                        f'<img src="{html.escape(m["path"])}" loading="lazy" alt="图片"></a>'
                    )
                elif m.get("ext") == "hevc":
                    inner.append(
                        f'<div class="raw">原图（微信 HEVC 封装，浏览器预览不了，已解密保存）：'
                        f'<a href="{html.escape(m["path"])}" target="_blank">下载原文件</a></div>'
                    )
                else:
                    inner.append(
                        f'<div class="raw">图片是微信 4.x 的加密格式，需要密钥才能还原。'
                        f'<a href="{html.escape(m["path"])}" target="_blank">下载 .dat 原文件</a>'
                        f'　想在微信里看原件：点开图片 → 右键「另存为」。</div>'
                    )
            elif m["kind"] == "video":
                label = "🎬 打开视频（仅封面）" if m.get("thumb_only") else "🎬 打开视频"
                inner.append(
                    f'<div><a class="video" href="{html.escape(m["path"])}" target="_blank">'
                    f"{label}</a></div>"
                )
            elif m["kind"] == "file":
                size = _fmt_size(m.get("size"))
                label = f'📎 {_esc(m.get("name","附件"))}'
                if size:
                    label += f"（{size}）"
                inner.append(
                    f'<div><a class="file" href="{html.escape(m["path"])}" target="_blank">'
                    f"{label}</a></div>"
                )
            elif m["kind"] == "link" and m.get("url"):
                inner.append(
                    f'<div><a class="file" href="{html.escape(m["url"])}" target="_blank">'
                    f"🔗 {_esc(m.get('title') or m['url'])}</a></div>"
                )

        side = "self" if e["is_self"] else "other"
        parts.append(
            f'<div class="row {side}" data-text="{html.escape(search_text)}" '
            f'data-img="{1 if has_img else 0}">'
            f'<div class="avatar">{_esc(_initial(e["sender"]))}</div>'
            f'<div class="bubble"><div class="who">{_esc(e["sender"])}</div>'
            + "".join(inner)
            + f'<div class="t">{t}</div></div></div>'
        )

    parts += [
        "</main>",
        '<footer>由「微信聊天记录一键导出」生成 · 数据仅保存在本机</footer>',
        f"<script>{_JS}</script>",
        "</body></html>",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
