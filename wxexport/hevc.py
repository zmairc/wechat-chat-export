"""处理微信的 `wxgf` 图片：抽出其中的 HEVC 码流，可选用 ffmpeg 转成 JPG。

微信 4.x 里一部分「图片」其实是 HEVC 封装的动图/原图，解密后的文件以 `wxgf`
开头，后面跟一段标准的 H.265 Annex-B 码流（起点是 VPS，NAL 类型 32）。
浏览器不认识这个格式，所以要：

1. **抽流**（本模块自己实现，零依赖）：从第一个 VPS 起始码开始截断，
   得到播放器能直接打开的 `.h265`；
2. **转码**（可选）：本机有 ffmpeg 就把首帧转成 JPG，没有就只做第 1 步。

ffmpeg 不是运行本工具的前提——没有它照样能导出，只是 HTML 里显示缩略图 + 原图下载。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

START_CODE = b"\x00\x00\x00\x01"
NAL_VPS = 32

# 不在系统 PATH 里时，往这些地方找一找
_COMMON_PATHS = (
    r"C:\ffmpeg\bin\ffmpeg.exe",
    r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
    r"C:\ProgramData\chocolatey\bin\ffmpeg.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links\ffmpeg.exe"),
    os.path.expandvars(r"%USERPROFILE%\scoop\shims\ffmpeg.exe"),
)

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_cache: dict[str, str | None] = {}


def extract_stream(blob: bytes) -> bytes | None:
    """从 `wxgf` 容器里截出 Annex-B 的 HEVC 码流。

    返回的内容以 `00 00 00 01 40 01`（layer 0 的 VPS）开头，可以直接存成 `.h265`
    交给播放器。少数文件在真正 VPS 之前还有一段 header 字节恰好长得像
    「起始码 + NAL 32」，所以优先挑第二字节为 0x01 的那个 VPS，
    实在没有才退回第一个。找不到就返回 None，让调用方保留原文件。
    """
    if not blob:
        return None
    if not blob.startswith(b"wxgf"):
        # 已经是裸码流就直接用
        return blob if blob.startswith(START_CODE) else None

    fallback = None
    pos = 0
    while True:
        i = blob.find(START_CODE, pos)
        if i < 0:
            return fallback
        if i + 6 <= len(blob) and (blob[i + 4] >> 1) & 0x3F == NAL_VPS:
            if blob[i + 5] == 0x01:        # nuh_layer_id == 0，正常的 VPS
                return blob[i:]
            if fallback is None:
                fallback = blob[i:]
        pos = i + 4


def find_ffmpeg(explicit: str | None = None) -> str | None:
    """找一个可用的 ffmpeg，找不到返回 None（不影响导出，只是不转码）。"""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    candidates.append(os.environ.get("WXEXPORT_FFMPEG") or "")
    # 允许把 ffmpeg.exe 放在本项目的 tools/ 下随包分发
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(here, "tools", "ffmpeg.exe"))
    found = shutil.which("ffmpeg")
    if found:
        candidates.append(found)
    candidates.extend(_COMMON_PATHS)

    for path in candidates:
        if not path:
            continue
        key = path.lower()
        if key in _cache:
            if _cache[key]:
                return _cache[key]
            continue
        if os.path.isfile(path) and os.access(path, os.X_OK):
            _cache[key] = path
            return path
        _cache[key] = None
    return None


def to_jpeg(ffmpeg: str, stream: bytes, timeout: int = 40) -> bytes | None:
    """把 HEVC 码流的首帧转成 JPEG（走管道，不留临时文件）。"""
    if not stream:
        return None
    cmd = [
        ffmpeg, "-hide_banner", "-loglevel", "error",
        "-f", "hevc", "-i", "pipe:0",
        "-frames:v", "1", "-q:v", "3",
        "-f", "mjpeg", "pipe:1",
    ]
    try:
        proc = subprocess.run(
            cmd, input=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, creationflags=_CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = proc.stdout or b""
    if proc.returncode == 0 and out.startswith(b"\xff\xd8\xff"):
        return out
    return None


def describe(ffmpeg: str | None) -> str:
    if ffmpeg:
        return f"ffmpeg 已就绪（{ffmpeg}），HEVC 图片会转成 JPG"
    return "没找到 ffmpeg：HEVC 图片仍会解出原图码流并配缩略图，只是不转 JPG"
