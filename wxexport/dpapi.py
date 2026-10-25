"""用 Windows 自带的 DPAPI 加密本地缓存（`work\\keys_*.json`）。

数据库密钥按库缓存下来，之后不开微信也能重复导出——但之前是明文十六进制，
文件一旦被拷走就等于把密钥送出去了。DPAPI（`CryptProtectData`）能把它绑到
**当前用户 + 当前机器**：换个账户或换台机器都解不开，且不需要任何第三方库。

非 Windows 或调用失败时返回 None，调用方回退到不加密（功能不受影响）。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os

CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    return os.name == "nt"


def _to_blob(data: bytes):
    """把 bytes 包成 DATA_BLOB，同时把底层缓冲区一起返回（防止被提前回收）。"""
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _read_blob(blob: _Blob) -> bytes:
    if not blob.pbData or not blob.cbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def protect(data: bytes, entropy: bytes | None = None) -> bytes | None:
    """加密。失败返回 None（调用方应回退到不加密存储）。"""
    if not available() or not data:
        return None
    crypt32 = ctypes.WinDLL("crypt32")
    kernel32 = ctypes.WinDLL("kernel32")
    blob_in, _buf_in = _to_blob(data)
    blob_out = _Blob()
    ent_in, _buf_ent = (_to_blob(entropy) if entropy else (None, None))

    ok = crypt32.CryptProtectData(
        ctypes.byref(blob_in), "wxexport", ctypes.byref(ent_in) if ent_in else None,
        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        return None
    try:
        return _read_blob(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def unprotect(blob: bytes, entropy: bytes | None = None) -> bytes | None:
    """解密。换了账户/机器会失败，返回 None 让调用方当成“没有缓存”。"""
    if not available() or not blob:
        return None
    crypt32 = ctypes.WinDLL("crypt32")
    kernel32 = ctypes.WinDLL("kernel32")
    blob_in, _buf_in = _to_blob(blob)
    blob_out = _Blob()
    ent_in, _buf_ent = (_to_blob(entropy) if entropy else (None, None))

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, ctypes.byref(ent_in) if ent_in else None,
        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        return None
    try:
        return _read_blob(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)
