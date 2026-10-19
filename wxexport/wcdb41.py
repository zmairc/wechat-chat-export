"""微信 4.1+ 的密钥获取。

4.1 之后微信不再把可用的数据库密钥以明文 `x'<hex>'` 缓存在内存里（老办法失效），
但 WCDB 的 `com.Tencent.WCDB.Config.Cipher` 配置对象里仍然留着一份经过固定
字节掩码混淆的 `x'<64hex 密钥><32hex salt>'` 字符串。本模块按"字符串 →
引用节点 → 配置对象 → 混淆 blob → 解混淆 → 正则"的顺序把它读出来，
再用 page1 的 HMAC 校验，只有校验通过才算数。

整个过程是**只读**的：只调用 ReadProcessMemory，不注入、不改内存、不 hook。
"""

from __future__ import annotations

import re
import struct
import time

from .keyscan import MemoryScanner

NEEDLE = b"com.Tencent.WCDB.Config.Cipher"
# Config.Cipher blob 的固定混淆掩码（21 字节，循环异或）
BLOB_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{96,256})'")
MAX_USER_ADDR = 0x0000_8000_0000_0000
BLOB_MAX = 4096

# 结构体偏移（4.1.x 实测）：node 里 0x10 是字符串指针，0x18 是长度，
# 0x28 是配置对象指针；配置对象 +0x88 处是个 {ptr,len} 的 string_view。
NODE_STR_PTR = 0x10
NODE_STR_LEN = 0x18
NODE_CONFIG_PTR = 0x28
CFG_BLOB_VIEW = 0x88
VIEW_PTR = 0x08
VIEW_LEN = 0x10


def _u64(data: bytes, off: int) -> int:
    if off < 0 or off + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, off)[0]


def unxor(blob: bytes) -> bytes:
    mask = BLOB_XOR_MASK
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(blob))


def _plausible_key(k: bytes) -> bool:
    return len(k) == 32 and len(set(k)) >= 15


def _decode_blob(blob: bytes):
    """从配置 blob 里解析出 (key_hex, salt_hex) 候选。"""
    out = []
    for decoded in (unxor(blob), blob):
        for m in LITERAL_RE.finditer(decoded):
            run = m.group(1).decode("ascii").lower()
            starts = {0}
            for s in range(0, max(1, len(run) - 63), 32):
                starts.add(s)
            starts.add(max(0, len(run) - 64))
            for s in starts:
                key_hex = run[s:s + 64]
                if len(key_hex) < 64:
                    continue
                try:
                    key = bytes.fromhex(key_hex)
                except ValueError:
                    continue
                if not _plausible_key(key):
                    continue
                salt_hex = run[s + 64:s + 96] if len(run) >= s + 96 else None
                item = (key_hex, salt_hex)
                if item not in out:
                    out.append(item)
    return out


def scan_config_cipher(scanner: MemoryScanner, progress=None) -> dict:
    """返回 {'candidates': [(key_hex, salt_hex|None)], 'stats': {...}}"""
    stats = {
        "needle": 0,
        "refs": 0,
        "nodes": 0,
        "config_ptrs": 0,
        "blobs": 0,
        "candidates": 0,
    }
    t0 = time.time()
    needle_addrs = set()
    for base, size in scanner.regions():
        off = 0
        while off < size:
            n = min(16 * 1024 * 1024, size - off)
            data = scanner.read(base + off, n)
            if data:
                i = -1
                while True:
                    i = data.find(NEEDLE, i + 1)
                    if i < 0:
                        break
                    needle_addrs.add(base + off + i)
            off += n
    stats["needle"] = len(needle_addrs)
    if not needle_addrs:
        return {"candidates": [], "stats": stats, "elapsed": time.time() - t0}

    pairs = [
        (struct.pack("<Q", a) + struct.pack("<Q", len(NEEDLE)), a) for a in needle_addrs
    ]
    candidates: list[tuple[str, str | None]] = []
    seen_cfg: set[int] = set()

    for base, size in scanner.regions():
        off = 0
        while off < size:
            n = min(16 * 1024 * 1024, size - off)
            data = scanner.read(base + off, n)
            if not data:
                off += n
                continue
            for pattern, needle_addr in pairs:
                pos = -1
                while True:
                    pos = data.find(pattern, pos + 1)
                    if pos < 0:
                        break
                    stats["refs"] += 1
                    qaddr = base + off + pos
                    node = scanner.read(qaddr - 0x10, 0x60)
                    if not node or len(node) < 0x40:
                        continue
                    if _u64(node, NODE_STR_PTR) != needle_addr:
                        continue
                    if _u64(node, NODE_STR_LEN) != len(NEEDLE):
                        continue
                    cfg = _u64(node, NODE_CONFIG_PTR)
                    if not (0x10000 <= cfg < MAX_USER_ADDR):
                        continue
                    stats["nodes"] += 1
                    seen_cfg.add(cfg)
                    obj = scanner.read(cfg + CFG_BLOB_VIEW, 0x28)
                    if not obj or len(obj) < 0x18:
                        continue
                    ptr = _u64(obj, VIEW_PTR)
                    ln = _u64(obj, VIEW_LEN)
                    if not (0 < ln <= BLOB_MAX) or not (0x10000 <= ptr < MAX_USER_ADDR):
                        continue
                    blob = scanner.read(ptr, int(ln))
                    if not blob:
                        continue
                    stats["blobs"] += 1
                    for item in _decode_blob(blob):
                        if item not in candidates:
                            candidates.append(item)
                            stats["candidates"] += 1
            off += n
        if progress:
            progress(len(seen_cfg), len(candidates))

    stats["config_ptrs"] = len(seen_cfg)
    return {
        "candidates": candidates,
        "stats": stats,
        "elapsed": time.time() - t0,
    }
