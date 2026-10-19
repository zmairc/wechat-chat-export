"""在微信进程内存里找"媒体密钥"（AES-128，图片 .dat 用）。

微信 4.x 的图片 .dat（V2 格式）前 1024 字节是 AES-128-ECB 加密的，密钥只在
进程内存里以裸 16 字节形式存在（不是十六进制字符串），所以只能扫描内存并用
"AES 解密后是否是 JPEG/PNG 文件头"来验证。

单次候选验证要走两次 CNG 调用（建 key + 解密一个 block），ctypes 调用期间会
释放 GIL，所以用线程池就能真正并行。
"""

from __future__ import annotations

import ctypes
import hmac
import struct
import threading
import time
import ctypes.wintypes as wt

BLOCK = 16

MAGICS = (
    b"\xff\xd8\xff",      # jpeg
    b"\x89PNG",           # png
    b"GIF8",              # gif
    b"BM",                # bmp（2 字节，另有额外校验）
    b"RIFF",              # webp
    b"wxgf",              # 微信自家 hevc 容器
)


class _Probe:
    """一个进程内复用的 AES-128-ECB 单块解密探针。"""

    def __init__(self):
        bcrypt = ctypes.WinDLL("bcrypt")
        self._bcrypt = bcrypt
        bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
        bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), wt.LPCWSTR, wt.LPCWSTR, wt.ULONG]
        bcrypt.BCryptSetProperty.restype = ctypes.c_long
        bcrypt.BCryptSetProperty.argtypes = [
            ctypes.c_void_p, wt.LPCWSTR, ctypes.c_char_p, wt.ULONG, wt.ULONG]
        bcrypt.BCryptGenerateSymmetricKey.restype = ctypes.c_long
        bcrypt.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            wt.ULONG, ctypes.c_char_p, wt.ULONG, wt.ULONG]
        bcrypt.BCryptDecrypt.restype = ctypes.c_long
        bcrypt.BCryptDecrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, wt.ULONG, ctypes.c_void_p,
            ctypes.c_char_p, wt.ULONG, ctypes.c_char_p, wt.ULONG,
            ctypes.POINTER(wt.ULONG), wt.ULONG]
        bcrypt.BCryptDestroyKey.restype = ctypes.c_long
        bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]

        alg = ctypes.c_void_p()
        if bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0):
            raise OSError("BCryptOpenAlgorithmProvider failed")
        mode = "ChainingModeECB".encode("utf-16-le")
        if bcrypt.BCryptSetProperty(alg, "ChainingMode", mode, len(mode), 0):
            raise OSError("BCryptSetProperty(ECB) failed")
        self._alg = alg
        self._hkey = ctypes.c_void_p()
        self._out = ctypes.create_string_buffer(BLOCK)
        self._outlen = wt.ULONG(0)

    def decrypt_block(self, key: bytes, block: bytes) -> bytes | None:
        if self._bcrypt.BCryptGenerateSymmetricKey(
                self._alg, ctypes.byref(self._hkey), None, 0, key, 16, 0):
            return None
        try:
            st = self._bcrypt.BCryptDecrypt(
                self._hkey, block, BLOCK, None, None, 0,
                self._out, BLOCK, ctypes.byref(self._outlen), 0)
            if st:
                return None
            return self._out.raw[:BLOCK]
        finally:
            self._bcrypt.BCryptDestroyKey(self._hkey)


def _looks_like_image(b: bytes) -> bool:
    if b.startswith(b"\xff\xd8\xff") or b.startswith(b"\x89PNG") or b.startswith(b"GIF8"):
        return True
    if b.startswith(b"RIFF") or b.startswith(b"wxgf"):
        return True
    return False


def check_key(probe: _Probe, key: bytes, blocks: list[bytes]) -> bool:
    for blk in blocks:
        dec = probe.decrypt_block(key, blk)
        if dec is None:
            continue
        if _looks_like_image(dec):
            return True
        # 有些图片会先做一次单字节 XOR
        for k in (dec[0],):
            if _looks_like_image(bytes(x ^ k for x in dec[:6])):
                return True
    return False


def find_media_key(pid: int, target_blocks: list[bytes], stride: int = 4,
                   threads: int = 0, progress=None, should_stop=None,
                   time_budget: float | None = None):
    """返回 (key_bytes, address) 或 (None, None)。"""
    from .keyscan import MemoryScanner

    scanner = MemoryScanner(pid)
    regions = list(scanner.regions())
    total = sum(s for _, s in regions)
    chunk = 8 * 1024 * 1024
    tasks = []
    for base, size in regions:
        off = 0
        while off < size:
            n = min(chunk, size - off)
            tasks.append((base + off, n))
            off += n
    tasks = [t for t in tasks if t[1] > stride]

    lock = threading.Lock()
    found = [None, None]
    done = [0]
    t0 = time.time()
    stop = threading.Event()
    if threads <= 0:
        threads = min(16, max(4, (__import__("os").cpu_count() or 4)))

    local = threading.local()

    def worker():
        probe = _Probe()
        while not stop.is_set():
            with lock:
                if not tasks:
                    return
                base, size = tasks.pop()
            data = scanner.read(base, size)
            if not data:
                with lock:
                    done[0] += size
                continue
            limit = len(data) - BLOCK
            i = 0
            while i <= limit:
                if should_stop and should_stop():
                    stop.set()
                    return
                key = data[i:i + BLOCK]
                if check_key(probe, key, target_blocks):
                    with lock:
                        if found[0] is None:
                            found[0] = key
                            found[1] = base + i
                            stop.set()
                    return
                i += stride
            with lock:
                done[0] += size
            if time_budget and time.time() - t0 > time_budget:
                stop.set()
                return
            if progress:
                progress(done[0], total, t0)

    pool = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    scanner.close()
    return found[0], found[1]
