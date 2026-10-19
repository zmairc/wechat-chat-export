"""从微信进程内存里找到各个数据库的密钥。

WCDB 会把每个数据库的 raw key 以 ASCII 形式缓存成：
    x'<64 位十六进制密钥><32 位十六进制 salt>'
salt 就是 db 文件开头 16 字节的 hex，因此可以用 salt 直接定位是哪个库，
再用 page1 的 HMAC 校验密钥是否真的正确（避免误判）。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import sys
import time

from .sqlcipher import PAGE_SZ, SALT_SZ, verify_key, read_page1_shared

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.c_void_p]
kernel32.Process32NextW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.c_void_p]

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
READABLE_PROTECT = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
MAX_REGION = 512 * 1024 * 1024


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


def list_processes(names=("Weixin.exe", "WeChat.exe")) -> list[tuple[int, str]]:
    out = []
    TH32CS_SNAPPROCESS = 0x00000002
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1, None):
        return out
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() in {n.lower() for n in names}:
                out.append((int(entry.th32ProcessID), entry.szExeFile))
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return out


HEX_RE = re.compile(rb"x'([0-9a-fA-F]{64,256})'")


class MemoryScanner:
    def __init__(self, pid: int):
        self.pid = pid
        self.h = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not self.h:
            raise OSError(
                f"无法打开进程 {pid}（错误码 {ctypes.get_last_error()}）。"
                "请用与微信相同的用户身份运行，或尝试以管理员身份运行。"
            )

    def close(self):
        if self.h:
            kernel32.CloseHandle(self.h)
            self.h = None

    def regions(self):
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        limit = 0x7FFFFFFFFFFF
        while addr < limit:
            got = kernel32.VirtualQueryEx(
                self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not got:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)
            if (
                mbi.State == MEM_COMMIT
                and mbi.Protect in READABLE_PROTECT
                and 0 < size < MAX_REGION
            ):
                yield base, size
            nxt = base + size
            if nxt <= addr:
                break
            addr = nxt

    def read(self, addr: int, size: int) -> bytes | None:
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)
        )
        if not ok:
            return None
        return buf.raw[: n.value]

    def scan_hex(self, chunk_size=32 * 1024 * 1024, progress=None):
        """产出 (地址, 十六进制串)。"""
        overlap = 512
        for base, size in self.regions():
            off = 0
            tail = b""
            while off < size:
                n = min(chunk_size, size - off)
                data = self.read(base + off, n)
                if data:
                    buf = tail + data
                    for m in HEX_RE.finditer(buf):
                        yield base + off - len(tail) + m.start(1), m.group(1)
                    tail = buf[-overlap:]
                off += n
                if progress:
                    progress(base + off, size)


class DbRef:
    def __init__(self, rel: str, path: str, page1: bytes):
        self.rel = rel
        self.path = path
        self.page1 = page1
        self.salt_hex = page1[:SALT_SZ].hex()

    @property
    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0


def collect_databases(db_dir: str) -> list[DbRef]:
    out = []
    skip = ("-wal", "-shm", ".material", ".crc")
    for root, _dirs, files in os.walk(db_dir):
        for fn in files:
            if not fn.endswith(".db") or fn.endswith(skip):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, db_dir).replace("\\", "/")
            try:
                if os.path.getsize(path) < PAGE_SZ:
                    continue
                page1 = read_page1_shared(path)
            except OSError:
                continue
            out.append(DbRef(rel, path, page1))
    return out


def find_keys(dbs: list[DbRef], pid: int | None = None, verbose=True) -> dict[str, bytes]:
    """返回 {db 相对路径: enc_key}。"""
    salt_to_dbs: dict[str, list[DbRef]] = {}
    for db in dbs:
        salt_to_dbs.setdefault(db.salt_hex, []).append(db)

    if pid is None:
        procs = list_processes()
        if not procs:
            raise RuntimeError("没有找到正在运行的微信进程（Weixin.exe），请先登录微信再试。")
        pid = max(procs, key=lambda p: _ws(p[0]))[0]
    if verbose:
        print(f"[*] 微信进程 PID = {pid}，共 {len(dbs)} 个数据库 / {len(salt_to_dbs)} 个 salt")

    scanner = MemoryScanner(pid)
    found: dict[str, bytes] = {}      # salt_hex -> key
    t0 = time.time()
    scanned = 0
    n_hex = 0
    try:
        def prog(done, size):
            nonlocal scanned
            scanned += size

        for _addr, hex_bytes in scanner.scan_hex(progress=prog):
            n_hex += 1
            s = hex_bytes.decode("ascii")
            n = len(s)
            if n < 64:
                continue
            key_hex = s[:64]
            salt_hex = s[-32:] if n >= 96 else None
            key = bytes.fromhex(key_hex)

            if salt_hex and salt_hex in salt_to_dbs and salt_hex not in found:
                db = salt_to_dbs[salt_hex][0]
                if verify_key(key, db.page1):
                    found[salt_hex] = key
                    if verbose:
                        print(f"[+] 命中 {db.rel}  salt={salt_hex}")
                    continue

            if salt_hex is None:
                # 只找到 key，逐个 DB 试
                for salt, group in salt_to_dbs.items():
                    if salt in found:
                        continue
                    if verify_key(key, group[0].page1):
                        found[salt] = key
                        if verbose:
                            print(f"[+] 命中 {group[0].rel}  salt={salt}")
                        break
    finally:
        scanner.close()

    if verbose:
        print(
            f"[*] 内存扫描完成：{scanned / 1024 / 1024:.0f}MB，"
            f"{n_hex} 个十六进制串，{time.time() - t0:.1f}s"
        )

    result = {}
    for db in dbs:
        if db.salt_hex in found:
            result[db.rel] = found[db.salt_hex]
    return result


def _ws(pid: int) -> int:
    """进程工作集大小，用于挑出真正持有密钥的那个进程。"""
    try:
        import ctypes.wintypes as wt2

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            return 0
        try:
            class PMC(ctypes.Structure):
                _fields_ = [
                    ("cb", wt.DWORD),
                    ("PageFaultCount", wt.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PMC()
            pmc.cb = ctypes.sizeof(PMC)
            if kernel32.K32GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                return int(pmc.WorkingSetSize)
        finally:
            kernel32.CloseHandle(h)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    db_dir = sys.argv[1] if len(sys.argv) > 1 else None
    if not db_dir:
        print("用法: python -m wxexport.keyscan <db_storage 目录>")
        raise SystemExit(1)
    dbs = collect_databases(db_dir)
    keys = find_keys(dbs)
    for rel, k in keys.items():
        print(rel, k.hex())
