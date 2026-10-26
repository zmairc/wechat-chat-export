"""QQ NT（9.9.x）本地数据库：定位、参数探测、解密。

和微信的区别（都是实测/公开资料确认过的）：

1. 文件 = **1024 字节自定义头** + SQLCipher 库；头不是真的 SQLite 头（写的是
   "SQLite header 3"，真头是 "SQLite format 3\\0"），剥掉之后长度才对齐 4096；
2. SQLCipher 参数是**非默认**的：`kdf_iter=4000`（不是 256000）；
   HMAC 算法各版本说法不一（SHA1 / SHA512 都有人报），所以这里不写死，
   而是拿 page1 的 HMAC **逐个组合试**，试通了再用来解；
3. 口令是登录后由 `nt_sqlite3_key_v2` 传入的 16 位 ASCII，**只在函数调用瞬间存在**，
   不常驻进程内存（本项目实测扫了 900MB 也没找到），所以只能由用户提供。

本项目只做「拿口令解密」这一段，不注入、不 hook、不改 QQ 文件。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from .cng_aes import AesCbc

HEADER_SZ = 1024
PAGE_SZ = 4096
SALT_SZ = 16
SQLITE_HDR = b"SQLite format 3\x00"


class Params:
    """一套 SQLCipher 参数。reserve = 16(IV) + HMAC，按 16 对齐。"""

    def __init__(self, name: str, kdf_iter: int, kdf_algo: str,
                 mac_algo: str, mac_len: int, reserve: int):
        self.name = name
        self.kdf_iter = kdf_iter
        self.kdf_algo = kdf_algo
        self.mac_algo = mac_algo
        self.mac_len = mac_len
        self.reserve = reserve

    def __repr__(self):
        return (f"<{self.name} iter={self.kdf_iter} kdf={self.kdf_algo} "
                f"mac={self.mac_algo} reserve={self.reserve}>")


# 常见组合，按"最像 QQ"的顺序排；detect() 会逐个试
PARAM_SETS = (
    Params("qq/sha1-48", 4000, "sha512", "sha1", 20, 48),
    Params("qq/sha1-36", 4000, "sha512", "sha1", 20, 36),
    Params("qq/sha512-80", 4000, "sha512", "sha512", 64, 80),
    Params("qq/legacy-sha1", 4000, "sha1", "sha1", 20, 48),
    Params("qq/iter64000", 64000, "sha512", "sha1", 20, 48),
    Params("sqlcipher-default", 256000, "sha512", "sha512", 64, 80),
)


# ------------------------------------------------------------------ 定位

class Database:
    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)

    @property
    def size(self):
        return os.path.getsize(self.path)

    def page1(self) -> bytes:
        """跳过 1024 字节自定义头，取出真正的 page1。"""
        with open(self.path, "rb") as f:
            f.seek(HEADER_SZ)
            return f.read(PAGE_SZ)

    def structure_ok(self) -> tuple[bool, str]:
        """不改动数据地判断「1024 字节头 + 4096 页」这个假设是否成立。"""
        size = self.size
        if size <= HEADER_SZ:
            return False, f"文件太小（{size} 字节）"
        body = size - HEADER_SZ
        if body % PAGE_SZ:
            return False, f"去掉 {HEADER_SZ} 字节头后余 {body}，不是 {PAGE_SZ} 的整数倍"
        with open(self.path, "rb") as f:
            head = f.read(16)
        if head == SQLITE_HDR:
            return True, "本身就是明文 SQLite，无需解密"
        return True, f"1024 字节头 + {(body // PAGE_SZ)} 页 × 4096"


def find_databases(extra_roots: list[str] | None = None) -> list[Database]:
    """找所有 `nt_qq*/nt_db/*.db`。"""
    roots = list(extra_roots or [])
    docs = os.path.join(os.path.expanduser("~"), "Documents", "Tencent Files")
    if os.path.isdir(docs):
        roots.append(docs)
    out: list[Database] = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            if os.path.basename(dirpath).lower() != "nt_db":
                continue
            dirnames[:] = []
            for f in sorted(filenames):
                if f.endswith(".db"):
                    out.append(Database(os.path.join(dirpath, f)))
    return out


# ------------------------------------------------------------------ 密钥

def derive(enc_passphrase: bytes, salt: bytes, p: Params) -> tuple[bytes, bytes]:
    """SQLCipher 的 enc_key / mac_key 推导。"""
    enc_key = hashlib.pbkdf2_hmac(p.kdf_algo, enc_passphrase, salt, p.kdf_iter, 32)
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac(p.mac_algo, enc_key, mac_salt, 2, p.mac_len)
    return enc_key, mac_key


def verify(passphrase: bytes, page1: bytes, p: Params) -> bool:
    """用 page1 的 HMAC 校验口令与参数是否匹配。"""
    if len(page1) < PAGE_SZ:
        return False
    salt = page1[:SALT_SZ]
    ct_len = PAGE_SZ - SALT_SZ - p.reserve
    data_end = SALT_SZ + ct_len + 16          # 密文 + IV
    if data_end > PAGE_SZ - p.mac_len:
        return False
    try:
        _ek, mac_key = derive(passphrase, salt, p)
    except Exception:      # noqa: BLE001
        return False
    h = hmac.new(mac_key, page1[SALT_SZ:data_end], getattr(hashlib, p.mac_algo))
    h.update(struct.pack("<I", 1))
    return hmac.compare_digest(h.digest(), page1[PAGE_SZ - p.mac_len:])


def detect(passphrase: bytes, page1: bytes) -> Params | None:
    """口令已知，但参数未知时逐个试。"""
    for p in PARAM_SETS:
        if verify(passphrase, page1, p):
            return p
    return None


# ------------------------------------------------------------------ 解密

def decrypt_db(db: Database, dst: str, passphrase: bytes, p: Params,
               apply_wal: bool = False) -> dict:
    page1 = db.page1()
    if not verify(passphrase, page1, p):
        return {"ok": False, "error": "口令或参数不匹配（page1 HMAC 校验失败）"}

    enc_key, _mac = derive(passphrase, page1[:SALT_SZ], p)
    aes = AesCbc(enc_key)
    # page1 的密文段要减去 16 字节 salt；其余页没有 salt
    ct1 = PAGE_SZ - SALT_SZ - p.reserve
    ctn = PAGE_SZ - p.reserve

    total = (db.size - HEADER_SZ) // PAGE_SZ
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(db.path, "rb") as fin, open(dst, "wb") as fout:
        fin.seek(HEADER_SZ)
        for pgno in range(1, total + 1):
            raw = fin.read(PAGE_SZ)
            if len(raw) < PAGE_SZ:
                break
            if pgno == 1:
                iv = raw[SALT_SZ + ct1: SALT_SZ + ct1 + 16]
                plain = aes.decrypt(raw[SALT_SZ: SALT_SZ + ct1], iv)
                fout.write(SQLITE_HDR + plain + b"\x00" * p.reserve)
            else:
                iv = raw[ctn: ctn + 16]
                plain = aes.decrypt(raw[:ctn], iv)
                fout.write(plain + b"\x00" * p.reserve)
        wal_frames = 0
        if apply_wal:
            wal = db.path + "-wal"
            if os.path.exists(wal):
                wal_frames = _apply_wal(fout, wal, aes, p, ct1, ctn)
    return {"ok": True, "pages": total, "wal_frames": wal_frames,
            "size": os.path.getsize(dst), "params": p.name}


def _apply_wal(fp, wal_path: str, aes, p: Params, ct1: int, ctn: int) -> int:
    """把 -wal 里已提交的帧补进已解密的库（QQ 的 WAL 结构同 SQLite）。"""
    try:
        with open(wal_path, "rb") as f:
            wal = f.read()
    except OSError:
        return 0
    if len(wal) <= 32:
        return 0
    if struct.unpack(">I", wal[:4])[0] not in (0x377F0682, 0x377F0683):
        return 0
    if (struct.unpack(">I", wal[8:12])[0] or PAGE_SZ) != PAGE_SZ:
        return 0
    frame_sz = 24 + PAGE_SZ
    n = (len(wal) - 32) // frame_sz
    last = -1
    for i in range(n):
        off = 32 + i * frame_sz
        if struct.unpack(">I", wal[off + 4: off + 8])[0]:
            last = i
    applied = 0
    for i in range(last + 1):
        off = 32 + i * frame_sz
        pgno = struct.unpack(">I", wal[off: off + 4])[0]
        if not pgno:
            continue
        raw = wal[off + 24: off + 24 + PAGE_SZ]
        if pgno == 1:
            iv = raw[SALT_SZ + ct1: SALT_SZ + ct1 + 16]
            plain = SQLITE_HDR + aes.decrypt(raw[SALT_SZ: SALT_SZ + ct1], iv)
        else:
            iv = raw[ctn: ctn + 16]
            plain = aes.decrypt(raw[:ctn], iv)
        fp.seek((pgno - 1) * PAGE_SZ)
        fp.write(plain + b"\x00" * p.reserve)
        applied += 1
    return applied


def integrity(path: str) -> str:
    import sqlite3

    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            row = con.execute("PRAGMA integrity_check").fetchone()
            return str(row[0]) if row else "unknown"
        finally:
            con.close()
    except Exception as e:      # noqa: BLE001
        return f"error: {e}"


def describe_schema(path: str) -> list[tuple[str, list[str]]]:
    """列出表名与列名，方便下一步按真实结构写解析。"""
    import sqlite3

    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        out = []
        for t in tables:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
            out.append((t, cols))
        return out
    finally:
        con.close()
