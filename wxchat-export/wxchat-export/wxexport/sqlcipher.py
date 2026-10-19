"""SQLCipher 4 页面解密（微信 4.x 使用的参数）。

微信 4.x 的数据目录下 db_storage 里的 .db 都是 WCDB(SQLCipher) 加密的，
每个库文件可能有**各自的**密钥（随机 32 字节），密钥只存在于微信进程内存里。

实测/公开资料确认的参数：
    page_size = 4096, key_size = 32, AES-256-CBC
    reserve   = 80  (16 字节 IV + 64 字节 HMAC-SHA512)
    HMAC 密钥 = PBKDF2-HMAC-SHA512(enc_key, salt XOR 0x3a, 2 轮, 32 字节)
    HMAC 内容 = (页码 1 时) ciphertext || IV，末尾再拼上小端 4 字节页码

页面布局（page1 特殊）：
    page1 : [16 字节 salt][4000 字节密文][16 字节 IV][64 字节 HMAC]
            解密后 = "SQLite format 3\\0" + 4000 字节明文 + 80 字节保留区
    其它页: [4016 字节密文][16 字节 IV][64 字节 HMAC]
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from .cng_aes import AesCbc

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = IV_SZ + HMAC_SZ  # 80
SQLITE_HDR = b"SQLite format 3\x00"


def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_key(enc_key: bytes, page1: bytes) -> bool:
    """用 page1 的 HMAC 校验密钥是否正确。"""
    if len(page1) < PAGE_SZ or len(enc_key) != KEY_SZ:
        return False
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    mac_data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored = page1[PAGE_SZ - HMAC_SZ:]
    h = hmac.new(mac_key, mac_data, hashlib.sha512)
    h.update(struct.pack("<I", 1))
    return hmac.compare_digest(h.digest(), stored)


class PageDecryptor:
    def __init__(self, enc_key: bytes):
        self.enc_key = bytes(enc_key)
        self.aes = AesCbc(self.enc_key)

    def page(self, raw: bytes, pgno: int) -> bytes:
        if len(raw) < PAGE_SZ:
            raw = raw + b"\x00" * (PAGE_SZ - len(raw))
        iv = raw[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
        if pgno == 1:
            plain = self.aes.decrypt(raw[SALT_SZ: PAGE_SZ - RESERVE_SZ], iv)
            return SQLITE_HDR + plain + b"\x00" * RESERVE_SZ
        plain = self.aes.decrypt(raw[: PAGE_SZ - RESERVE_SZ], iv)
        return plain + b"\x00" * RESERVE_SZ


def read_page1_shared(path: str) -> bytes:
    """以共享方式读取 page1（微信正在运行也能读）。"""
    with open(path, "rb") as f:
        return f.read(PAGE_SZ)


def _apply_wal(db_fp, wal_path: str, dec: PageDecryptor) -> int:
    """把 -wal 里已提交的帧补进已解密的数据库文件，返回补写帧数。"""
    try:
        size = os.path.getsize(wal_path)
    except OSError:
        return 0
    if size <= 32:
        return 0
    with open(wal_path, "rb") as f:
        wal = f.read()
    magic = struct.unpack(">I", wal[:4])[0]
    if magic not in (0x377F0682, 0x377F0683):
        return 0
    page_size = struct.unpack(">I", wal[8:12])[0] or PAGE_SZ
    if page_size != PAGE_SZ:
        return 0
    frame_sz = 24 + page_size
    n_frames = (len(wal) - 32) // frame_sz
    # 找出最后一个 commit 帧
    last_commit = -1
    for i in range(n_frames):
        off = 32 + i * frame_sz
        db_size = struct.unpack(">I", wal[off + 4: off + 8])[0]
        if db_size:
            last_commit = i
    if last_commit < 0:
        return 0
    applied = 0
    for i in range(last_commit + 1):
        off = 32 + i * frame_sz
        pgno = struct.unpack(">I", wal[off: off + 4])[0]
        if pgno == 0:
            continue
        raw = wal[off + 24: off + 24 + page_size]
        plain = dec.page(raw, pgno)
        db_fp.seek((pgno - 1) * PAGE_SZ)
        db_fp.write(plain)
        applied += 1
    return applied


def decrypt_database(
    src: str, dst: str, enc_key: bytes, verify: bool = True, apply_wal: bool = False
) -> dict:
    """解密单个 .db，返回统计信息。

    apply_wal=False 时只解主库。微信 4.x 会频繁 checkpoint，WAL 里的帧可能已经
    合并进主库（此时再把 WAL 回放上去反而会把库写坏），所以默认不回放，
    只有主库读不出来时才尝试带 WAL 的版本。
    """
    page1 = read_page1_shared(src)
    if len(page1) < PAGE_SZ:
        return {"ok": False, "error": "文件太小"}
    if verify and not verify_key(enc_key, page1):
        return {"ok": False, "error": "HMAC 校验失败（密钥不对）"}

    dec = PageDecryptor(enc_key)
    total = os.path.getsize(src) // PAGE_SZ
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for pgno in range(1, total + 1):
            raw = fin.read(PAGE_SZ)
            if len(raw) < PAGE_SZ:
                break
            fout.write(dec.page(raw, pgno))
        wal_frames = 0
        if apply_wal:
            wal = src + "-wal"
            if os.path.exists(wal):
                wal_frames = _apply_wal(fout, wal, dec)
    return {
        "ok": True,
        "pages": total,
        "wal_frames": wal_frames,
        "size": os.path.getsize(dst),
    }


def sqlite_integrity(path: str) -> str:
    """返回 'ok' 或者错误摘要。"""
    import sqlite3

    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            row = con.execute("PRAGMA integrity_check").fetchone()
            return str(row[0]) if row else "unknown"
        finally:
            con.close()
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"


def decrypt_with_fallback(src: str, dst: str, enc_key: bytes) -> dict:
    """先只解主库并校验；不行再试回放 WAL 的版本。"""
    res = decrypt_database(src, dst, enc_key, apply_wal=False)
    if not res.get("ok"):
        return res
    state = sqlite_integrity(dst)
    res["integrity"] = state
    if state != "ok" and os.path.exists(src + "-wal"):
        res2 = decrypt_database(src, dst, enc_key, apply_wal=True)
        if res2.get("ok"):
            state2 = sqlite_integrity(dst)
            res2["integrity"] = state2
            res2["fallback"] = "wal"
            if state2 == "ok":
                return res2
            # 两者都不完美时，选报错更少的
            if len(state2) < len(state):
                return res2
        # 回放失败，恢复成不带 WAL 的版本
        decrypt_database(src, dst, enc_key, apply_wal=False)
    return res

