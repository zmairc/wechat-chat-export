"""导出聊天里的媒体文件：图片(.dat 解密)、视频、文件、表情。"""

from __future__ import annotations

import glob
import hashlib
import os
import re
import shutil
import struct

from .cng_aes import AesEcb

V1_SIG = b"\x07\x08\x56\x31\x08\x07"
V2_SIG = b"\x07\x08\x56\x32\x08\x07"
V1_KEY = b"cfcd208495d565ef"      # = md5("0")[:16]，微信 V1 的固定密钥
V2_XOR = 0x88

IMAGE_MASK = (
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG", "png"),
    (b"GIF8", "gif"),
    (b"BM", "bmp"),
    (b"RIFF", "webp"),
    (b"wxgf", "hevc"),
)


def _sniff(blob: bytes) -> str:
    for magic, ext in IMAGE_MASK:
        if blob.startswith(magic):
            return ext
    return ""


def _unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 0 < n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def _align16(n: int) -> int:
    return n + 16 if n % 16 == 0 else n + (16 - n % 16)


def detect_xor_key(data: bytes) -> int | None:
    """旧格式：整文件单字节 XOR，靠文件头猜出 key。"""
    head = data[:16]
    for magic, _ext in IMAGE_MASK:
        if len(magic) < 3:
            continue
        key = head[0] ^ magic[0]
        if all((head[i] ^ key) == magic[i] for i in range(1, len(magic))):
            return key
    return None


def decrypt_dat_blob(data: bytes, aes_key: bytes | None = None,
                     xor_key: int | None = None) -> tuple[bytes, str] | None:
    """解密一段 .dat 内容，返回 (原始图片字节, 扩展名)；无法解密时返回 None。

    V1 用固定密钥；V2 的 AES 段密钥因账号而异，尾段的单字节 XOR 密钥是
    ``uin & 0xFF``（见 imagekey.py），拿不到时退回历史常量。
    """
    if len(data) < 32:
        return None
    sig = data[:6]

    if sig in (V1_SIG, V2_SIG):
        is_v2 = sig == V2_SIG
        key = aes_key if is_v2 else V1_KEY
        if not key:
            return None
        tail_key = (xor_key if xor_key is not None else V2_XOR) if is_v2 else V2_XOR
        aes_size, xor_size = struct.unpack_from("<II", data, 6)
        aligned = _align16(aes_size)
        if 15 + aligned > len(data):
            return None
        aes_blob = data[15:15 + aligned]
        try:
            plain = _unpad(AesEcb(key[:16]).decrypt(aes_blob))
        except Exception:
            return None
        ext = _sniff(plain)
        if not ext:
            return None
        rest = data[15 + aligned:]
        tail_idx = len(rest) - xor_size
        raw_part = rest[:tail_idx] if tail_idx > 0 else b""
        xor_part = rest[tail_idx:] if tail_idx > 0 else rest
        out = plain + raw_part + bytes(b ^ tail_key for b in xor_part)
        ext = _sniff(out) or ext
        return out, ext

    # 旧格式：单字节 XOR
    key = detect_xor_key(data)
    if key is None:
        return None
    out = bytes(b ^ key for b in data)
    ext = _sniff(out)
    if not ext:
        return None
    return out, ext


def decrypt_dat(path: str, aes_key: bytes | None = None,
                xor_key: int | None = None) -> tuple[bytes, str] | None:
    """解密 .dat 文件，返回 (原始图片字节, 扩展名)；无法解密时返回 None。"""
    with open(path, "rb") as f:
        return decrypt_dat_blob(f.read(), aes_key, xor_key)


class MediaExporter:
    """把消息里的媒体落到 media/ 目录，并返回相对路径。"""

    def __init__(self, account, out_dir: str, aes_key: bytes | None = None,
                 xor_key: int | None = None):
        self.account = account
        self.out_dir = out_dir            # 导出目录（media/ 的父目录）
        self.media_dir = os.path.join(out_dir, "media")
        self.aes_key = aes_key
        self.xor_key = xor_key
        self.attach_root = os.path.join(account.path, "msg", "attach")
        self.video_root = os.path.join(account.path, "msg", "video")
        self.file_root = os.path.join(account.path, "msg", "file")
        self._index: dict[str, list[str]] = {}
        self._cache: dict[str, dict] = {}
        self._n = 0
        self.stats = {"image": 0, "image_raw": 0, "image_hevc": 0,
                      "video": 0, "file": 0, "missing": 0}

    # ------------------------------------------------------------ 索引
    def _chat_dir(self, chat_hash: str) -> str:
        return os.path.join(self.attach_root, chat_hash)

    def _files_of(self, base: str) -> list[str]:
        if base in self._index:
            return self._index[base]
        files = []
        if os.path.isdir(base):
            for root, _dirs, fs in os.walk(base):
                for f in fs:
                    files.append(os.path.join(root, f))
        self._index[base] = files
        return files

    def _find_by_md5(self, chat_hash: str, md5: str) -> list[str]:
        hits = []
        for f in self._files_of(self._chat_dir(chat_hash)):
            if os.path.basename(f).startswith(md5):
                hits.append(f)
        return hits

    def _find_global(self, md5: str, roots: list[str]) -> list[str]:
        hits = []
        for r in roots:
            hits += glob.glob(os.path.join(r, "**", f"{md5}*"), recursive=True)
        return hits

    def _unique(self, stem: str, ext: str) -> str:
        os.makedirs(self.media_dir, exist_ok=True)
        self._n += 1
        name = f"{self._n:05d}_{stem}.{ext}"
        return os.path.join(self.media_dir, name)

    @staticmethod
    def _rel(path: str, base: str) -> str:
        return os.path.relpath(path, base).replace("\\", "/")

    # ------------------------------------------------------------ 图片
    def export_image(self, chat_hash: str, md5: str, month: str) -> dict:
        """返回 {'path': 相对路径, 'decoded': 能否直接在浏览器显示, 'ext': 扩展名}"""
        key = f"img:{chat_hash}:{md5}"
        if key in self._cache:
            return self._cache[key]
        miss = {"path": None, "decoded": False, "ext": ""}
        if not md5:
            self.stats["missing"] += 1
            return miss

        cands = self._find_by_md5(chat_hash, md5)
        # 优先完整图，其次缩略图
        cands.sort(key=lambda p: ("_t" in os.path.basename(p), "_h" in os.path.basename(p), len(p)))

        for src in cands:
            if not src.endswith(".dat"):
                ext = os.path.splitext(src)[1].lstrip(".").lower()
                dst = self._unique(md5[:8], ext)
                shutil.copyfile(src, dst)
                res = {"path": self._rel(dst, self.out_dir), "decoded": True, "ext": ext}
                self._cache[key] = res
                self.stats["image"] += 1
                return res
            got = decrypt_dat(src, self.aes_key, self.xor_key)
            if got:
                blob, ext = got
                stem = md5[:8] + os.path.basename(src).split("_")[-1].replace(".dat", "")
                dst = self._unique(stem, ext)
                with open(dst, "wb") as f:
                    f.write(blob)
                # wxgf 是微信自家的 HEVC 封装（动图/原图），解密成功但浏览器放不了
                playable = ext != "hevc"
                res = {"path": self._rel(dst, self.out_dir), "decoded": playable, "ext": ext}
                self._cache[key] = res
                self.stats["image"] += 1
                if not playable:
                    self.stats["image_hevc"] += 1
                return res
            # 解不开就原样保存，至少不丢数据
            dst = self._unique(md5[:8] + "_raw", "dat")
            shutil.copyfile(src, dst)
            self.stats["image_raw"] += 1
            res = {"path": self._rel(dst, self.out_dir), "decoded": False, "ext": "dat"}
            self._cache[key] = res
            return res

        self.stats["missing"] += 1
        self._cache[key] = miss
        return miss

    # ------------------------------------------------------------ 视频
    def export_video(self, chat_hash: str, md5: str, month: str) -> dict | None:
        key = f"video:{md5}"
        if key in self._cache:
            return self._cache[key]
        cands = self._find_by_md5(chat_hash, md5)
        if not cands:
            cands = self._find_global(md5, [self.video_root])
        if not cands:
            cands = self._find_global(md5, [self.attach_root])
        if not cands:
            self._cache[key] = None
            self.stats["missing"] += 1
            return None
        # 优先真实视频文件，其次封面图
        cands.sort(key=lambda p: (
            os.path.splitext(p)[1].lower() in (".mp4", ".mov"),
            "thumb" not in os.path.basename(p).lower(),
            len(p),
        ), reverse=True)
        src = cands[0]
        ext = os.path.splitext(src)[1].lstrip(".").lower() or "mp4"
        is_thumb = "thumb" in os.path.basename(src).lower() or ext in ("jpg", "png")
        dst = self._unique(md5[:8], ext)
        shutil.copyfile(src, dst)
        rel = self._rel(dst, self.out_dir)
        res = {"path": rel, "thumb_only": is_thumb}
        self._cache[key] = res
        self.stats["video"] += 1
        return res

    # ------------------------------------------------------------ 文件
    def _file_index(self) -> dict[str, list[str]]:
        if "_files" in self.__dict__:
            return self.__dict__["_files"]
        idx: dict[str, list[str]] = {}
        if os.path.isdir(self.file_root):
            for root, _dirs, fs in os.walk(self.file_root):
                for f in fs:
                    idx.setdefault(f.lower(), []).append(os.path.join(root, f))
        self.__dict__["_files"] = idx
        return idx

    def export_file(self, chat_hash: str, md5: str, month: str, name: str,
                    size=None) -> str | None:
        key = f"file:{md5}:{name}:{month}"
        if key in self._cache:
            return self._cache[key]
        name = (name or "").strip()
        cands: list[str] = []
        if month and name:
            cands.append(os.path.join(self.file_root, month, name))
            cands.append(os.path.join(self.file_root, month, f"1_{name}"))
        idx = self._file_index()
        if name:
            cands += idx.get(name.lower(), [])
            cands += idx.get(f"1_{name}".lower(), [])
            base = os.path.basename(name).lower()
            if base != name.lower():
                cands += idx.get(base, [])
        if md5:
            cands += self._find_global(md5, [self._chat_dir(chat_hash)])
            cands += self._find_global(md5, [self.attach_root])
        # 大小兜底：名字对不上时，用消息里记录的文件大小在同一月份里找
        try:
            want = int(size) if size else 0
        except (TypeError, ValueError):
            want = 0
        if want and month:
            mdir = os.path.join(self.file_root, month)
            if os.path.isdir(mdir):
                for f in os.listdir(mdir):
                    p = os.path.join(mdir, f)
                    try:
                        if os.path.isfile(p) and os.path.getsize(p) == want:
                            cands.append(p)
                    except OSError:
                        pass

        seen = set()
        for src in cands:
            if not src or src in seen:
                continue
            seen.add(src)
            if os.path.isfile(src):
                ext = os.path.splitext(src)[1].lstrip(".") or "bin"
                dst = self._unique(re.sub(r'[\\/:*?"<>|]', "_", name or "file")[:40] or "file", ext)
                shutil.copyfile(src, dst)
                rel = self._rel(dst, self.out_dir)
                self._cache[key] = rel
                self.stats["file"] += 1
                return rel
        self.stats["missing"] += 1
        self._cache[key] = None
        return None
