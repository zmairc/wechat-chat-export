"""离线派生微信 4.x 图片（V2 `.dat`）的密钥。

微信 4.1+ 的聊天图片是「AES 段 + 明文段 + XOR 段」拼起来的，两把密钥都来自
账号级数字 uin：

    aes_key = md5(f"{uin}{wxid}").hexdigest()[:16]   # 16 个 ASCII 字符直接当 16 字节用
    xor_key = uin & 0xFF

其中 wxid 是数据目录名去掉 `_<4位十六进制>` 后缀。**uin 不需要读微信进程内存**：

1. 首选：`%APPDATA%\\Tencent\\xwechat\\net\\kvcomm\\key_<uin>_*.statistic` 的**文件名**；
2. 兜底：`md5(str(uin))[:4]` 等于数据目录的 4 位后缀，可以反推 uin。

所有派生结果都必须**实测验证**——拿 `.dat` 的 AES 段解出图片魔数才算数，
验证不过一律当没找到，绝不把猜测的密钥交给调用方。
"""

from __future__ import annotations

import glob
import hashlib
import os
import re
import time

from .cng_aes import AesEcb
from .media import IMAGE_MASK, V2_SIG, decrypt_dat_blob

KVCOMM_GLOBS = (
    ("APPDATA", os.path.join("Tencent", "xwechat", "net", "kvcomm")),
    ("APPDATA", os.path.join("Tencent", "xwechat", "ilink", "kvcomm")),
    ("APPDATA", os.path.join("Tencent", "WeChat", "*", "kvcomm")),
)

# 2 字节的 BM 在单块验证里太容易撞车，验证时不用它
_STRONG_MAGICS = tuple(m for m, _ext in IMAGE_MASK if len(m) >= 3)

_BRUTEFORCE_LIMIT = 1 << 24      # 后缀反推要枚举 24 位，约几秒


def clean_wxid(name: str) -> str:
    """去掉数据目录名的 `_<4位hex>` / `_<数字>` 后缀。"""
    s = re.sub(r"_[0-9a-fA-F]{4}$", "", name)
    if s == name:
        s = re.sub(r"_\d+$", "", name)
    return s


def wxid_variants(name: str) -> list[str]:
    """目录名的候选写法，按「去掉后缀」优先排序。

    有些老账号的目录名本身就带 4 位十六进制结尾（没有 `_账号后缀`），
    所以不能只认一种写法，交给验证环节挑。
    """
    out = []
    for cand in (clean_wxid(name), name):
        if cand and cand not in out:
            out.append(cand)
    return out


def suffix_of(account_name: str) -> str:
    m = re.search(r"_([0-9a-fA-F]{4})$", account_name)
    return m.group(1).lower() if m else ""


def derive(uin: int, wxid: str) -> tuple[int, bytes]:
    """由 uin 和清洗过的 wxid 派生 (xor_key, aes_key)。"""
    aes_key = hashlib.md5(f"{int(uin)}{wxid}".encode("utf-8")).hexdigest()[:16].encode("ascii")
    return int(uin) & 0xFF, aes_key


# --------------------------------------------------------------- uin 来源

def kvcomm_dirs() -> list[str]:
    out = []
    for env, rel in KVCOMM_GLOBS:
        base = os.environ.get(env) or ""
        if not base:
            continue
        pat = os.path.join(base, rel)
        for d in glob.glob(pat):
            if os.path.isdir(d) and d not in out:
                out.append(d)
    return out


def uins_from_kvcomm(dirs: list[str] | None = None) -> list[int]:
    """从 MMKV 统计文件名里取候选 uin（`key_<uin>_...`，`key_0_` 是占位项）。"""
    out: list[int] = []
    for d in dirs if dirs is not None else kvcomm_dirs():
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            m = re.match(r"key_(\d+)_", n)
            if not m:
                continue
            uin = int(m.group(1))
            if uin and uin not in out:
                out.append(uin)
    return out


def uins_by_suffix(suffix: str, limit: int = _BRUTEFORCE_LIMIT):
    """兜底：枚举满足 `md5(str(uin))[:4] == suffix` 的 uin（约 2^24 次 md5）。"""
    if not suffix:
        return
    want = suffix.lower()
    for uin in range(1, limit):
        if hashlib.md5(str(uin).encode()).hexdigest()[:4] == want:
            yield uin


# --------------------------------------------------------------- 验证

def v2_samples(account_dir: str, limit: int = 6) -> list[str]:
    """在 msg/attach 下找几个 V2 格式的 `.dat` 做验证样本。"""
    attach = os.path.join(account_dir, "msg", "attach")
    out: list[str] = []
    if not os.path.isdir(attach):
        return out
    for root, _dirs, files in os.walk(attach):
        for name in files:
            if not name.lower().endswith(".dat"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as f:
                    if f.read(6) != V2_SIG:
                        continue
            except OSError:
                continue
            out.append(path)
            if len(out) >= limit:
                return out
    return out


def probe_blocks(paths: list[str]) -> list[bytes]:
    """取出每个样本第 [15:31] 字节——AES 段的第一块，用来验证密钥。"""
    blocks = []
    for path in paths:
        try:
            with open(path, "rb") as f:
                head = f.read(31)
        except OSError:
            continue
        if len(head) >= 31 and head[:6] == V2_SIG:
            blocks.append(head[15:31])
    return blocks


def verify(aes_key: bytes, blocks: list[bytes]) -> int:
    """返回能解出图片魔数的样本数量。"""
    if not blocks or len(aes_key) < 16:
        return 0
    try:
        cipher = AesEcb(aes_key[:16])
    except Exception:      # noqa: BLE001 - 系统 AES 不可用时直接放弃
        return 0
    ok = 0
    for blk in blocks:
        try:
            plain = cipher.decrypt(blk)
        except Exception:  # noqa: BLE001
            continue
        if any(plain.startswith(m) for m in _STRONG_MAGICS):
            ok += 1
    return ok


def _need(blocks: list[bytes]) -> int:
    """至少一半样本命中才算数，避免单块偶然撞上魔数。"""
    return max(1, (len(blocks) + 1) // 2)


def find(account_dir: str, allow_bruteforce: bool = True,
         verbose: bool = False) -> dict | None:
    """给一个账号数据目录，返回可用的图片密钥；找不到或验证不过返回 None。

    返回：``{"uin", "wxid", "aes_key", "xor_key", "source", "verified", "samples"}``
    """
    name = os.path.basename(os.path.normpath(account_dir))
    blocks = probe_blocks(v2_samples(account_dir))
    if not blocks:
        return None

    need = _need(blocks)
    suffix = suffix_of(name)

    def attempt(uin, source):
        for wxid in wxid_variants(name):
            xor_key, aes_key = derive(uin, wxid)
            hits = verify(aes_key, blocks)
            if hits >= need:
                return {
                    "uin": int(uin), "wxid": wxid,
                    "aes_key": aes_key, "xor_key": xor_key,
                    "source": source, "verified": hits, "samples": len(blocks),
                }
        return None

    cands = uins_from_kvcomm()
    if suffix:
        # 目录后缀能和 md5(uin)[:4] 对上的先试
        cands.sort(key=lambda u: hashlib.md5(str(u).encode()).hexdigest()[:4] != suffix)
    for uin in cands:
        got = attempt(uin, "kvcomm")
        if got:
            return got

    if allow_bruteforce and suffix:
        t0 = time.time()
        for uin in uins_by_suffix(suffix):
            got = attempt(uin, "suffix")
            if got:
                return got
        if verbose:
            print(f"    后缀反推没找到可用密钥（耗时 {time.time() - t0:.1f}s）")
    return None


def describe(info: dict) -> str:
    """给命令行用的一句话摘要。"""
    return (f"uin={info['uin']} xor_key=0x{info['xor_key']:02X} "
            f"（{info['source']}，{info['verified']}/{info['samples']} 个样本验证通过）")


# ------------------------------------------------- 只有 AES 密钥时反推 xor

_TAIL_MARKERS = {
    "jpg": b"\xff\xd9",
    "png": b"IEND\xaeB`\x82",
    "gif": b"\x3b",
}


def _tail_ok(blob: bytes, ext: str) -> bool:
    marker = _TAIL_MARKERS.get(ext)
    return bool(marker) and blob.endswith(marker)


def guess_xor_key(paths: list[str], aes_key: bytes, limit: int = 3) -> int | None:
    """已知 AES 密钥、但不知道尾段 XOR 密钥时，用文件尾标记反推。

    只对能验证结尾的格式（jpg / png / gif）有效；hevc 没有可靠的结束标记，不参与投票。
    """
    votes: dict[int, int] = {}
    used = 0
    for path in paths[:limit]:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if data[:6] != V2_SIG:
            continue
        used += 1
        for key in range(256):
            got = decrypt_dat_blob(data, aes_key, key)
            if not got:
                continue
            blob, ext = got
            if ext in _TAIL_MARKERS and _tail_ok(blob, ext):
                votes[key] = votes.get(key, 0) + 1
    if not votes:
        return None
    best = max(votes, key=lambda k: votes[k])
    return best if votes[best] >= max(1, used) else None
