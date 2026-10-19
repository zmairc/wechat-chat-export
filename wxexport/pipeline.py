"""定位微信数据目录、管理密钥缓存、批量解密数据库。"""

from __future__ import annotations

import json
import os
import re
import string
import time

from . import keyextract, keyscan, sqlcipher


# ----------------------------------------------------------- 数据目录定位

def _ini_data_roots() -> list[str]:
    appdata = os.environ.get("APPDATA") or ""
    cfg = os.path.join(appdata, "Tencent", "xwechat", "config")
    roots = []
    if os.path.isdir(cfg):
        for fn in os.listdir(cfg):
            if not fn.lower().endswith(".ini"):
                continue
            try:
                with open(os.path.join(cfg, fn), "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read(512).strip().strip('"')
            except OSError:
                continue
            if txt and os.path.isdir(txt):
                roots.append(txt)
    return roots


def _scan_drives_for_root(max_depth=3) -> list[str]:
    found = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if not os.path.isdir(drive):
            continue
        stack = [(drive, 0)]
        while stack:
            path, depth = stack.pop()
            if depth > max_depth:
                continue
            try:
                entries = list(os.scandir(path))
            except (OSError, PermissionError):
                continue
            for e in entries:
                try:
                    if not e.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                name = e.name
                if name == "xwechat_files":
                    found.append(os.path.join(path, name))
                    continue
                if depth >= max_depth:
                    continue
                if name in {"Windows", "$Recycle.Bin", "System Volume Information",
                            "Program Files", "Program Files (x86)", "AppData"}:
                    continue
                if name.startswith("."):
                    continue
                if depth >= 2 and name.lower() not in {
                    "documents", "users", "tencent", "data", "wechat", "xwechat",
                    "desktop", "downloads", "software", "apps",
                } and depth >= 2 and len(stack) > 4000:
                    continue
                stack.append((e.path, depth + 1))
    # 去重
    out = []
    for p in found:
        if p not in out:
            out.append(p)
    return out


def find_data_roots() -> list[str]:
    roots = _ini_data_roots()
    roots += _scan_drives_for_root()
    uniq = []
    for r in roots:
        if os.path.isdir(r) and r not in uniq:
            uniq.append(r)
    return uniq


class Account:
    def __init__(self, path: str):
        self.path = path                      # ...\xwechat_files\wxid_xxx_abcd
        self.name = os.path.basename(path)
        self.db_dir = os.path.join(path, "db_storage")

    @property
    def username(self) -> str:
        m = re.match(r"^(wxid_[0-9a-zA-Z]+)", self.name)
        return m.group(1) if m else self.name

    def message_dbs(self) -> list[str]:
        d = os.path.join(self.db_dir, "message")
        if not os.path.isdir(d):
            return []
        return sorted(
            os.path.join(d, f) for f in os.listdir(d)
            if re.fullmatch(r"message_\d+\.db", f)
        )

    def valid(self) -> bool:
        return os.path.isdir(self.db_dir) and bool(self.message_dbs())

    def __repr__(self):
        return f"<Account {self.name}>"


def list_accounts(roots: list[str] | None = None) -> list[Account]:
    roots = roots if roots is not None else find_data_roots()
    out = []
    for root in roots:
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for name in entries:
            p = os.path.join(root, name)
            if not os.path.isdir(p) or name in ("all_users", "Backup", "WMPF"):
                continue
            acc = Account(p)
            if acc.valid():
                out.append(acc)

    def latest(acc: Account) -> float:
        try:
            return max(os.path.getmtime(p) for p in acc.message_dbs())
        except ValueError:
            return 0

    # 同一个 wxid 可能在多个磁盘上各留一份数据目录（比如以前装在 D:，后来搬到 E:），
    # 只保留最近更新的那份，避免让用户面对一堆重复账号。
    best: dict[str, Account] = {}
    for acc in out:
        cur = best.get(acc.name)
        if cur is None or latest(acc) > latest(cur):
            best[acc.name] = acc
    out = sorted(best.values(), key=latest, reverse=True)
    return out


# --------------------------------------------------------------- 密钥缓存

def default_work_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "work")


def keys_file(work_dir: str, account: Account) -> str:
    return os.path.join(work_dir, f"keys_{account.name}.json")


def cache_keys(path: str, keys: dict[str, bytes]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {rel: k.hex() for rel, k in keys.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_cached_keys(path: str, dbs) -> dict[str, bytes]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    by_salt = {db.salt_hex: db for db in dbs}
    out = {}
    for rel, hexkey in raw.items():
        try:
            k = bytes.fromhex(hexkey)
        except ValueError:
            continue
        db = by_salt.get(rel)  # 兼容：key 里也可能存 salt
        out[rel] = k
    # 只保留当前仍然存在的库
    valid = {db.rel for db in dbs}
    return {rel: k for rel, k in out.items() if rel in valid}


def get_keys(account: Account, work_dir: str, verbose=True,
             allow_cache=True, force_scan=False) -> dict[str, bytes]:
    dbs = keyscan.collect_databases(account.db_dir)
    if not dbs:
        raise RuntimeError(f"在 {account.db_dir} 里没有找到数据库文件")
    cache = keys_file(work_dir, account)
    keys = {} if force_scan else (load_cached_keys(cache, dbs) if allow_cache else {})

    missing = [db for db in dbs if db.rel not in keys]
    # 用缓存的密钥校验一遍，避免 key 过期
    ok_keys = {}
    for db in dbs:
        k = keys.get(db.rel)
        if k and sqlcipher.verify_key(k, db.page1):
            ok_keys[db.rel] = k
    keys = ok_keys
    missing = [db for db in dbs if db.rel not in keys]

    if missing:
        if verbose:
            print(f"[*] 需要从微信进程提取 {len(missing)} 个数据库的密钥 ...")
        fresh = keyextract.find_keys(missing, verbose=verbose)
        keys.update(fresh)
        if keys:
            cache_keys(cache, keys)
    else:
        if verbose:
            print(f"[*] 使用已缓存的密钥（{len(keys)} 个库）")
    return keys


# ------------------------------------------------------------------ 解密

def decrypt_required(account: Account, work_dir: str, keys: dict[str, bytes],
                     rels=None, verbose=True) -> dict[str, str]:
    """解密需要的库，返回 {相对路径: 解密后的绝对路径}。"""
    out_root = os.path.join(work_dir, "decrypted", account.name)
    rels = rels or [
        "contact/contact.db",
        "session/session.db",
        "message/message_resource.db",
    ]
    out = {}
    all_rels = list(rels)
    dbs = {db.rel: db for db in keyscan.collect_databases(account.db_dir)}
    for rel in dbs:
        if re.fullmatch(r"message/message_\d+\.db", rel):
            all_rels.append(rel)

    for rel in all_rels:
        db = dbs.get(rel)
        if not db or rel not in keys:
            continue
        dst = os.path.join(out_root, rel.replace("/", os.sep))
        res = sqlcipher.decrypt_with_fallback(db.path, dst, keys[rel])
        if verbose:
            state = res.get("integrity", "?")
            flag = "OK" if state == "ok" else f"WARN({state[:40]})"
            print(f"    {rel:38s} {flag}")
        if res.get("ok"):
            out[rel] = dst
    return out
