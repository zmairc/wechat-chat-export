"""读取解密后的微信数据库：联系人、会话列表、某个聊天的全部消息。"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3

from . import zstd_codec

MSG_TABLE_RE = re.compile(r"^Msg_([0-9a-f]{32})$")


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.text_factory = bytes  # 避免非法 UTF-8 直接报错，后面自己解码
    return con


_HEX32 = re.compile(rb"(?<![0-9a-fA-F])[0-9a-f]{32}(?![0-9a-fA-F])")


def _md5_from_packed(packed: bytes) -> str:
    """消息表 packed_info_data 里藏着媒体文件名的 md5（图片/视频/文件都靠它定位）。"""
    if not packed:
        return ""
    m = _HEX32.search(packed)
    return m.group(0).decode("ascii") if m else ""


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.decode("utf-8", "replace")
    return str(v)


def _decompress_columns(con: sqlite3.Connection, table: str, cols: list[str]):
    """把指定列里 zstd 压缩的 blob 批量解压，返回 {(col, rowid): text}。"""
    out = {}
    for col in cols:
        ct = f"WCDB_CT_{col}"
        try:
            rows = con.execute(
                f"SELECT local_id, {col} FROM {table} WHERE {ct} IS NOT NULL AND {ct} != 0"
            ).fetchall()
        except sqlite3.Error:
            continue
        if not rows:
            continue
        blobs = [r[1] if isinstance(r[1], bytes) else b"" for r in rows]
        if not any(zstd_codec.is_compressed(b) for b in blobs):
            continue
        decompressed = zstd_codec.decompress_many(blobs)
        for (local_id, _orig), val in zip(rows, decompressed):
            if val is not None:
                out[(col, local_id)] = val.decode("utf-8", "replace")
    return out


class Store:
    """一个账号的解密后数据。"""

    def __init__(self, account, decrypted: dict[str, str], work_dir: str = ""):
        self.account = account
        self.files = decrypted
        self.work_dir = work_dir
        self.self_username = account.username
        self.contacts: dict[str, dict] = {}
        self._name2id: dict[str, dict[int, str]] = {}     # db rel -> {rowid: username}
        self._load_contacts()

    # ------------------------------------------------------------ 联系人
    def _load_contacts(self):
        path = self.files.get("contact/contact.db")
        if not path or not os.path.exists(path):
            return
        con = _connect(path)
        try:
            for row in con.execute(
                "SELECT username, nick_name, remark, alias, local_type FROM contact"
            ):
                u = _s(row[0])
                if not u:
                    continue
                self.contacts[u] = {
                    "username": u,
                    "nick": _s(row[1]),
                    "remark": _s(row[2]),
                    "alias": _s(row[3]),
                    "type": row[4] or 0,
                }
        except sqlite3.Error:
            pass
        finally:
            con.close()

    def display_name(self, username: str) -> str:
        if not username:
            return "未知"
        if username == self.self_username:
            return self.display_name_self()
        c = self.contacts.get(username)
        if c:
            for key in ("remark", "nick"):
                if c.get(key):
                    return c[key]
        if username.endswith("@chatroom"):
            return "群聊 " + username
        return username

    def display_name_self(self) -> str:
        me = self.contacts.get(self.self_username)
        if me:
            for key in ("remark", "nick"):
                if me.get(key):
                    return me[key]
        return "我"

    # ------------------------------------------------------- 消息库/表索引
    def message_dbs(self) -> list[str]:
        return sorted(
            [p for rel, p in self.files.items() if MSG_TABLE_RE.match("Msg_" + rel[-36:-3])
             or rel.startswith("message/message_")]
        )

    def _msg_db_files(self) -> dict[str, str]:
        return {
            rel: p for rel, p in self.files.items()
            if re.fullmatch(r"message/message_\d+\.db", rel)
        }

    def name2id(self, rel: str) -> dict[int, str]:
        if rel in self._name2id:
            return self._name2id[rel]
        mapping = {}
        con = _connect(self.files[rel])
        try:
            for rowid, user_name in con.execute("SELECT rowid, user_name FROM Name2Id"):
                mapping[int(rowid)] = _s(user_name)
        except sqlite3.Error:
            pass
        finally:
            con.close()
        self._name2id[rel] = mapping
        return mapping

    def _tables(self, rel: str) -> list[str]:
        con = _connect(self.files[rel])
        try:
            return [
                _s(r[0]) for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")
                if MSG_TABLE_RE.match(_s(r[0]))
            ]
        finally:
            con.close()

    def chat_index(self, merge: bool = True) -> list[dict]:
        """所有有聊天记录的会话：数量、最后时间、显示名。

        同一个人/群的消息可能分散在 message_0.db、message_1.db … 里，
        默认按 username 合并成一条。
        """
        raw = []
        for rel, path in sorted(self._msg_db_files().items()):
            n2i = self.name2id(rel)
            hash_map = {md5_hex(u): u for u in n2i.values() if u}
            con = _connect(path)
            try:
                for t in self._tables(rel):
                    h = t[4:]
                    username = hash_map.get(h, "")
                    try:
                        n, last = con.execute(
                            f"SELECT COUNT(*), MAX(create_time) FROM {t}").fetchone()
                    except sqlite3.Error:
                        continue
                    if not n:
                        continue
                    raw.append({
                        "db": rel,
                        "table": t,
                        "hash": h,
                        "username": username or f"({h[:8]})",
                        "count": int(n),
                        "last": int(last or 0),
                    })
            finally:
                con.close()

        if not merge:
            raw.sort(key=lambda x: (-x["count"], -x["last"]))
            return raw

        merged: dict[str, dict] = {}
        for item in raw:
            key = item["username"]
            cur = merged.get(key)
            if cur is None:
                merged[key] = dict(item, parts=[{"db": item["db"], "table": item["table"],
                                                 "count": item["count"], "hash": item["hash"]}])
            else:
                cur["count"] += item["count"]
                cur["last"] = max(cur["last"], item["last"])
                cur["parts"].append({"db": item["db"], "table": item["table"],
                                     "count": item["count"], "hash": item["hash"]})
        out = list(merged.values())
        # 会话按"最后一条消息时间"排，更贴近微信习惯
        out.sort(key=lambda x: (-x["last"], -x["count"]))
        return out

    def find_chat(self, needle: str, index=None) -> list[dict]:
        """按 wxid / 备注 / 昵称 / 微信号模糊查找会话。"""
        index = index if index is not None else self.chat_index()
        needle = (needle or "").strip()
        if not needle:
            return index
        low = needle.lower()
        exact, partial, by_contact = [], [], []
        for item in index:
            u = item["username"]
            c = self.contacts.get(u) or {}
            names = [u, c.get("nick", ""), c.get("remark", ""), c.get("alias", "")]
            item["display"] = self.display_name(u)
            if u == needle:
                exact.append(item)
            elif any(low == str(n).lower() for n in names if n):
                exact.append(item)
            elif any(low in str(n).lower() for n in names if n):
                partial.append(item)
        return exact + [i for i in partial if i not in exact]

    # ------------------------------------------------------------ 消息
    def messages(self, item: dict) -> list[dict]:
        parts = item.get("parts") or [{"db": item["db"], "table": item["table"]}]
        rows_all = []
        for part in parts:
            rows_all += self._read_part(part["db"], part["table"])
        rows_all.sort(key=lambda r: (r["sort_seq"], r["local_id"]))
        return rows_all

    def _read_part(self, rel: str, table: str) -> list[dict]:
        n2i = self.name2id(rel)
        con = _connect(self.files[rel])
        try:
            rows = con.execute(
                f"SELECT local_id, server_id, local_type, sort_seq, real_sender_id, create_time, "
                f"message_content, compress_content, source, packed_info_data, "
                f"WCDB_CT_message_content, WCDB_CT_source, status, origin_source "
                f"FROM {table} ORDER BY sort_seq ASC, local_id ASC"
            ).fetchall()
            decomp = _decompress_columns(con, table, ["message_content", "source", "compress_content"])
        finally:
            con.close()

        out = []
        for r in rows:
            (local_id, server_id, local_type, sort_seq, sender_id, create_time,
             content, compress_content, source, packed, ct_c, ct_s, status, origin) = r
            local_id = int(local_id)
            content_txt = _s(content)
            if zstd_codec.is_compressed(content or b""):
                content_txt = decomp.get(("message_content", local_id), "")
            elif ct_c not in (None, 0) and isinstance(content, bytes):
                content_txt = decomp.get(("message_content", local_id), _s(content))
            if isinstance(source, bytes) and zstd_codec.is_compressed(source):
                source_txt = decomp.get(("source", local_id), "")
            else:
                source_txt = _s(source)

            sender = n2i.get(int(sender_id or 0), "")
            lt = int(local_type or 0)
            out.append({
                "local_id": local_id,
                "server_id": int(server_id or 0),
                "sort_seq": int(sort_seq or 0),
                "time": int(create_time or 0),
                "type": lt & 0xFFFFFFFF,
                "sub_type": lt >> 32 if lt > 0xFFFFFFFF else 0,
                "sender": sender,
                "is_self": sender == self.self_username,
                "content": content_txt,
                "source": source_txt,
                "packed": packed if isinstance(packed, bytes) else b"",
                "md5": _md5_from_packed(packed if isinstance(packed, bytes) else b""),
            })
        return out
