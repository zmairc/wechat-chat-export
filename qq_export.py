"""QQ NT 聊天记录导出（命令行入口）。

用法：

```bash
python qq_export.py probe                       # 看看找到哪些库、结构对不对
python qq_export.py decrypt --key <16位口令>     # 解密到 work/qq_decrypted/
python qq_export.py schema                      # 解密后打印表与列（用来核对解析规则）
```

口令从哪来：QQ 的 passphrase 只在 `nt_sqlite3_key_v2` 调用瞬间存在，不常驻内存。
可以设环境变量 `QQ_DB_KEY`，或参考 `docs/QQ.md` 里写的办法取一次（拿到后可以重复用）。
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wxexport import qq  # noqa: E402


def force_utf8_stdio() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def default_out() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "work", "qq_decrypted")


def cmd_probe(args) -> int:
    dbs = qq.find_databases(args.root)
    if not dbs:
        print("[!] 没找到 QQ NT 的数据库。")
        print("    预期位置：%USERPROFILE%\\Documents\\Tencent Files\\<QQ号>\\nt_qq\\nt_db\\")
        return 2
    print(f"[*] 找到 {len(dbs)} 个库：")
    for db in dbs:
        ok, detail = db.structure_ok()
        flag = "OK  " if ok else "WARN"
        print(f"    [{flag}] {db.name:24s} {db.size/1024:9.1f} KB   {detail}")
    print("\n[*] 下一步：拿到 16 位口令后执行")
    print("    python qq_export.py decrypt --key <口令>")
    return 0


def _load_key(args) -> bytes | None:
    key = args.key or os.environ.get("QQ_DB_KEY")
    if not key:
        return None
    return key.encode("utf-8")


def cmd_decrypt(args) -> int:
    key = _load_key(args)
    if not key:
        print("[!] 需要口令：--key <16位> 或环境变量 QQ_DB_KEY")
        print("    取口令的办法见 docs/QQ.md（只需取一次，之后可复用）")
        return 3
    dbs = qq.find_databases(args.root)
    if args.db:
        dbs = [d for d in dbs if d.name == args.db]
    if not dbs:
        print("[!] 没有可处理的库")
        return 2

    out_dir = args.out or default_out()
    os.makedirs(out_dir, exist_ok=True)
    print(f"[*] 输出目录：{out_dir}")
    ok = bad = 0
    params_used = set()
    for db in dbs:
        dst = os.path.join(out_dir, db.name)
        t0 = time.time()
        with open(db.path, "rb") as f:
            head = f.read(16)
        if head == qq.SQLITE_HDR:
            shutil.copy2(db.path, dst)
            print(f"    [PLAIN] {db.name:24s} 本身就是明文")
            ok += 1
            continue
        param = qq.detect(key, db.page1())
        if not param:
            print(f"    [BADKEY] {db.name:24s} 口令不对，或参数不在已知组合里")
            bad += 1
            continue
        res = qq.decrypt_db(db, dst, key, param, apply_wal=args.wal)
        if not res.get("ok"):
            print(f"    [ERR ] {db.name:24s} {res.get('error')}")
            bad += 1
            continue
        state = qq.integrity(dst)
        params_used.add(param.name)
        tag = "OK  " if state == "ok" else "WARN"
        print(f"    [{tag}] {db.name:24s} {res['pages']:5d} 页  {param.name}"
              f"  {time.time()-t0:.1f}s" + ("" if state == "ok" else f"  integrity={state[:40]}"))
        ok += 1
    print(f"\n[*] 完成：{ok} 成功 / {bad} 失败；参数：{', '.join(sorted(params_used)) or '无'}")
    if ok:
        print(f"[*] 明文库在 {out_dir}，可用 `python qq_export.py schema` 看表结构")
    return 0 if ok else 4


def cmd_schema(args) -> int:
    out_dir = args.out or default_out()
    targets = [f for f in sorted(os.listdir(out_dir)) if f.endswith(".db")] if os.path.isdir(out_dir) else []
    if not targets:
        print(f"[!] {out_dir} 里没有解密后的库，先跑 decrypt")
        return 2
    for name in targets:
        if args.db and name != args.db:
            continue
        path = os.path.join(out_dir, name)
        try:
            tables = qq.describe_schema(path)
        except Exception as e:      # noqa: BLE001
            print(f"[!] {name}: {e}")
            continue
        total = sum(len(c) for _t, c in tables)
        print(f"=== {name}  ({len(tables)} 表 / {total} 列)")
        for t, cols in tables:
            print(f"    {t:28s} {len(cols):3d} 列")
    return 0


def main(argv=None) -> int:
    force_utf8_stdio()
    ap = argparse.ArgumentParser(description="QQ NT（Windows 9.9.x）本地数据库导出")
    ap.add_argument("--root", action="append", help="额外的数据根目录（可多次）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("probe", help="列出找到的库并检查结构")

    p = sub.add_parser("decrypt", help="用口令解密到明文 SQLite")
    p.add_argument("--key", help="16 位 passphrase（或用环境变量 QQ_DB_KEY）")
    p.add_argument("--db", help="只处理指定文件名")
    p.add_argument("--out", help="输出目录，默认 work/qq_decrypted")
    p.add_argument("--wal", action="store_true", help="同时回放 -wal 里已提交的帧")

    p = sub.add_parser("schema", help="打印解密后的表结构")
    p.add_argument("--db", help="只看某个库")
    p.add_argument("--out", help="解密目录，默认 work/qq_decrypted")

    args = ap.parse_args(argv)
    return {"probe": cmd_probe, "decrypt": cmd_decrypt, "schema": cmd_schema}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
