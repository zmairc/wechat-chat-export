"""命令行入口：一键导出与某个好友（或群）的全部聊天记录。"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import exporter, imagekey, media as media_mod, pipeline, wxstore


def _hr(t=""):
    print(t)


def _pick(prompt: str, options: list[str], default: int = 0) -> int:
    print(prompt)
    for i, o in enumerate(options, 1):
        print(o)
    while True:
        try:
            raw = input(f"请输入序号（直接回车选 {default + 1}）：").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1


def _fmt_time(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))
    except (ValueError, OSError):
        return "?"


def _safe_name(name: str) -> str:
    for ch in '\\/:*?"<>|\n\r\t':
        name = name.replace(ch, "_")
    return name.strip()[:60] or "chat"


def _try_scan_media_key(account, target, work):
    """实验性：在微信进程内存里找图片 AES 密钥。慢，且不一定能成功。"""
    import glob

    from . import keyscan, mediakey

    attach = os.path.join(account.path, "msg", "attach", target["hash"])
    cands = []
    for pat in ("**/Img/*.dat",):
        for p in glob.glob(os.path.join(attach, pat), recursive=True):
            try:
                with open(p, "rb") as f:
                    if f.read(6) == b"\x07\x08\x56\x32\x08\x07":
                        cands.append(p)
            except OSError:
                continue
    if not cands:
        print("[!] 这个聊天里没有 V2 格式的加密图片，不需要图片密钥。")
        return None
    blocks = []
    for p in cands[:2]:
        with open(p, "rb") as f:
            data = f.read(1200)
        blocks.append(data[15:31])
    procs = keyscan.list_processes()
    if not procs:
        print("[!] 微信没在运行，无法扫描图片密钥。")
        return None
    pid = max(procs, key=lambda p: keyscan._ws(p[0]))[0]
    print(f"[*] 正在进程 {pid} 的内存里找图片 AES 密钥（可能要几分钟，可 Ctrl+C 中断）…")
    try:
        key, addr = mediakey.find_media_key(pid, blocks, stride=8, threads=16,
                                           progress=lambda d, t, t0: None)
    except KeyboardInterrupt:
        print("[!] 已中断，图片将以 .dat 原样导出。")
        return None
    if key:
        print(f"[+] 找到图片密钥：{key.hex()}  (地址 {hex(addr) if addr else '?'})")
        return key
    print("[!] 没找到图片密钥。先关掉这个提示的话：在微信里点开几张图片再运行，或手动 --media-key。")
    return None


def _parse_xor_key(raw) -> int | None:
    """把 0x26 / 26 这样的十六进制写法转成 0~255 的整数。"""
    if raw in (None, ""):
        return None
    s = str(raw).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        v = int(s, 16)
    except ValueError:
        return None
    return v if 0 <= v <= 0xFF else None


def _resolve_media_keys(args, account):
    """决定这次导出用哪套图片密钥：手填 > 离线派生 > （交给内存扫描）。"""
    if getattr(args, "no_media_key", False) and not args.media_key:
        return None, None, ""

    if args.media_key:
        try:
            aes_key = bytes.fromhex(args.media_key.strip())
        except ValueError:
            print("[!] --media-key 不是合法的十六进制，已忽略。")
            aes_key = None
        xor_key = _parse_xor_key(getattr(args, "media_xor_key", None))
        if aes_key and xor_key is None:
            samples = imagekey.v2_samples(account.path)
            xor_key = imagekey.guess_xor_key(samples, aes_key)
            if xor_key is not None:
                print(f"[*] 尾段 XOR 密钥从文件尾反推为 0x{xor_key:02X}")
        return aes_key, xor_key, "手填"

    info = imagekey.find(account.path)
    if info:
        print(f"[+] 图片密钥：{imagekey.describe(info)}")
        return info["aes_key"], info["xor_key"], "离线派生"
    print("[*] 没能离线派生图片密钥（没有 V2 图片，或公式不适用）")
    return None, None, ""


def _locate_account(args):
    accounts = pipeline.list_accounts()
    if not accounts:
        print("[!] 没有找到微信 4.x 的数据目录（xwechat_files）。")
        print("    请确认微信已经登录过，并且数据目录没有被移动。")
        return None
    if args.account:
        for a in accounts:
            if args.account in (a.name, a.username):
                return a
        print(f"[!] 没找到账号 {args.account}，可用账号：{[a.name for a in accounts]}")
        return None
    if len(accounts) == 1 or args.yes:
        return accounts[0]
    opts = [
        f"  {i}. {a.name}（{len(a.message_dbs())} 个消息库，最近更新 "
        f"{_fmt_time(os.path.getmtime(a.message_dbs()[-1]))}）"
        for i, a in enumerate(accounts, 1)
    ]
    idx = _pick("[*] 发现多个微信账号，请选择要导出的账号：", opts)
    return accounts[idx]


def _find_target(store, args):
    index = store.chat_index()
    if not index:
        print("[!] 数据库里没有任何聊天记录。")
        return None
    for item in index:
        item["display"] = store.display_name(item["username"])

    if args.friend:
        hits = [i for i in index if args.friend.lower() in
                (i["display"] + " " + i["username"]).lower()]
        exact = [i for i in hits if args.friend.lower() in
                 (i["display"].lower(), i["username"].lower())]
        pool = exact or hits
        if not pool:
            print(f"[!] 没有找到名字包含「{args.friend}」的会话。")
            return None
        if len(pool) > 1 and not args.yes:
            opts = [f"  {n}. {i['display']}（{i['count']} 条，最后 {_fmt_time(i['last'])}）"
                    for n, i in enumerate(pool[:20], 1)]
            print(f"[*] 找到 {len(pool)} 个匹配的会话：")
            idx = _pick("请选择：", opts)
            return pool[idx]
        return pool[0]

    # 交互式选择：默认列出最近 30 个会话
    recent = sorted(index, key=lambda x: -x["last"])[:30]
    opts = [f"  {n}. {i['display']}（{i['count']} 条，最后 {_fmt_time(i['last'])}）"
            for n, i in enumerate(recent, 1)]
    opts.append("  c. 显示更多会话（按消息条数排序）")
    print("[*] 最近的会话：")
    idx = _pick("请选择要导出的好友/群：", opts)
    if idx >= len(recent):
        top = sorted(index, key=lambda x: -x["count"])[:60]
        opts = [f"  {n}. {i['display']}（{i['count']} 条，最后 {_fmt_time(i['last'])}）"
                for n, i in enumerate(top, 1)]
        idx = _pick("[*] 与消息最多的会话：", opts)
        return top[idx]
    return recent[idx]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="微信聊天记录一键导出（Windows 微信 4.x）：导出与某个好友/群的全部聊天记录",
    )
    ap.add_argument("--friend", "-f", help="好友或群的备注/昵称/wxid（可模糊匹配）")
    ap.add_argument("--account", "-a", help="要导出的微信账号（wxid），默认自动选择")
    ap.add_argument("--out", "-o", help="导出到哪个目录（默认 导出/<名字>_<时间>）")
    ap.add_argument("--work", help="工作目录（放密钥缓存和解密后的数据库）")
    ap.add_argument("--format", default="html,txt", help="导出格式，逗号分隔：html,txt")
    ap.add_argument("--no-media", action="store_true", help="不导出图片/视频/文件，只导文字")
    ap.add_argument("--media-key", help="图片解密用的 AES-128 密钥（32 位十六进制）；默认自动离线派生")
    ap.add_argument("--media-xor-key", help="图片尾段的单字节 XOR 密钥（十六进制，如 0x26）；一般不用填")
    ap.add_argument("--no-media-key", action="store_true",
                    help="不自动派生图片密钥（解不开的图片按 .dat 原样保存）")
    ap.add_argument("--scan-media-key", action="store_true",
                    help="（实验性，较慢）离线派生失败时，扫描微信进程内存找图片密钥")
    ap.add_argument("--list", action="store_true", help="只列出会话，不导出")
    ap.add_argument("--rescan", action="store_true", help="忽略缓存的密钥，重新从内存提取")
    ap.add_argument("--no-open", action="store_true", help="导出后不自动打开 HTML")
    ap.add_argument("--yes", "-y", action="store_true", help="自动确认（无人值守）")
    args = ap.parse_args(argv)

    print("=" * 66)
    print("  微信聊天记录一键导出（微信 4.x / Windows）")
    print("=" * 66)

    account = _locate_account(args)
    if not account:
        return 2
    print(f"[*] 账号：{account.name}")
    print(f"[*] 数据目录：{account.db_dir}")

    work = args.work or pipeline.default_work_dir()
    try:
        keys = pipeline.get_keys(account, work, force_scan=args.rescan)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 取密钥失败：{e}")
        print("    提示：微信必须处于登录/运行状态，密钥只在它的进程内存里。")
        return 3
    if not keys:
        print("[!] 没能拿到数据库密钥，无法继续。")
        return 3

    print("[*] 解密数据库 ...")
    decrypted = pipeline.decrypt_required(account, work, keys)
    store = wxstore.Store(account, decrypted, work)

    if args.list:
        index = store.chat_index()
        print(f"[*] 共 {len(index)} 个会话：")
        for item in sorted(index, key=lambda x: -x["last"]):
            print(f"    {_fmt_time(item['last'])}  {item['count']:6d} 条  "
                  f"{store.display_name(item['username'])}  [{item['username']}]")
        return 0

    target = _find_target(store, args)
    if not target:
        return 4
    display = store.display_name(target["username"])
    print(f"[*] 目标：{display}（{target['username']}），共 {target['count']} 条消息")

    stamp = time.strftime("%Y%m%d_%H%M")
    out_dir = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "导出", f"{_safe_name(display)}_{stamp}")
    os.makedirs(out_dir, exist_ok=True)

    aes_key, xor_key, key_source = (None, None, "")
    if not args.no_media:
        aes_key, xor_key, key_source = _resolve_media_keys(args, account)
        if aes_key is None and getattr(args, "scan_media_key", False):
            aes_key = _try_scan_media_key(account, target, work)
            if aes_key:
                xor_key = imagekey.guess_xor_key(imagekey.v2_samples(account.path), aes_key)
                key_source = "内存扫描"
    me = media_mod.MediaExporter(account, out_dir, aes_key, xor_key) if not args.no_media else None

    print("[*] 读取并渲染消息 ...")
    t0 = time.time()
    entries = exporter.build_entries(store, target, me, include_media=not args.no_media)
    print(f"    共 {len(entries)} 条，用时 {time.time() - t0:.1f}s")

    first = entries[0]["dt"].strftime("%Y-%m-%d") if entries else ""
    last = entries[-1]["dt"].strftime("%Y-%m-%d") if entries else ""
    title = f"与 {display} 的聊天记录"
    subtitle = f"{len(entries)} 条 · {first} ~ {last} · 导出于 {time.strftime('%Y-%m-%d %H:%M')}"

    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    outputs = []
    if "html" in formats:
        path = os.path.join(out_dir, "chat.html")
        exporter.write_html(entries, title, subtitle, path)
        outputs.append(path)
    if "txt" in formats:
        path = os.path.join(out_dir, "chat.txt")
        exporter.write_txt(entries, title, subtitle, path)
        outputs.append(path)

    print("")
    print("=" * 66)
    print(f"  导出完成：{out_dir}")
    for p in outputs:
        print(f"    - {os.path.basename(p)}  ({os.path.getsize(p) // 1024} KB)")
    if me is not None:
        st = me.stats
        print(f"    媒体：图片 {st['image']} 张、视频 {st['video']} 个、"
              f"文件 {st['file']} 个、缺失 {st['missing']} 个")
        detail = []
        if st.get("image_hevc"):
            detail.append(f"HEVC 封装的动图/原图 {st['image_hevc']} 张（已解密，浏览器不能直接显示）")
        if st.get("image_raw"):
            detail.append(f"未解开 {st['image_raw']} 张")
        if detail:
            print(f"          其中 {'；'.join(detail)}")
        if st.get("image_raw"):
            if key_source:
                print("    提示：这些图片用现有密钥解不开，可能是新版本换了格式；原文件已原样保留。")
            else:
                print("    提示：没拿到图片密钥，解不开的原图会以 .dat 原样保存在 media/ 目录，不会丢数据。")
    print("=" * 66)

    if outputs and not args.no_open and "html" in formats:
        try:
            os.startfile(outputs[0])  # noqa: S606
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
