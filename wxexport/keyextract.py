"""密钥提取总入口：先走 4.1+ 的 Config.Cipher 路线，再回退老版内存扫描。"""

from __future__ import annotations

import time

from . import keyscan, wcdb41
from .sqlcipher import verify_key

PBKDF2_ITER_V41 = 256_000


def _verify_against(cand_key: bytes, salt_hex, unresolved: dict, found: dict) -> int:
    matched = 0
    targets = [salt_hex] if salt_hex in unresolved else list(unresolved)
    for sh in targets:
        if sh not in unresolved:
            continue
        db = unresolved[sh][0]
        if verify_key(cand_key, db.page1):
            found[sh] = cand_key
            unresolved.pop(sh, None)
            matched += 1
    return matched


def find_keys(dbs, verbose=True, try_passphrase=False, pids=None) -> dict[str, bytes]:
    salt_group: dict[str, list] = {}
    for db in dbs:
        salt_group.setdefault(db.salt_hex, []).append(db)
    unresolved = dict(salt_group)
    found: dict[str, bytes] = {}

    if pids is None:
        procs = keyscan.list_processes()
        if not procs:
            raise RuntimeError(
                "没有检测到正在运行的微信（Weixin.exe）。\n"
                "微信 4.1 之后数据库密钥只存在于运行中的进程内存里，请先登录微信再运行本工具。"
            )
        pids = [p[0] for p in sorted(procs, key=lambda x: keyscan._ws(x[0]), reverse=True)]

    t0 = time.time()
    for pid in pids:
        try:
            scanner = keyscan.MemoryScanner(pid)
        except OSError as e:
            if verbose:
                print(f"[!] 打不开进程 {pid}: {e}")
            continue
        try:
            if verbose:
                print(f"[*] 扫描进程 {pid} 的 WCDB Config.Cipher ...")
            res = wcdb41.scan_config_cipher(scanner)
            if verbose:
                st = res["stats"]
                print(
                    f"    命中 {st['needle']} 个特征串 / {st['nodes']} 个配置节点 / "
                    f"{st['candidates']} 个候选密钥，{res['elapsed']:.1f}s"
                )
            for key_hex, salt_hex in res["candidates"]:
                if not unresolved:
                    break
                try:
                    key = bytes.fromhex(key_hex)
                except ValueError:
                    continue
                n = _verify_against(key, salt_hex, unresolved, found)
                if n and verbose:
                    print(f"    [+] 校验通过 {n} 个库（{key_hex[:8]}…）")
                if try_passphrase and unresolved:
                    import hashlib

                    for sh, group in list(unresolved.items()):
                        derived = hashlib.pbkdf2_hmac(
                            "sha512", key, bytes.fromhex(sh), PBKDF2_ITER_V41, dklen=32
                        )
                        if verify_key(derived, group[0].page1):
                            found[sh] = derived
                            unresolved.pop(sh)
                            if verbose:
                                print("    [+] passphrase 派生成功")
                            break

            if unresolved:
                if verbose:
                    print("[*] 回退到老版内存扫描（x'<hex>'）...")
                legacy = keyscan.find_keys(dbs, pid=pid, verbose=False)
                for db in dbs:
                    if db.salt_hex in legacy and db.salt_hex in unresolved:
                        found[db.salt_hex] = legacy[db.salt_hex]
                        unresolved.pop(db.salt_hex)
        finally:
            scanner.close()
        if not unresolved:
            break

    if verbose:
        print(
            f"[*] 密钥提取完成：{len(found)}/{len(salt_group)} 个库，耗时 {time.time() - t0:.1f}s"
        )
        for db in dbs:
            mark = "OK  " if db.salt_hex in found else "MISS"
            print(f"    {mark} {db.rel}")

    return {db.rel: found[db.salt_hex] for db in dbs if db.salt_hex in found}
