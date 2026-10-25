"""离线自检：完全不接触微信、不联网、不需要第三方库。

这个工具要读别的进程内存，别人看代码时难免心里打鼓，所以把「格式理解对不对」
做成可复现的断言：自己造一个 SQLCipher 加密页面、自己造几个 .dat 文件，再走
项目里的解密代码，看能不能原样还原。`python main.py --selftest` 就是这个。

测试用的 AES **加密**实现只存在于这里（ctypes 调 Windows CNG），生产代码只有
解密路径——工具本身没有任何加密/写回能力。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import os
import platform
import shutil
import struct
import sys
import traceback

from . import imagekey, media, sqlcipher, wxmsg
from .cng_aes import AesCbc, AesEcb

BLOCK = 16


# --------------------------------------------------------- 测试用 AES 加密

class _Enc:
    """只给自检用的 AES 加密器（Windows CNG，BCryptEncrypt）。"""

    def __init__(self, key: bytes, mode: str = "CBC"):
        self._b = ctypes.WinDLL("bcrypt")
        b = self._b
        b.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
        b.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), wt.LPCWSTR, wt.LPCWSTR, wt.ULONG]
        b.BCryptSetProperty.restype = ctypes.c_long
        b.BCryptSetProperty.argtypes = [
            ctypes.c_void_p, wt.LPCWSTR, ctypes.c_char_p, wt.ULONG, wt.ULONG]
        b.BCryptGenerateSymmetricKey.restype = ctypes.c_long
        b.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            wt.ULONG, ctypes.c_char_p, wt.ULONG, wt.ULONG]
        b.BCryptEncrypt.restype = ctypes.c_long
        b.BCryptEncrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, wt.ULONG, ctypes.c_void_p,
            ctypes.c_void_p, wt.ULONG, ctypes.c_char_p, wt.ULONG,
            ctypes.POINTER(wt.ULONG), wt.ULONG]
        b.BCryptDestroyKey.restype = ctypes.c_long
        b.BCryptDestroyKey.argtypes = [ctypes.c_void_p]

        alg = ctypes.c_void_p()
        st = b.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0)
        if st != 0:
            raise Fail(f"BCryptOpenAlgorithmProvider 失败 0x{st & 0xFFFFFFFF:08x}")
        m = f"ChainingMode{mode}".encode("utf-16-le")
        st = b.BCryptSetProperty(alg, "ChainingMode", m, len(m), 0)
        if st != 0:
            raise Fail(f"BCryptSetProperty({mode}) 失败 0x{st & 0xFFFFFFFF:08x}")
        hkey = ctypes.c_void_p()
        st = b.BCryptGenerateSymmetricKey(
            alg, ctypes.byref(hkey), None, 0, key, len(key), 0)
        if st != 0:
            raise Fail(f"BCryptGenerateSymmetricKey 失败 0x{st & 0xFFFFFFFF:08x}"
                       f"（key len={len(key)}, mode={mode}）")
        self._alg, self._hkey = alg, hkey

    def encrypt(self, data: bytes, iv: bytes | None = None) -> bytes:
        if len(data) % BLOCK:
            raise Fail(f"自检内部错误：待加密数据不是 16 的整数倍（{len(data)} 字节）")
        out = ctypes.create_string_buffer(len(data))
        n = wt.ULONG(0)
        # 同样要用可写 IV 缓冲区：CNG 会把链式值写回去
        iv_buf = ctypes.create_string_buffer(bytes(iv), BLOCK) if iv else None
        st = self._b.BCryptEncrypt(
            self._hkey, data, len(data), None,
            ctypes.cast(iv_buf, ctypes.c_void_p) if iv_buf else None,
            BLOCK if iv_buf else 0,
            out, len(data), ctypes.byref(n), 0)
        assert st == 0, f"BCryptEncrypt 失败 0x{st & 0xFFFFFFFF:08x}"
        return out.raw[:n.value]


def _pkcs7(data: bytes) -> bytes:
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


# ------------------------------------------------------------------- 断言

class Fail(AssertionError):
    pass


def _check(cond, msg):
    if not cond:
        raise Fail(msg)


# ------------------------------------------------------------ 1. AES 向量

def check_aes_vectors() -> str:
    # NIST SP 800-38A F.2.6：AES-256-CBC 单块向量（这里只取第一块）
    key256 = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ct = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    got = AesCbc(key256).decrypt(ct, iv)
    _check(got == pt, "AES-256-CBC（CNG）解密结果不对")
    got_pure = AesCbc(key256, force_pure=True).decrypt(ct, iv)
    _check(got_pure == pt, "AES-256-CBC（纯 Python 兜底）解密结果不对")

    # FIPS-197 AES-128 单块向量
    k128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    c128 = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    p128 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    _check(AesEcb(k128).decrypt(c128) == p128, "AES-128-ECB 解密结果不对")
    _check(_Enc(k128, "ECB").encrypt(p128) == c128, "AES-128-ECB 加密自检不对")
    return "AES 向量（CBC/ECB、CNG 与纯 Python）"


# ------------------------------------------------- 2. SQLCipher 页面往返

def _make_db_pages(key: bytes, salt: bytes, pages: int = 3):
    """按项目里解密的逆过程，造一个"加密的页列表"。"""
    mac_key = sqlcipher.derive_mac_key(key, salt)
    enc = _Enc(key, "CBC")
    out = []
    for pgno in range(1, pages + 1):
        reserve = b"\x00" * sqlcipher.RESERVE_SZ
        if pgno == 1:
            # page1 明文 = SQLite 头(16) + 4000 字节 + 80 字节保留区（解密后会填 0）
            plain = sqlcipher.SQLITE_HDR + bytes(
                (i * 37 + 11) % 251 for i in range(sqlcipher.PAGE_SZ - 16 - sqlcipher.RESERVE_SZ)
            ) + reserve
        else:
            plain = bytes(
                (i * 13 + pgno * 7) % 256
                for i in range(sqlcipher.PAGE_SZ - sqlcipher.RESERVE_SZ)
            ) + reserve
        iv = bytes(((pgno * 31 + i) % 256) for i in range(16))  # 固定 IV，保证可复现
        if pgno == 1:
            ct = enc.encrypt(plain[16:sqlcipher.PAGE_SZ - sqlcipher.RESERVE_SZ], iv)
            raw = salt + ct + iv
        else:
            ct = enc.encrypt(plain[:sqlcipher.PAGE_SZ - sqlcipher.RESERVE_SZ], iv)
            raw = ct + iv
        # HMAC 覆盖的是「密文 + IV」，page1 的 salt 不参与
        h = hmac_mod.new(mac_key, ct + iv, hashlib.sha512)
        h.update(struct.pack("<I", pgno))
        out.append((pgno, raw + h.digest()[: sqlcipher.HMAC_SZ], plain))
    return out


def check_sqlcipher_roundtrip() -> str:
    key = bytes(range(32))
    salt = bytes.fromhex("415a7d8fe309c9aa49af0a9175cd367c")
    pages = _make_db_pages(key, salt)

    page1 = pages[0][1]
    _check(len(page1) == sqlcipher.PAGE_SZ, "page1 长度不是 4096")
    _check(sqlcipher.verify_key(key, page1), "正确密钥的 HMAC 校验没通过")
    _check(not sqlcipher.verify_key(key[::-1], page1), "错误密钥竟然通过了 HMAC 校验")

    dec = sqlcipher.PageDecryptor(key)
    for pgno, raw, plain in pages:
        got = dec.page(raw, pgno)
        _check(got == plain, f"第 {pgno} 页解密结果与原文不一致")
    return "SQLCipher 4 页面还原 + HMAC 校验"


# ------------------------------------------------------ 3. 图片 .dat 解密

def _make_jpeg(total: int) -> bytes:
    head = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    body = bytes((i * 7 + 3) % 256 for i in range(total - len(head) - 2))
    return head + body + b"\xff\xd9"


def _make_v2(jpeg: bytes, aes_key: bytes, xor_key: int = 0x88, aes_size: int = 1024):
    aes_part = _pkcs7(jpeg[:aes_size])
    enc_aes = _Enc(aes_key, "ECB").encrypt(aes_part)
    rest = jpeg[aes_size:]
    xor_part = bytes(b ^ xor_key for b in rest)
    header = (media.V2_SIG
              + struct.pack("<II", aes_size, len(xor_part))
              + b"\x00")
    _check(len(header) == 15, "V2 头部长度应为 15")
    return header + enc_aes + xor_part


def _make_v1(jpeg: bytes, aes_size: int = 1024):
    aes_part = _pkcs7(jpeg[:aes_size])
    enc_aes = _Enc(media.V1_KEY, "ECB").encrypt(aes_part)
    rest = jpeg[aes_size:]
    return (media.V1_SIG + struct.pack("<II", aes_size, len(rest)) + b"\x00"
            + enc_aes + bytes(b ^ media.V2_XOR for b in rest))


def check_dat_formats() -> str:
    tmp = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "work", "tmp"))
    os.makedirs(tmp, exist_ok=True)
    try:
        jpeg = _make_jpeg(8192)
        aes_key = bytes.fromhex("0123456789abcdeffedcba9876543210")

        cases = {
            "v2": (_make_v2(jpeg, aes_key), aes_key),
            "v1": (_make_v1(jpeg), None),
            "xor": (bytes(b ^ 0x5A for b in jpeg), None),
        }
        for name, (blob, key) in cases.items():
            path = os.path.join(tmp, f"selftest_{name}.dat")
            try:
                with open(path, "wb") as f:
                    f.write(blob)
                got = media.decrypt_dat(path, key)
                _check(got is not None, f"{name} 格式解不开")
                data, ext = got
                _check(ext == "jpg", f"{name} 格式识别出的扩展名是 {ext}")
                _check(data == jpeg, f"{name} 格式解密结果与原始 JPEG 不一致")
                os.remove(path)
            except Fail:
                raise
            except Exception as e:      # noqa: BLE001 - 把用例名带进消息里
                raise Fail(f"{name} 用例异常：{type(e).__name__}: {e or repr(e)}") from e
        # 没有密钥时 V2 应该诚实地解不开
        path = os.path.join(tmp, "selftest_v2_nokey.dat")
        with open(path, "wb") as f:
            f.write(_make_v2(jpeg, aes_key))
        _check(media.decrypt_dat(path, None) is None, "没有密钥时 V2 却解密成功了？")
        os.remove(path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return "图片 .dat（V2 / V1 / 旧 XOR）解密"


# ---------------------------------------------------------- 4. 消息渲染

def check_render() -> str:
    cases = [
        ({"type": 1, "sub_type": 0, "content": "你好", "md5": ""}, {}, "text", "你好"),
        ({"type": 3, "sub_type": 0,
          "content": '<msg><img md5="0123456789abcdef0123456789abcdef"/></msg>',
          "md5": ""}, {}, "image", "[图片]"),
        ({"type": 34, "sub_type": 0, "content": '<msg><voicemsg length="2048"/></msg>',
          "md5": ""}, {}, "voice", "[语音 2\"]"),
        ({"type": 43, "sub_type": 0, "content": '<msg><videomsg playlength="11"/></msg>',
          "md5": ""}, {}, "video", "[视频 11 秒]"),
        ({"type": 47, "sub_type": 0, "content": '<msg><emoji md5="aa"/></msg>',
          "md5": ""}, {}, "sticker", "[表情]"),
        ({"type": 49, "sub_type": 6,
          "content": "<msg><appmsg><title>报告.docx</title><type>6</type>"
                     '<appattach totallen="1234"/></appmsg></msg>',
          "md5": ""}, {}, "file", "报告.docx"),
        ({"type": 49, "sub_type": 57,
          "content": "<msg><appmsg><title>打错字了</title><type>57</type>"
                     "<refermsg><displayname>张三</displayname><type>1</type>"
                     "<content>原文</content></refermsg></appmsg></msg>",
          "md5": ""}, {}, "quote", "打错字了"),
        ({"type": 49, "sub_type": 2000,
          "content": "<msg><appmsg><title>微信转账</title><type>2000</type>"
                     "<des>收到转账 2.00 元</des></appmsg></msg>",
          "md5": ""}, {}, "transfer", None),
        ({"type": 10000, "sub_type": 0, "content": "你撤回了一条消息",
          "md5": ""}, {}, "system", None),
        ({"type": 10002, "sub_type": 0,
          "content": '<sysmsg type="revokemsg"><replacemsg>李四撤回了一条消息</replacemsg>'
                     "</sysmsg>", "md5": ""}, {}, "system", "李四撤回了一条消息"),
    ]
    for msg, kw, kind, text in cases:
        r = wxmsg.render(msg, **kw)
        _check(r["kind"] == kind, f"类型 {msg['type']} 渲染成 {r['kind']}，期望 {kind}")
        if text is not None:
            _check(r["text"] == text, f"类型 {msg['type']} 文本是 {r['text']!r}，期望 {text!r}")

    # 群聊消息内容开头的 "wxid_xxx: " 前缀要剥掉
    r = wxmsg.render({"type": 1, "sub_type": 0, "content": "wxid_abc123: 哈哈哈",
                      "md5": ""}, is_chatroom=True)
    _check(r["text"] == "哈哈哈", f"群聊前缀没剥干净：{r['text']!r}")

    # packed_info_data 里的文件 md5
    from .wxstore import _md5_from_packed
    packed = b'\x08\x02\x12\x22\x0a\x20' + b"0123456789abcdef0123456789abcdef"
    _check(_md5_from_packed(packed) == "0123456789abcdef0123456789abcdef",
           "从 packed_info_data 提取 md5 失败")
    _check(_md5_from_packed(b"") == "", "空 packed_info 应该返回空串")
    return "消息类型渲染 + 群聊前缀 + 媒体 md5 提取"


# ------------------------------------------------------------- 5. 杂项

def check_helpers() -> str:
    from .pipeline import Account

    acc = Account(r"X:\xwechat_files\wxid_abcd1234_ef56")
    _check(acc.username == "wxid_abcd1234", f"账号名解析不对：{acc.username}")
    _check(media._align16(1024) == 1040, "_align16 对 16 的整数倍应额外补一整块")
    _check(media._align16(1000) == 1008, "_align16 向上对齐错了")

    from .exporter import _fmt_size
    _check(_fmt_size(0) == "" and _fmt_size(2048) == "2.0KB", "_fmt_size 输出不对")

    from . import zstd_codec
    _check(zstd_codec.is_compressed(b"\x28\xb5\x2f\xfd\x00"), "zstd 魔数识别失败")
    _check(not zstd_codec.is_compressed(b"hello"), "普通文本被当成 zstd 了")
    return "辅助函数（账号解析 / 对齐 / 大小格式化 / zstd 魔数）"


# ------------------------------------------- 6. 图片密钥离线派生（imagekey）

def check_image_keys() -> str:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "work", "tmp"))
    kv_dir = os.path.join(root, "selftest_kv")
    acc_dir = os.path.join(root, "selftest_acc", "wxid_test_c23a")
    img_dir = os.path.join(acc_dir, "msg", "attach", "abc123", "Img")
    uin = 123456789
    try:
        # ---- 公式本身：md5(f"{uin}{wxid}")[:16] + uin & 0xFF
        want = hashlib.md5(f"{uin}wxid_test".encode()).hexdigest()[:16].encode()
        xor_key, aes_key = imagekey.derive(uin, "wxid_test")
        _check(aes_key == want, f"派生出的 aes_key 不对：{aes_key!r}")
        _check(xor_key == (uin & 0xFF) == 0x15, f"xor_key 应为 uin & 0xFF，实际 {xor_key:#x}")

        # ---- 目录名清洗与后缀
        _check(imagekey.clean_wxid("wxid_abc_c23a") == "wxid_abc", "clean_wxid 没去掉 _c23a 后缀")
        _check(imagekey.suffix_of("wxid_abc_c23a") == "c23a", "suffix_of 取错后缀")
        _check("wxid_abc" in imagekey.wxid_variants("wxid_abc_c23a"), "候选 wxid 里没有去后缀的写法")

        # ---- kvcomm 文件名里取 uin（key_0_ 这类占位项必须跳过）
        os.makedirs(kv_dir, exist_ok=True)
        for name in (f"key_{uin}_1_2_3_3600_ready.statistic", "key_0_9_9_9_input.statistic"):
            with open(os.path.join(kv_dir, name), "wb"):
                pass
        _check(imagekey.uins_from_kvcomm([kv_dir]) == [uin],
               f"uin 提取不对：{imagekey.uins_from_kvcomm([kv_dir])}")

        # ---- 造一个账号目录 + 三张 V2 图片，走完整 discover 流程
        os.makedirs(img_dir, exist_ok=True)
        jpeg = _make_jpeg(8192)
        for i in range(3):
            with open(os.path.join(img_dir, f"aa{i}.dat"), "wb") as f:
                f.write(_make_v2(jpeg, aes_key, xor_key=xor_key))

        orig_dirs = imagekey.kvcomm_dirs
        imagekey.kvcomm_dirs = lambda: [kv_dir]   # 只认这份假的 kvcomm
        try:
            info = imagekey.find(acc_dir, allow_bruteforce=False)
        finally:
            imagekey.kvcomm_dirs = orig_dirs
        _check(info is not None, "在自造的账号目录上没能派生图片密钥")
        _check(info["uin"] == uin and info["wxid"] == "wxid_test", f"派生结果不对：{info}")
        _check(info["verified"] == info["samples"] == 3,
               f"样本验证数不对：{info['verified']}/{info['samples']}")

        sample = os.path.join(img_dir, "aa0.dat")
        got = media.decrypt_dat(sample, info["aes_key"], info["xor_key"])
        _check(got is not None and got[0] == jpeg, "用派生密钥没能还原出原始 JPEG")
        _check(got[1] == "jpg", f"识别出的扩展名是 {got[1]}")

        # ---- 尾段 XOR 密钥必须真的用上：用错密钥时尾部会坏
        wrong = media.decrypt_dat(sample, info["aes_key"], 0x88)
        _check(wrong is not None, "换了错的 xor_key 就连头都解不开了？")
        _check(wrong[0] != jpeg and not wrong[0].endswith(b"\xff\xd9"),
               "xor_key 没生效——换了密钥居然还原出一模一样的结果")

        # ---- 只给 AES 密钥时，能从文件尾反推出 xor_key
        guessed = imagekey.guess_xor_key([sample], info["aes_key"])
        _check(guessed == info["xor_key"], f"反推出的 xor_key 是 {guessed}，应为 {info['xor_key']}")
        return "图片密钥派生（含尾段 XOR 密钥与文件尾反推）"
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------ 7. HEVC / wxgf 抽流与转码

def check_hevc() -> str:
    from . import hevc

    # 伪造一个 wxgf 容器：头部里故意塞一个「假起始码 + NAL 类型 0」，真流在 VPS 处
    vps = b"\x00\x00\x00\x01\x40\x01\x0c\x01\xff\xff\x01\x60"
    body = b"wxgf" + b"\x13\x00\x02\x04\x38\x09\x60" + b"\x00\x00\x00\x01\x00" + b"\xaa" * 12
    blob = body + vps + b"\x00\x00\x00\x01\x42\x01\x01\x60"
    stream = hevc.extract_stream(blob)
    _check(stream is not None, "wxgf 里没抽出 HEVC 码流")
    _check(stream.startswith(b"\x00\x00\x00\x01\x40\x01"), "抽出的码流不是从 VPS 开始")
    _check(stream == vps + b"\x00\x00\x00\x01\x42\x01\x01\x60", "抽出的码流内容不对")

    # 没有 VPS 的容器要老实返回 None，不能瞎截一段给播放器
    _check(hevc.extract_stream(b"wxgf" + b"\x00" * 40) is None, "没有 VPS 却返回了数据")
    _check(hevc.extract_stream(b"not a wxgf file") is None, "非 wxgf 被当成了 HEVC")
    _check(hevc.extract_stream(vps) == vps, "裸 Annex-B 码流应该原样返回")

    # 少数文件在真 VPS 前有一段「假 VPS」（NAL 32 但 layer_id 不是 0），要跳过它
    bogus = b"\x00\x00\x00\x01\x40\x4d\x00\x01\x40\x40"
    real = b"\x00\x00\x00\x01\x40\x01\x0c\x01"
    got = hevc.extract_stream(b"wxgf" + b"\x13" * 5 + bogus + real)
    _check(got == real, "没能跳过假的 VPS，抽出的码流起点不对")

    # 找不到 ffmpeg 时必须安静地返回 None，而不是抛异常
    _check(hevc.find_ffmpeg(r"C:\definitely\not\here\ffmpeg.exe") is None,
           "不存在的 ffmpeg 路径居然返回了值")
    _check(hevc.to_jpeg(r"C:\definitely\not\here\ffmpeg.exe", vps) is None,
           "ffmpeg 不存在时 to_jpeg 应当返回 None")
    return "HEVC 抽流（VPS 定位）与 ffmpeg 缺失时的降级"


# ------------------------------------------------------------------ 入口

def force_utf8_stdio() -> None:
    """把 stdout/stderr 切成 UTF-8。

    某些环境（比如 GitHub Actions 的 Windows runner）默认是 cp1252，
    一 print 中文就抛 UnicodeEncodeError；重定向到文件时同理。
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # 老版本或被包装过的流
            pass


CHECKS = (
    check_aes_vectors,
    check_sqlcipher_roundtrip,
    check_dat_formats,
    check_render,
    check_helpers,
    check_image_keys,
    check_hevc,
)


def run(verbose: bool = True) -> bool:
    force_utf8_stdio()
    print("=" * 66)
    print("  自检：不读微信、不联网，只验证格式解析与解密逻辑")
    print(f"  环境：Python {platform.python_version()} / {platform.platform()}")
    print("=" * 66)
    ok = True
    debug = os.environ.get("SELFTEST_TRACEBACK") == "1"
    for fn in CHECKS:
        try:
            name = fn()
            print(f"  [OK]   {name}")
        except Exception as e:  # noqa: BLE001
            ok = False
            detail = str(e) or repr(e)      # 裸 assert 抛出的 AssertionError 消息是空的
            print(f"  [FAIL] {fn.__name__}: {type(e).__name__}: {detail}")
            # 断言以外的情况（环境问题、代码 bug）必须留完整栈，否则 CI 上只看到 exit 1
            if debug or not isinstance(e, Fail):
                traceback.print_exc()
    print("=" * 66)
    print("  全部通过 ✅" if ok else "  有失败项 ❌")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
