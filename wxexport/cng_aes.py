"""AES-256-CBC 解密，优先使用 Windows 自带的 CNG(bcrypt) ，无第三方依赖。

之所以不用 pycryptodome / cryptography：
  * 目标机器（普通用户、无管理员权限、可能离线）不一定能 pip 安装；
  * bcrypt.dll 是 Windows 自带，速度接近 OpenSSL。
若 CNG 不可用（例如非 Windows），自动回退到纯 Python 实现（较慢但能跑）。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct

BLOCK = 16

# ---------------------------------------------------------------- CNG 实现


class _CngAes:
    """一个 key 对应一个 key handle，CBC/ECB 解密时可复用。"""

    _bcrypt = None
    _algs: dict = {}

    @classmethod
    def _load(cls, mode_name="CBC"):
        if cls._bcrypt is not None:
            return
        bcrypt = ctypes.WinDLL("bcrypt")
        bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
        bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            wt.LPCWSTR,
            wt.LPCWSTR,
            wt.ULONG,
        ]
        bcrypt.BCryptSetProperty.restype = ctypes.c_long
        bcrypt.BCryptSetProperty.argtypes = [
            ctypes.c_void_p,
            wt.LPCWSTR,
            ctypes.c_char_p,
            wt.ULONG,
            wt.ULONG,
        ]
        bcrypt.BCryptGenerateSymmetricKey.restype = ctypes.c_long
        bcrypt.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p,
            wt.ULONG,
            ctypes.c_char_p,
            wt.ULONG,
            wt.ULONG,
        ]
        bcrypt.BCryptDecrypt.restype = ctypes.c_long
        bcrypt.BCryptDecrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            wt.ULONG,
            ctypes.c_void_p,
            ctypes.c_void_p,   # IV 会被 CNG 就地改写，必须传可写缓冲区
            wt.ULONG,
            ctypes.c_char_p,
            wt.ULONG,
            ctypes.POINTER(wt.ULONG),
            wt.ULONG,
        ]
        bcrypt.BCryptDestroyKey.restype = ctypes.c_long
        bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
        bcrypt.BCryptCloseAlgorithmProvider.restype = ctypes.c_long
        bcrypt.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wt.ULONG]
        cls._bcrypt = bcrypt

    @classmethod
    def _get_alg(cls, mode_name: str):
        cls._load(mode_name)
        alg = cls._algs.get(mode_name)
        if alg is not None:
            return alg
        alg = ctypes.c_void_p()
        if cls._bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(alg), "AES", None, 0
        ):
            raise OSError("BCryptOpenAlgorithmProvider 失败")
        mode = f"ChainingMode{mode_name}".encode("utf-16-le")
        if cls._bcrypt.BCryptSetProperty(
            alg, "ChainingMode", mode, len(mode), 0
        ):
            raise OSError(f"BCryptSetProperty({mode_name}) 失败")
        cls._algs[mode_name] = alg
        return alg

    def __init__(self, key: bytes, mode: str = "CBC"):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES 密钥长度必须是 16/24/32 字节")
        self._load()
        self.mode = mode
        self._alg = self._get_alg(mode)
        self.key = bytes(key)
        self._hkey = ctypes.c_void_p()
        if self._bcrypt.BCryptGenerateSymmetricKey(
            self._alg,
            ctypes.byref(self._hkey),
            None,
            0,
            self.key,
            len(self.key),
            0,
        ):
            raise OSError("BCryptGenerateSymmetricKey 失败")

    def decrypt_ecb(self, data: bytes) -> bytes:
        if len(data) % BLOCK:
            data = data[: len(data) - len(data) % BLOCK]
        if not data:
            return b""
        out = ctypes.create_string_buffer(len(data))
        outlen = wt.ULONG(0)
        st = self._bcrypt.BCryptDecrypt(
            self._hkey,
            data,
            len(data),
            None,
            None,
            0,
            out,
            len(data),
            ctypes.byref(outlen),
            0,
        )
        if st:
            raise OSError(f"BCryptDecrypt(ECB) 失败 status=0x{st & 0xFFFFFFFF:08x}")
        return out.raw[: outlen.value]

    def decrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """CBC 解密；data 长度必须是 16 的倍数。"""
        if len(data) % BLOCK:
            raise ValueError("数据长度不是 16 的倍数")
        if not data:
            return b""
        if len(iv) != BLOCK:
            raise ValueError("IV 必须是 16 字节")
        out = ctypes.create_string_buffer(len(data))
        outlen = wt.ULONG(0)
        # CNG 的 CBC 会把链式值写回 IV，所以这里必须用可写缓冲区，
        # 不能直接把 Python 的 bytes 传进去（那会踩坏不可变对象的内存）。
        iv_buf = ctypes.create_string_buffer(bytes(iv), BLOCK)
        st = self._bcrypt.BCryptDecrypt(
            self._hkey,
            data,
            len(data),
            None,
            ctypes.cast(iv_buf, ctypes.c_void_p),
            BLOCK,
            out,
            len(data),
            ctypes.byref(outlen),
            0,
        )
        if st:
            raise OSError(f"BCryptDecrypt 失败 status=0x{st & 0xFFFFFFFF:08x}")
        return out.raw[: outlen.value]

    def __del__(self):
        try:
            if getattr(self, "_hkey", None) and self._hkey:
                self._bcrypt.BCryptDestroyKey(self._hkey)
        except Exception:
            pass


# ------------------------------------------------------- 纯 Python 回退实现

_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


_MUL = {}
for _c in (2, 3, 9, 11, 13, 14):
    _t = [0] * 256
    for _x in range(256):
        _acc = 0
        _m, _a = _c, _x
        while _m:
            if _m & 1:
                _acc ^= _a
            _a = _xtime(_a)
            _m >>= 1
        _t[_x] = _acc
    _MUL[_c] = _t


class _PurePythonAes:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES 密钥长度必须是 16/24/32 字节")
        nk = len(key) // 4
        self.nr = nk + 6
        w = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (self.nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        self._rk = w

    def _decrypt_block(self, block: bytes) -> bytes:
        nr, w = self.nr, self._rk
        s = [block[i] ^ w[nr * 4 + i // 4][i % 4] for i in range(16)]
        for rnd in range(nr - 1, -1, -1):
            # InvShiftRows
            s = [
                s[0], s[13], s[10], s[7],
                s[4], s[1], s[14], s[11],
                s[8], s[5], s[2], s[15],
                s[12], s[9], s[6], s[3],
            ]
            s = [_INV_SBOX[b] for b in s]
            s = [s[i] ^ w[rnd * 4 + i // 4][i % 4] for i in range(16)]
            if rnd:
                m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
                out = [0] * 16
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c: 4 * c + 4]
                    out[4 * c + 0] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
                    out[4 * c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
                    out[4 * c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
                    out[4 * c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
                s = out
        return bytes(s)

    def decrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        if len(data) % BLOCK:
            raise ValueError("数据长度不是 16 的倍数")
        out = bytearray()
        prev = bytes(iv)
        for i in range(0, len(data), BLOCK):
            ct = data[i: i + BLOCK]
            pt = self._decrypt_block(ct)
            out += bytes(a ^ b for a, b in zip(pt, prev))
            prev = ct
        return bytes(out)


# ------------------------------------------------------------------ 对外接口


class AesCbc:
    """AES-CBC 解密器。优先 CNG，失败自动回退。"""

    def __init__(self, key: bytes, force_pure: bool = False):
        self.backend = "pure"
        self._impl = None
        if not force_pure:
            try:
                self._impl = _CngAes(key, "CBC")
                self.backend = "cng"
                return
            except Exception:
                self._impl = None
        self._impl = _PurePythonAes(key)

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        return self._impl.decrypt_cbc(data, iv)


class AesEcb:
    """AES-ECB 解密器（微信 4.x 的 .dat 图片用的就是 AES-128-ECB）。"""

    def __init__(self, key: bytes, force_pure: bool = False):
        self.backend = "pure"
        if not force_pure:
            try:
                self._impl = _CngAes(key, "ECB")
                self.backend = "cng"
                return
            except Exception:
                self._impl = None
        self._impl = _PurePythonAes(key)

    def decrypt(self, data: bytes) -> bytes:
        try:
            return self._impl.decrypt_ecb(data)
        except AttributeError:
            return self._impl.decrypt_cbc(data, bytes(BLOCK))



def selftest() -> str:
    """NIST SP 800-38A F.2.6 (AES-256-CBC) 测试向量自检。"""
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ct = bytes.fromhex(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b"
    )
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    out = AesCbc(key).decrypt(ct, iv)
    return "OK" if out == pt else "FAIL"


if __name__ == "__main__":
    print("AES self-test:", selftest())
