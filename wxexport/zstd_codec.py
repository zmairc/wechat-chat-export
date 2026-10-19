"""zstd 解压（微信 4.x 会把部分 message_content / source 列用 zstd 压缩）。

不强制依赖：
  1. 有 zstandard 模块就用它（pip install zstandard）；
  2. Python 3.14+ 自带 compression.zstd 就用它；
  3. 否则调用系统里的 Node.js（自 22.15 起 zlib 内置 zstd）；
  4. 都没有就返回 None，导出时用占位文本代替。
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_impl = None
_checked = False

_NODE_SCRIPT = r"""
const fs = require('fs');
const zlib = require('zlib');
const [input, output] = process.argv.slice(2);
const buf = fs.readFileSync(input);
let off = 0;
const chunks = [];
while (off + 4 <= buf.length) {
  const len = buf.readUInt32LE(off); off += 4;
  const frame = buf.subarray(off, off + len); off += len;
  let out;
  try {
    if (len === 0) { out = Buffer.alloc(0); }
    else if (frame.length < 4 || frame[0] !== 0x28 || frame[1] !== 0xb5 || frame[2] !== 0x2f || frame[3] !== 0xfd) {
      out = Buffer.alloc(0);
    } else {
      out = zlib.zstdDecompressSync(frame);
    }
    const head = Buffer.alloc(4);
    head.writeUInt32LE(out.length, 0);
    chunks.push(head, out);
  } catch (e) {
    const head = Buffer.alloc(4);
    head.writeUInt32LE(0xffffffff, 0);
    chunks.push(head);
  }
}
fs.writeFileSync(output, Buffer.concat(chunks));
"""


def _detect():
    global _impl, _checked
    if _checked:
        return _impl
    _checked = True
    try:
        import zstandard  # type: ignore

        _impl = "zstandard"
        return _impl
    except Exception:
        pass
    try:
        from compression import zstd as _z  # type: ignore  # Python 3.14+

        globals()["_pyzstd"] = _z
        _impl = "stdlib"
        return _impl
    except Exception:
        pass
    node = shutil.which("node")
    if node:
        _impl = "node"
        globals()["_node"] = node
        return _impl
    _impl = None
    return None


def is_compressed(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and bytes(data[:4]) == _ZSTD_MAGIC


def decompress(data: bytes):
    """单个 blob；失败返回 None。"""
    if not is_compressed(data):
        return bytes(data)
    res = decompress_many([data])
    return res[0]


def decompress_many(blobs: list[bytes]) -> list[bytes | None]:
    if not blobs:
        return []
    impl = _detect()
    if impl == "node":
        return _node_batch(blobs)
    out: list[bytes | None] = []
    for b in blobs:
        try:
            if impl == "zstandard":
                import zstandard  # type: ignore

                r = zstandard.ZstdDecompressor().decompress(b, max_output_size=64 * 1024 * 1024)
            elif impl == "stdlib":
                r = globals()["_pyzstd"].decompress(b, max_output_size=64 * 1024 * 1024)
            else:
                r = None
        except Exception:
            r = None
        out.append(r)
    return out


def _tmp_root() -> str:
    """优先用工具目录下的 work/tmp（某些环境禁止往系统临时目录写文件）。"""
    env = os.environ.get("WXEXPORT_TMP")
    if env:
        os.makedirs(env, exist_ok=True)
        return env
    tool_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(tool_root, "work", "tmp")
    try:
        os.makedirs(p, exist_ok=True)
        probe = os.path.join(p, ".w")
        with open(probe, "w") as f:
            f.write("1")
        os.remove(probe)
        return p
    except OSError:
        return tempfile.gettempdir()


def _node_batch(blobs: list[bytes]) -> list[bytes | None]:
    import time as _time

    tmpdir = os.path.join(_tmp_root(), f"wxzstd_{os.getpid()}_{int(_time.time() * 1000)}")
    os.makedirs(tmpdir, exist_ok=True)
    try:
        inp = os.path.join(tmpdir, "in.bin")
        outp = os.path.join(tmpdir, "out.bin")
        script = os.path.join(tmpdir, "z.js")
        with open(script, "w", encoding="utf-8") as f:
            f.write(_NODE_SCRIPT)
        with open(inp, "wb") as f:
            for b in blobs:
                f.write(struct.pack("<I", len(b)))
                f.write(b)
        try:
            subprocess.run(
                [globals()["_node"], script, inp, outp],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=300,
            )
        except Exception:
            return [None] * len(blobs)
        results: list[bytes | None] = []
        with open(outp, "rb") as f:
            data = f.read()
        off = 0
        while off + 4 <= len(data):
            ln = struct.unpack_from("<I", data, off)[0]
            off += 4
            if ln == 0xFFFFFFFF:
                results.append(None)
                continue
            results.append(data[off:off + ln])
            off += ln
        if len(results) < len(blobs):
            results += [None] * (len(blobs) - len(results))
        return results[: len(blobs)]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def backend() -> str:
    return _detect() or "none"
