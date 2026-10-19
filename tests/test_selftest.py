"""把离线自检包成 unittest，方便 CI 和本地 `python -m unittest` 跑。

这些用例全部不接触微信、不联网，可在任何 Windows 机器上跑（需要 Windows 自带的
bcrypt.dll 做 AES）。
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wxexport import selftest  # noqa: E402


class TestSelfChecks(unittest.TestCase):
    def test_aes_vectors(self):
        self.assertTrue(selftest.check_aes_vectors())

    def test_sqlcipher_roundtrip(self):
        self.assertTrue(selftest.check_sqlcipher_roundtrip())

    def test_dat_formats(self):
        self.assertTrue(selftest.check_dat_formats())

    def test_render(self):
        self.assertTrue(selftest.check_render())

    def test_helpers(self):
        self.assertTrue(selftest.check_helpers())

    def test_run_returns_true(self):
        self.assertTrue(selftest.run(verbose=False))


class TestBadInputs(unittest.TestCase):
    """坏输入不能崩，要返回 None / 报清楚的错。"""

    def test_verify_key_rejects_bad_sizes(self):
        from wxexport import sqlcipher

        self.assertFalse(sqlcipher.verify_key(b"short", b"\x00" * 4096))
        self.assertFalse(sqlcipher.verify_key(bytes(32), b"\x00" * 16))

    def test_decrypt_dat_rejects_garbage(self):
        import os
        import tempfile

        from wxexport import media

        fd, path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)
        try:
            with open(path, "wb") as f:
                f.write(b"\x00" * 64)
            self.assertIsNone(media.decrypt_dat(path, None))
        finally:
            os.remove(path)

    def test_align16(self):
        from wxexport import media

        for n in (1, 15, 16, 17, 1024, 1025):
            self.assertEqual(media._align16(n) % 16, 0)
            self.assertGreater(media._align16(n), n)


if __name__ == "__main__":
    unittest.main(verbosity=2)
