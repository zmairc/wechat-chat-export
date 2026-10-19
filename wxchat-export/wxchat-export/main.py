#!/usr/bin/env python
"""微信聊天记录一键导出 —— 双击这个文件或在命令行里运行 python main.py

用法：
    python main.py                 # 交互式：选账号 → 选好友/群 → 导出
    python main.py --list          # 只列出会话和消息条数
    python main.py --friend 张三    # 直接按备注/昵称/wxid 导出
    python main.py --selftest      # 离线自检（不读微信、不联网，验证解密逻辑）
    python main.py --help
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wxexport.cli import main  # noqa: E402


def _selftest() -> int:
    from wxexport.selftest import run

    return 0 if run() else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(_selftest())
    sys.exit(main())
