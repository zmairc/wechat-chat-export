# docs

这里是给 README 用的图片资源目录。

## 界面截图 `screenshot.png`

**不要**拿真实聊天记录截图——这个仓库是公开的。正确做法是用虚构数据生成一个页面：

```bash
# 1. 生成演示页面（数据全写死在脚本里，不读微信、不联网）
python tools/demo_export.py                       # 输出到 docs/demo/chat.html

# 2. 用 Windows 自带的 Edge 无头模式截图
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" \
  --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1280,900 \
  --screenshot=docs/screenshot.png \
  "file:///<项目绝对路径>/docs/demo/chat.html"
```

- `--window-size` 的高度要略大于页面内容，否则底部会被裁掉；改完示例数据先看一眼
- 想改内容就动 `tools/demo_export.py` 里的 `_entries()`
- `docs/demo/` 是生成物（已忽略），只需要提交 `screenshot.png`

也可以打开真实导出的 `chat.html` 手动截图，但**务必打码**，
别把好友姓名和聊天内容带进公开仓库。
