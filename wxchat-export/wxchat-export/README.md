# 微信聊天记录一键导出（Windows · 微信 4.x）

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-0078D4.svg)

<!-- 想要 CI 徽章：把下面这行的 <OWNER> / <REPO> 换成你的 GitHub 用户名和仓库名，再删掉这行注释符号
[![ci](https://github.com/<OWNER>/<REPO>/actions/workflows/ci.yml/badge.svg)](https://github.com/<OWNER>/<REPO>/actions/workflows/ci.yml)
-->

把**你和某个好友（或某个群）的全部聊天记录**一键导出成：

* `chat.html` —— 网页版，像微信聊天窗口一样左右分栏，**能搜索、能只看图片、能直接点开图片/视频/附件**，还能用浏览器"打印成 PDF"
* `chat.txt` —— 纯文本，按日期分段，方便丢进笔记软件、Word，或者拿去做文本分析
* `media/` —— 图片、视频、文档等附件（原文件搬过来，不压缩）

全程**只读**本机数据：不联网、不上传、不修改微信任何文件。数据只留在你自己的电脑上。

> 只用 Python 标准库 + Windows 自带的 `bcrypt.dll`，**不需要 pip install 任何东西**。

<!-- 截图：把图片放到 docs/screenshot.png 后取消注释
![界面截图](docs/screenshot.png)
-->

---

## 安装

1. Windows 10/11，装了 Python 3.10+（[下载](https://www.python.org/downloads/windows/)，安装时勾选 *Add Python to PATH*）
2. 下载本仓库（`Code → Download ZIP`）解压，或 `git clone`
3. 打开微信并登录，然后双击 `一键导出.bat`

零依赖、免安装、免配置。想先确认环境没问题，跑一下离线自检：

```bash
python main.py --selftest
```

自检**不读微信、不联网**，它会自己造一个 SQLCipher 加密页面和几个 `.dat` 图片，
再走一遍项目里的解密代码，验证 AES 向量、页面还原、HMAC 校验、图片格式解析是不是都正常。

可选组件（都不是必需的）：

| 组件 | 作用 | 没有会怎样 |
|---|---|---|
| Node.js 22.15+ | 解压消息里 zstd 压缩的字段 | 少部分（约 1/3）消息正文可能显示不出来 |
| `pip install zstandard` | 同上，替代 Node | 同上（有 Node 时优先用 zstandard） |

---

## 一键使用

**前提：微信正在运行且已登录**（微信 4.1 之后，数据库密钥只存在于微信进程内存里，关掉微信就拿不到）。
然后：

```
双击  一键导出.bat
```

脚本会：

1. 自动找到微信数据目录（`xwechat_files\<你的wxid>`）
2. 从微信进程内存里取出数据库密钥（只读 `ReadProcessMemory`，不注入、不 hook），并校验通过后才使用
3. 解密数据库副本到 `work\decrypted\`（不碰原始文件）
4. 列出最近的会话，你输入序号选一个好友/群
5. 导出到 `导出\<名字>_<时间>\`

命令行用法（更灵活）：

```bash
python main.py                          # 交互式选择好友
python main.py --friend 张三            # 按备注/昵称/wxid 直接导出（模糊匹配）
python main.py --list                   # 只列出所有会话和条数
python main.py --friend 张三 --format html,txt --out D:\导出\张三
python main.py --friend 张三 --no-media # 只要文字，不搬图片视频
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--friend/-f` | 好友或群的备注、昵称、wxid（可模糊匹配；匹配多个会让你选） |
| `--list` | 只列会话，不导出 |
| `--out/-o` | 输出目录，默认 `导出\<名字>_<时间>` |
| `--format` | `html,txt`（默认两个都出），也可以只写 `html` 或 `txt` |
| `--no-media` | 不导出图片/视频/文件 |
| `--media-key` | 图片解密密钥（32 位十六进制），见下方"图片"说明 |
| `--scan-media-key` | 实验性：扫描内存尝试自动找图片密钥（较慢，可能失败） |
| `--work` | 工作目录（密钥缓存 + 解密后的库），默认 `work\` |
| `--rescan` | 忽略缓存，重新从微信内存取一次密钥 |
| `--no-open` | 导完不自动打开 HTML |

---

## 它到底做了什么（原理）

微信 4.x（Weixin.exe）的聊天记录在 `xwechat_files\<wxid>\db_storage\*.db`，
是 **WCDB / SQLCipher 4** 加密的：AES-256-CBC、页大小 4096、每页 16 字节 IV + 64 字节 HMAC-SHA512、保留 80 字节。
每个库文件有自己的 32 字节密钥，密钥只缓存在微信进程内存中。

本工具的步骤：

1. **找库**：扫描磁盘定位 `xwechat_files\*\db_storage`，自动挑最近活跃的账号。
2. **取密钥**（`wxexport/wcdb41.py` + `wxexport/keyextract.py`）：
   * 微信 4.1+ 不再把密钥以明文十六进制缓存在内存，但 WCDB 的配置对象
     `com.Tencent.WCDB.Config.Cipher` 里仍留着一份做了固定字节掩码混淆的
     `x'<64hex 密钥><32hex salt>'`；
   * 顺着"特征字符串 → 引用节点 → 配置对象 → 混淆 blob → 去掩码 → 正则"把它读出来；
   * 用数据库第一页的 HMAC **校验**，校验不通过的候选一律丢弃（防止取错）。
   * 微信 4.0.x 的老版本会自动回退到"内存里直接扫 `x'<hex>'`"的旧办法。
   * 校验通过的密钥缓存到 `work\keys_*.json`，之后即使不开微信也能重复导出。
3. **解密**（`wxexport/sqlcipher.py`）：逐页 AES-256-CBC 还原成标准 SQLite 文件，
   解密后自动跑 `PRAGMA integrity_check`；如果 `-wal` 里还有没合并的数据才尝试回放，
   避免"把已经 checkpoint 的日志再回放一遍"导致库损坏。
4. **读消息**（`wxexport/wxstore.py`、`wxmsg.py`）：
   * 每个会话是一张 `Msg_<md5(用户名)>` 表，同一个人可能分散在多个 `message_N.db` 里，会自动合并；
   * `WCDB_CT_*` 标记为压缩的内容用 zstd 解压（有 `zstandard` 模块就用它，
     没有就调用系统自带 Node.js 的 zlib；都没有则跳过压缩字段）；
   * 消息类型映射成中文：文本、图片、语音、视频、表情、位置、名片、通话、
     引用、文件、转账、红包、链接、小程序、聊天记录、系统提示……
5. **落盘**（`wxexport/exporter.py`、`media.py`）：
   * 图片：`packed_info_data` 里有文件 md5 → 在 `msg\attach\<md5(会话)>\<年-月>\Img\` 找到 `.dat`
     → 自动识别并解密（旧版单字节 XOR / V1 固定密钥 / V2 AES-128-ECB）；
   * 视频：`msg\video\<年-月>\<md5>.mp4`；
   * 文件：`msg\file\<年-月>\<文件名>`（同名多了会带 `1_` 前缀，已做多种匹配兜底）。

---

## 已知限制（重要）

* **微信 4.1+ 的"V2"格式图片**（文件头 `07 08 56 32 08 07`）前 1024 字节是 AES-128-ECB 加密的，
  密钥只在内存里、且不是十六进制字符串形式，本工具在不给密钥的情况下**解不开**。
  这类图片会以 `.dat` 原样保存在 `media/` 里（**不丢数据**），HTML 里显示为"未能解密"。
  办法：用 `--media-key 0123...`（32 位十六进制）传入密钥，或用实验性的 `--scan-media-key` 碰碰运气。
  旧格式（XOR / V1）图片可以自动解开。
* **语音/表情**：微信 4.x 本地基本不落盘（`Voice`/`Emoji` 目录是空的），所以只保留 `[语音 3"]`、`[表情]` 这样的文字占位。
* 需要 Windows + 微信 4.x（本工具在 微信 4.1.13 / Windows 11 上实测通过）。微信 3.x（`WeChat Files\Msg\MSG*.db`）格式不同，不支持。
* 只支持导出的账号是**本机已登录**的那个；密钥缓存后可以离线重复导出。
* 不能导出"已被删除"的消息（服务端才有）。

## 隐私与合规

* 全程本地运行，不联网、不上传，导出的东西就在 `导出\` 目录里。
* 只读取你自己登录的账号在本机的数据；请勿用它处理别人的数据或用于侵权用途。
* 建议把 `work\`、`导出\` 当作敏感目录：里面是解密后的聊天内容。
  不需要时直接删掉即可（下次运行会重新生成）。
* 发布/分享代码时注意：**不要**把 `work\`、`导出\`、`keys_*.json` 一起传上去（仓库里已用 `.gitignore` 挡住）。

## 免责声明

* 本项目仅用于**备份自己设备上自己账号**的聊天记录，请勿用于侵犯他人隐私或任何违法用途。
* 项目的取密钥方式是对**本机内存的只读访问**（`ReadProcessMemory`），不注入、不修改、不 hook、
  不绕过账号安全机制，也不与任何服务器通信。
* 微信版本更新可能导致取密钥的方式失效；本项目不保证长期可用，也不提供任何形式的担保
  （见 [LICENSE](LICENSE)）。
* 使用本工具产生的一切后果（包括但不限于数据损坏、账号异常、法律风险）由使用者自行承担。

## 开发与自检

```bash
python main.py --selftest              # 离线自检：AES 向量 / 页面还原 / HMAC / .dat 格式 / 渲染
python -m unittest discover -s tests   # 同一批断言，CI 里跑的就是这个
```

自检自己造密文再解密，不需要微信、不需要网络、不需要任何第三方库，
所以你在读代码时也能直接验证"它确实只是在做解密和搬运"。
GitHub Actions（[.github/workflows/ci.yml](.github/workflows/ci.yml)）会在
Windows + Python 3.10~3.13 上跑这套自检。

## 目录结构

```
一键导出.bat           ← 双击这个
main.py                ← 命令行入口（--selftest 也在这里）
wxexport/
  cli.py               交互/参数、选好友、导出流程
  pipeline.py          找数据目录、密钥缓存、批量解密
  wcdb41.py            微信 4.1+ Config.Cipher 取密钥
  keyscan.py           内存扫描基础库（进程/区域/读取）
  keyextract.py        取密钥总入口（新路线 + 老路线回退）
  sqlcipher.py         SQLCipher 4 页面解密 / WAL / 完整性校验
  cng_aes.py           AES（Windows CNG，自带无依赖；纯 Python 兜底）
  wxstore.py           联系人、会话索引、消息读取
  wxmsg.py             消息内容解析（XML/类型映射）
  zstd_codec.py        zstd 解压（zstandard / Node.js）
  media.py             图片 .dat 解密、视频/文件搬运
  exporter.py          HTML / TXT 渲染
  selftest.py          离线自检（含测试用的 AES 加密，生产代码只有解密）
  mediakey.py          [实验性] 内存里找图片 AES 密钥
tests/                 unittest 包装
.github/workflows/     CI
work/                  密钥缓存 + 解密后的数据库（敏感，可删）
导出/                  导出结果
```

## 致谢

* WCDB / SQLCipher 的公开文档与格式说明（页大小、HMAC、KDF 参数）
* 社区里关于微信 4.x 数据库与 `.dat` 图片格式的公开讨论，帮助我确认了字段与偏移
* 早期同类工具的思路启发（它们大多已停止维护或下架，本项目是独立实现）

## 贡献

欢迎 Issue / PR：

* 报 bug 请附上微信版本、Windows 版本、运行到哪一步、错误输出（**不要**贴聊天内容或密钥）
* 新版本微信取密钥失效时，最有用的信息是"哪个版本、哪一步失败"
* 代码风格：`wxexport/` 内保持零第三方依赖，新增依赖请走可选路径

---

如果这个工具帮你把珍贵的聊天记录留住了，点个 ⭐ 就好。


## 常见问题

**Q：提示"没有检测到正在运行的微信"？**
A：先打开微信并登录，再运行。密钥只在运行时内存里。

**Q：提示"打不开进程"？**
A：用同一用户运行即可；个别环境（比如微信以管理员身份启动）需要本工具也用管理员身份运行。

**Q：导出要多久？**
A：纯文字几秒到几十秒；带媒体要看附件大小（实测 5500 条 + 300 张图约十几秒）。

**Q：会封号吗？**
A：不会。工具只读本机数据库文件和微信进程内存，不修改微信行为、不接触服务器通信。

**Q：能导出群聊吗？**
A：可以，群聊也能选，会显示每条消息的发送者。
