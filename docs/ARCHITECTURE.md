# 架构说明

> 这份文档是给「要接手本项目」或「照它给别的平台写一个（QQ / 钉钉 / 抖音…）」的人和 AI 看的。
> 目标是让你在动手前就清楚：数据怎么流、哪些代码能直接用、哪些必须重写、哪里有坑。

## 0. 一句话概括

把**加密的本地聊天数据库**变成标准 SQLite → 把 SQLite 里的消息变成结构化数据 → 渲染成 HTML / TXT 并搬运附件。

## 1. 数据流

```
<应用数据目录>\db_storage\*.db        ← SQLCipher 加密的库文件
        │
        │ ① keyscan / wcdb41 / keyextract   从进程内存取密钥
        │    （读出来之后必须用 page1 的 HMAC 校验，校验不过一律丢弃）
        ▼
        │ ② sqlcipher.decrypt_with_fallback 逐页解密 + 完整性校验
        ▼
work\decrypted\<账号>\*.db            ← 明文 SQLite（标准格式，可直接用 sqlite3 打开）
        │
        │ ③ wxstore.Store.chat_index()      反查 md5(用户名) → 会话列表 + 条数
        │    wxstore.Store.messages()        读 Msg_<hash> 表、zstd 解压、Name2Id 翻译发送者
        ▼
[{local_id, type, sub_type, time, sender, is_self, content, md5}, …]
        │
        │ ④ wxmsg.render()        类型 / XML → {kind, text, media, quote}
        │ ⑤ media.MediaExporter   图片 .dat 解密（imagekey 派生 AES/XOR 密钥）、
        │                         视频与附件落盘
        ▼
entries ──⑥ exporter.write_html() / write_txt()──▶ 导出\<名字>_<时间>\
```

关键设计：**解密、读取、渲染三段彼此独立**。换平台时通常只需要重写 ①②（定位与取密钥）和 ③④（schema 与类型），⑤⑥ 基本照用。

## 2. 模块地图

| 文件 | 职责 | 换平台时 |
|---|---|---|
| `cng_aes.py` | AES-256-CBC / AES-128-ECB，走 Windows 自带 `bcrypt.dll`，失败回退纯 Python | **直接复用** |
| `sqlcipher.py` | SQLCipher 4 页面解密、HMAC 校验、WAL 按需回放、`integrity_check` 封装 | **直接复用**（目标也是 SQLCipher 就别改） |
| `zstd_codec.py` | zstd 解压（优先 `zstandard`，其次系统 Node.js，都没有则跳过） | **直接复用** |
| `exporter.py` | 聊天气泡 HTML（搜索 / 只看图片 / 打印 CSS）+ 按日期分段的 TXT | **直接复用** |
| `keyscan.py` | Windows 进程内存枚举的底座（`VirtualQueryEx` / `ReadProcessMemory` / 区域遍历） | 复用底座，扫描策略重写 |
| `mediakey.py` | 实验性：内存里暴力找图片 AES 密钥（慢，可能失败） | 按需 |
| `pipeline.py` | 定位数据根、选账号、密钥缓存、批量解密 | 改数据目录规则与解密编排 |
| `keyextract.py` | 取密钥的编排（新路线 + 老路线回退 + 校验） | 重写 |
| `wcdb41.py` | 微信 4.1+ 从 `com.Tencent.WCDB.Config.Cipher` 取密钥 | **重写**（这是微信专有结构） |
| `wxstore.py` | 微信 schema：`Msg_<md5>` 表、`Name2Id`、`packed_info_data` | **重写** |
| `wxmsg.py` | 微信消息类型与 XML 结构 → 可读文本 | **重写** |
| `media.py` | 图片 `.dat` 解密（旧 XOR / V1 / V2）、视频与附件搬运 | 复用框架，换格式判断 |
| `imagekey.py` | 图片密钥离线派生：`uin` → AES / XOR 密钥，并用多个样本验证 | 微信专有公式，换平台要重写 |
| `hevc.py` | 从 `wxgf` 容器抽出 Annex-B 码流；可选调 ffmpeg 把首帧转 JPG | 复用（容器换成平台的即可） |
| `selftest.py` | 离线自检：自己造密文再解密，断言格式理解正确 | **复用套路**，加新格式断言 |
| `cli.py` | 交互选好友、参数解析、导出流程 | 复用骨架 |

## 3. 微信 4.x 的关键格式（实测）

**数据库（SQLCipher 4）**

- 页大小 4096，AES-256-CBC，每页保留 80 字节 = 16 字节 IV + 64 字节 HMAC-SHA512
- `mac_key = PBKDF2-HMAC-SHA512(enc_key, salt XOR 0x3a, 2 轮, 32 字节)`
- page1 特殊：文件前 16 字节是 salt，明文头 `SQLite format 3\0` 从第 16 字节开始
- 每个库文件的密钥**各自独立**，且只存在于运行中的微信进程内存里

**消息表**

- 表名 `Msg_<md5(用户名)>`，同一个人可能分散在 `message_0.db` / `message_1.db` / `message_2.db`，要合并
- 关键列：`local_id`、`local_type`、`sort_seq`、`real_sender_id`（→ `Name2Id` 的 rowid）、`create_time`、`message_content`、`packed_info_data`、`WCDB_CT_message_content`、`WCDB_CT_source`
- `local_type` 低 32 位是类型，高位是子类型：`sub = local_type >> 32`
- `packed_info_data` 里藏着媒体文件的 md5，是「消息 → 附件」的定位依据
- `WCDB_CT_xxx != 0` 表示该列被压缩，目前见到的都是 zstd

**图片 `.dat`**

- V2（微信 4.1+ 主流）：`[6B 签名][4B aes_size][4B xor_size][1B pad]` + AES-128-ECB 段 + 明文段 + 单字节 XOR 段
- V1：同上结构，但 AES 密钥是固定值 `md5("0")[:16]`
- 更老的：整文件单字节 XOR，靠文件头魔数反推 key
- V2 的两把密钥都由账号级数字 `uin` 派生，**不用读进程内存**：

  ```
  aes_key = md5(f"{uin}{wxid}").hexdigest()[:16]   # 16 个 ASCII 字符直接当 16 字节用
  xor_key = uin & 0xFF
  ```

  `uin` 来自 `%APPDATA%\Tencent\xwechat\net\kvcomm\key_<uin>_*.statistic` 的文件名，
  兜底可用 `md5(str(uin))[:4] == wxid 目录后缀` 反推；`wxid` 是数据目录名去掉 `_<4位hex>`
  后缀。派生结果必须用多个样本验证（AES 段解出图片魔数、尾段解出 `FF D9` / `IEND`）才算数。
- 解出来是 `wxgf` 的（约六成）是 HEVC 封装的原图/动图，需要 ffmpeg 取帧才能显示。

**`wxgf` 容器（HEVC 图片）**

- 文件以 `wxgf` 开头，紧跟一段头部，之后才是标准 H.265 Annex-B 码流
- 码流起点是 VPS（NAL 类型 32，NAL 头 `40 01`）。少数文件的头部里还有一段
  「起始码 + NAL 字节 `40 4d`」的假 VPS，直接取第一个会多带 10 字节垃圾，
  所以要优先挑 `nuh_layer_id == 0`（第二字节 0x01）的那个
- 抽流后存成 `.h265`，VLC / PotPlayer / MPV 可直接播放
- 每张原图旁边通常还有个 `_t.dat` 缩略图，是普通 JPEG，可以当预览用
- 有 ffmpeg 时：`ffmpeg -f hevc -i pipe:0 -frames:v 1 -f mjpeg pipe:1`，走管道不留临时文件

## 4. 接一个新平台（QQ / 抖音…）怎么做

**Step 0 — 只读排查（先别写代码）**

1. 数据在哪：`%APPDATA%`、`%LOCALAPPDATA%`、安装目录、`Documents`，谁最近被写过
2. 是不是 SQLite：读头 16 字节，是 `SQLite format 3\0` 就直接能开；是随机字节说明加密
3. 加密的话要弄清：页大小、HMAC 算法、KDF 参数、**密钥从哪来**（内存 / 配置文件 / DPAPI / 设备指纹）
4. 消息表结构：谁发给谁、时间戳单位（秒 / 毫秒）、类型枚举、正文里是不是套了 JSON / XML、附件怎么引用

**Step 1 — 先打通文本**：一条会话 → 全量消息 → TXT。别一上来做媒体。

**Step 2 — 再上 HTML**：直接复用 `exporter.py`，只把 `entries` 结构对齐。

**Step 3 — 最后做附件**：先摸清命名规则与加密方式，做不出来的就保留原文件并在页面上标注，**不要为了好看而丢数据**。

**Step 4 — 自检与 CI**：照 `selftest.py` 的套路，自造一份加密数据再解出来，证明自己理解对了格式；再挂一个 GitHub Actions 矩阵跑它。

## 5. 已经踩过的坑（省你几小时）

| 坑 | 表现 | 正确做法 |
|---|---|---|
| **CNG 的 CBC 会就地改写 IV** | 偶尔解出乱码、甚至内存异常 | 传 `create_string_buffer` 的可写缓冲区，不要直接传 Python `bytes` |
| **V2 尾段的 XOR 密钥不是常量** | 图片头能解出来、尾部却是花屏，浏览器打不开 | 尾段密钥是 `uin & 0xFF`（因账号而异）；验证密钥不能只看文件头魔数，必须同时看文件尾的 `FF D9` / `IEND` |
| **WAL 不能无条件回放** | 解密后 `integrity_check` 报 malformed | 先只解主库并校验；不通过再试回放 WAL |
| **Windows runner 默认 cp1252** | CI 里 `UnicodeEncodeError` | 启动时 `stdout.reconfigure(encoding="utf-8")`，CI 里设 `PYTHONUTF8=1` |
| **`.bat` 换行** | 下载后双击报「不是内部或外部命令」 | 仓库里存 LF + `.gitattributes` 写 `*.bat eol=crlf` |
| **会话分散在多库** | 只导出一部分消息 | 按 `Msg_<hash>` 跨库合并 |
| **密钥缓存的时效** | 换了密钥后旧缓存失效 | 用前必须 HMAC 校验，不通过就重新提取 |
| **Git Data API 对空仓库** | `409 Git Repository is empty` | 先用 Contents API 创建首个文件，再走 Git Data API |

## 6. 硬性约束（别越界）

- **只读**：不写、不删、不改原始数据；解密产物落在 `work\`，可随时删
- **不联网**：整个工具零网络请求，没有上传通道
- **不打印密钥**：密钥只进内存和 `work\keys_*.json`（本地缓存，`.gitignore` 挡住）
- **敏感目录**：`work\`、`导出\` 都是隐私数据，发布/分享时务必排除
- README 里要有清楚的能力边界、已知限制和免责声明

## 7. 本地产物位置

```
work\                    密钥缓存 + 解密后的数据库（敏感，可删，会自动重建）
work\decrypted\<账号>\   明文 SQLite
work\keys_<账号>.json    每个库的密钥缓存（hex）
导出\<名字>_<时间>\       chat.html / chat.txt / media\
```

## 8. 给协作的 AI 的建议

1. 先读 `README.md` 的「工作原理」「已知限制」，再看这份文档
2. 动真实数据前，先让 `--selftest` 通过；改格式代码就同步补一条断言
3. 每个平台单独写 `store` / `msg` 两个模块，不要在一个文件里用 `if 平台 ==` 分支
4. 媒体处理失败时要**保留原始文件**并显式标注，不能静默丢弃
5. 交付前跑一遍：`--selftest`、`unittest`、`compileall`，再全文搜一遍有没有把真实聊天内容/密钥带进仓库
