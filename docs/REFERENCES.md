# 同类项目调研与关键技术参考

> 记录本项目（微信 4.x 聊天记录导出）在 GitHub 上的同类实现、它们各自解决得更好的问题，
> 以及哪些结论已经在本机实测验证过。目的是**避免重复踩坑**，也方便判断某个设计该不该改。
>
> 调研时间：2026-10-25。协议一栏以仓库 LICENSE 为准，引用代码务必注明出处。
>
> **更新（同日）**：第 3 节的图片密钥派生已经落进代码（`wxexport/imagekey.py`），
> 真实数据上 286 个 `.dat` 全部解开、0 失败，详见第 3 节末尾。

## 1. 一句话结论

同类项目的差别不在「能不能解密数据库」——这一步大家的做法已经趋同（内存里找
`com.Tencent.WCDB.Config.Cipher` → 去掩码 → page1 HMAC 校验 → SQLCipher 4 逐页解）。
真正的分水岭只有三处：

1. **图片 V2 密钥从哪来**（我们当前的短板，见第 3 节，已解决）
2. **语音还原**（SILK → WAV，别人做了，我们只留占位）
3. **产品形态**（Web UI / MCP / 桌面客户端 vs 我们的命令行 + 静态 HTML）

## 2. 对照表

| 项目 | 定位 | 值得借鉴的地方 | 不打算跟的部分 |
|---|---|---|---|
| [usenrong/SIWX](https://github.com/usenrong/SIWX) | 完整度最高的参照：Web 控制台 + MCP，8 种导出格式 | **密钥按 salt 缓存并用 Windows DPAPI 加密落盘**；**SILK 语音用纯 Python `pilk` 直接转 WAV**（不需要 ffmpeg）；逐页 4KB 流式解密 + K 路归并导出，万级消息内存占用低；`media_*.db` 资源库索引 | Web 控制台依赖较重，与「双击 .bat 就出结果」的定位冲突 |
| [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) | 桌面版 Electron，功能面最广（朋友圈、收藏、年度总结、视频号） | **图片密钥派生公式的原始出处**；按文件签名建立分片索引；导出 Excel(ZIP) | Electron + 后端双进程，装完几百 MB；支持「修改消息」，与本项目只读原则相反 |
| [CN-Grace/Wechat-Emoticon-Parser](https://github.com/CN-Grace/Wechat-Emoticon-Parser) | 表情包 + V2 图片 + 全库解密，单文件脚本 | **V2 `.dat` 完整算法与容器结构**；`PersistStore` 多图拼接容器用流式结构解析（PNG→IEND / GIF→0x3B / JPEG→EOI），避免把压缩数据里的假魔数切断；`wxgf` = HEVC 流，取首帧 | 依赖 `pycryptodome` + `imageio-ffmpeg`，破坏了本项目「零第三方依赖」 |
| [killLuoti/weixin-decrypte-script](https://github.com/killLuoti/weixin-decrypte-script) | 解密脚本集 + REST API | 三种 `.dat`（旧 XOR / V1 / V2）的判别与兜底；**V2 的 xor_key 用缩略图 `_t.dat` 的文件尾反推**（原图是 WxAM 压缩，尾部没有 `FF D9`） | REST 服务长期监听端口，与「不联网、不留服务」冲突 |
| [WeinanHu/wechat-decrypt](https://github.com/WeinanHu/wechat-decrypt) | 打包成 Agent Skill，macOS + Windows | **用 `--json` 作为给机器读的唯一输出契约**；事件分类（拍一拍 / 撤回 / 红包 / 通话 / 置顶）很细；Whisper 本地转写语音（首次要下 ~3GB 模型，需显式同意） | 依赖 SQLCipher 二进制与 Frida（macOS 走重签名），门槛高于本项目 |
| [kenchikuliu/wechat-local-backup-search](https://github.com/kenchikuliu/wechat-local-backup-search) | 检索为主，但图片密钥这块研究最细 | **uin 的离线反推**：wxid 目录后缀 4 位 hex == `md5(str(uin))[:4]`，配合 xor_key 枚举 2^24 个候选可唯一定位（~7 秒，不读进程）；要求**多个不同模板都通过验证**才算命中，防止短魔数偶然命中 | 为 macOS 写的，派生逻辑可移植、代码不必照搬 |
| [HShiDianLu/wx-dat2img](https://github.com/HShiDianLu/wx-dat2img) | 专攻 `.dat` → 图片，含 WxAM 解析 | `.dat` 分代（纯 XOR → XOR+固定 AES → XOR+动态 AES）的清晰梳理；`msg/attach/<会话>/Img/` 按会话分目录，`_t` 是缩略图 | 只做图片，不管数据库 |
| [dkluffy/wx_key](https://github.com/dkluffy/wx_key) | DLL Hook + Flutter UI 取密钥 | 说明「Hook `SetDBKey`」这条路可行且只在上电登录早期有效 | **明确不采用**：注入远程 Hook 违背本项目「不注入、不 hook、只读内存」的承诺，风险与合规都不可接受 |

## 3. 本机实测：V2 图片密钥可以被「算」出来，不必扫内存

多个来源指向同一个公式（WeChatDataAnalysis、Wechat-Emoticon-Parser、52pojie 上的逆向帖、
kenchikuliu 的 macOS 实现）。**已在本机真实数据上验证通过**：

```
uin   = 账号级数字（内存里的 seed / MMKV 统计文件名里的 code）
wxid  = 数据目录名去掉 _<数字或4位hex> 后缀
aes_key = md5(f"{uin}{wxid}").hexdigest()[:16]      # 16 个 ASCII 字符直接当 16 字节用，不要 hex 解码
xor_key = uin & 0xFF
```

uin 的离线来源（不需要微信运行、不需要读内存）：

- 主路径：`%APPDATA%\Tencent\xwechat\net\kvcomm\key_<uin>_*.statistic` 的**文件名**
  （正则 `key_(\d+)_`，跳过 `key_0_` 这类占位项）
- 兜底：`md5(str(uin))[:4]` 等于 wxid 目录后缀，反推 uin

验证方法：拿任一 V2 `.dat` 的第 `[15:31]` 字节做 AES-128-ECB 单块解密，命中图像魔数
（`FF D8 FF` / `89 50 4E 47` / `GIF8` / `RIFF` / `wxgf`）即命中。

**本机实测结果（2026-10-25，`导出/` 下 286 个未解开的 `.dat`）**

| 步骤 | 结果 |
|---|---|
| 从 kvcomm 文件名取 uin | `604808998`（唯一非 0 候选） |
| 派生 aes_key（wxid 保留后缀） | 0/40 命中 —— 后缀必须去掉 |
| 派生 aes_key（wxid 去掉 `_c23a`） | **40/40 命中**，xor_key = `0x26` |
| 用现有 `media.decrypt_dat()` 全量解 286 个 | **286/286 全部解开**：jpg 153、png 28、`hevc`(wxgf) 105 |

也就是说：`media.py` 的容器解析本来就是对的，缺的只是**把密钥算出来传给 `aes_key` 参数**。
剩下 105 个 `wxgf` 是 HEVC 封装的原图/动图，解密已成功，但需要取首帧（或转 GIF）才能显示。

**已落地（2026-10-25）**：新增 `wxexport/imagekey.py`，默认自动派生并验证；同时修掉一个
真 bug——`media.py` 原先假设 V2 尾段的 XOR 密钥是常量 `0x88`，实际是 `uin & 0xFF`，
导致「图片头能解开、尾部却是花屏」。用真实会话重跑对比：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 能直接在浏览器显示的图片 | 4 张 | 40 张（jpg 27 + png 13） |
| 解不开、只剩 `.dat` | 93 个 | **0 个** |
| 已解密但需转码的 HEVC | — | 57 个（`wxgf` 容器，浏览器不能直接显示） |

## 4. 可以直接照搬的想法（按性价比排序）

1. ~~**图片密钥离线派生**（第 3 节）：约 40 行代码，零依赖，一次性把「一半媒体是 `.dat`」这个最大短板补掉。~~
   **已实现**：`wxexport/imagekey.py`。
2. **密钥缓存加密落盘**：现在 `work\keys_*.json` 是明文 hex，README 也承认这是敏感文件。
   改用 DPAPI（`CryptProtectData`，同样走系统 API、零依赖）就能让缓存「只在本机本账户可解」。
3. **语音 SILK → WAV**：`pilk` 是纯 Python 实现，但它是第三方依赖，与「零依赖」冲突；
   折中方案是**可选依赖**——没装就仍打 `[语音 3"]` 占位，装了才转 WAV。
4. **CSV 导出**：`wechat-chat-export` 技能里的做法是 `时间,发送人,类型,内容` + UTF-8 BOM，
   直接用 Excel 打开不乱码。我们只有 HTML/TXT，加一列 CSV 成本很低，对做数据分析的人很有用。
5. **流式解密**：现在是整库解密到 `work\decrypted\`，几个 G 的库会吃满内存/磁盘。参考 SIWX 逐页 4KB 处理。
6. **`--json` 输出契约**：给脚本调用方一个稳定的机器可读输出，比现在纯人类可读的提示更利于二次集成。

## 5. 明确不跟的做法

- **DLL 注入 / Hook `SetDBKey`**（`wx_key` 路线）：能力更强，但违背只读承诺，不做。
- **修改消息**（WeChatDataAnalysis 的功能）：本项目定位是「备份」，不是「编辑」。
- **Electron 桌面端**：与「双击 bat、导出完自动开网页」的轻量定位冲突。
- 直接复制上述项目的代码：多数是 MIT，但仍有风格与出处问题；**只借鉴算法，实现自己写**，
  并在 README「致谢」里点名。

## 6. 本地已安装的技能（可用于后续开发）

| 技能 | 用途 |
|---|---|
| Windows 便携 Python 零安装交付 | 把工具打包成「随包便携 Python」的零安装交付物，解决用户必须自己装 Python 3.10+ 的门槛 |
| 代码质量审查 | 交付前按七维（正确性/错误处理/并发/资源/性能/安全/可维护性）过一遍，结论按阻塞/应该改/可选分级 |
| 微信 WCDB 本地解密与消息提取 | 交叉核对密钥派生与 `local_type` / `real_sender_id` 解析（含「XOR 解码 + 内嵌 salt 定向 PBKDF2」思路） |
| 微信聊天记录导出 | 对照它的 CSV 输出约定与「主库被独占锁定需 `FILE_SHARE_READ|WRITE|DELETE` 读取」的处理 |
| 微信聊天记录读取 | 对照 HTML/Markdown/CSV 三种导出的排版细节 |

其中两份笔记里有两处与我们不同、值得核实的说法：

- 它称「同一账号全部库共用同一个 32 字节 key」。我们按库缓存密钥；因为有 page1 HMAC 校验
  兜底，功能上不会出错，但**可以去验证一次**——若确实共用，`wcdb41` 的扫描次数能少一半。
- 它称「WAL 帧头被魔改，主库文件本身完整，导出以主库为准」。我们目前是「必要时回放 WAL」，
  两种说法未必冲突，但值得在一次真实导出上对比 `integrity_check` 与消息条数。

## 7. 建议的下一步

| 优先级 | 事项 | 状态 |
|---|---|---|
| P0 | 修最新 CI 上 Python 3.12 那条腿的失败（3.11/3.13 通过，本地 3.12 也通过） | 待复跑；自检已改成失败时打印完整栈，便于定位 |
| P1 | 图片密钥离线派生 + 接入 `media.py`（第 3 节已验证） | **已完成**：`imagekey.py` + `decrypt_dat(xor_key=...)` + selftest 断言 |
| P2 | `wxgf`(HEVC) 首帧提取，让那 57~105 个文件能直接显示 | **已完成**：`hevc.py` 抽流 + 缩略图兜底，有 ffmpeg 时转 JPG |
| P3 | 密钥缓存用 DPAPI 加密；补 CSV 导出；README 截图 | 待做 |
