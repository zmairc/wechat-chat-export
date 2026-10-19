"""把数据库里的一条消息渲染成"人类可读"的内容。

微信的消息内容五花八门：纯文本、XML（图片/语音/视频/链接/引用/转账/接龙…）、
以及 4.x 的整数类型（高位是子类型）。这里统一归类成 kind + text。
"""

from __future__ import annotations

import re

# 常见类型（低 32 位）
T_TEXT = 1
T_IMAGE = 3
T_VOICE = 34
T_CARD = 42
T_VIDEO = 43
T_STICKER = 47
T_LOCATION = 48
T_APP = 49
T_CALL = 50
T_STATUS = 51
T_SHORTVIDEO = 62
T_SYSTEM = 10000
T_SYSTEM_XML = 10002

_GROUP_PREFIX = re.compile(r"^(wxid_[0-9A-Za-z_\-]+|gh_[0-9A-Za-z_\-]+|[0-9]+@chatroom):\s*\n?")


def _attr(xml: str, name: str) -> str:
    m = re.search(rf'{name}\s*=\s*"([^"]*)"', xml)
    return m.group(1) if m else ""


def _tag(xml: str, name: str) -> str:
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S)
    return m.group(1) if m else ""


def _tag_full(xml: str, name: str) -> str:
    m = re.search(rf"<{name}\b[^>]*>", xml, re.S)
    return m.group(0) if m else ""


def _cdata(s: str) -> str:
    s = s.strip()
    if s.startswith("<![CDATA[") and s.endswith("]]>"):
        s = s[9:-3]
    return s.strip()


def _strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s)
    return s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").strip()


_APP_TYPE_TEXT = {
    "3": "音乐",
    "4": "视频链接",
    "5": "链接",
    "6": "文件",
    "8": "表情包",
    "19": "聊天记录",
    "33": "小程序",
    "36": "小程序",
    "51": "视频号",
    "53": "接龙",
    "57": "引用",
    "63": "直播",
    "74": "文件",
    "87": "群公告",
    "115": "直播",
    "2000": "转账",
    "2001": "红包",
    "2003": "群接龙",
}


def render(m: dict, is_chatroom: bool = False) -> dict:
    """返回 {kind, text, media, quote}。"""
    t = m["type"]
    sub = m["sub_type"]
    raw = m["content"] or ""
    if is_chatroom:
        pm = _GROUP_PREFIX.match(raw)
        if pm:
            raw = raw[pm.end():]

    kind = "text"
    text = raw.strip()
    media: list[dict] = []
    quote = ""

    if t == T_TEXT:
        if text.startswith("<") and "</" in text:
            r = _render_app(raw)
            if r.get("kind") != "unknown":
                return r
        if not text:
            text = "[空消息]"

    elif t == T_IMAGE:
        kind = "image"
        text = "[图片]"
        md5 = _attr(raw, "md5") or _attr(raw, "cdnthumbmd5")
        media.append({"type": "image", "md5": md5,
                      "len": _attr(raw, "length"), "thumb": _attr(raw, "cdnthumburl")})

    elif t == T_VOICE:
        kind = "voice"
        ms = _attr(raw, "voicelength") or _attr(raw, "length")
        try:
            secs = max(1, round(int(ms) / 1000))
        except (TypeError, ValueError):
            secs = 0
        text = f"[语音 {secs}\"]" if secs else "[语音]"

    elif t == T_VIDEO:
        kind = "video"
        pl = _attr(raw, "playlength")
        text = f"[视频 {pl} 秒]" if pl else "[视频]"

    elif t == T_STICKER:
        kind = "sticker"
        text = "[表情]"
        md5 = _attr(raw, "md5")
        if md5:
            media.append({"type": "sticker", "md5": md5})

    elif t == T_LOCATION:
        kind = "location"
        label = _attr(raw, "label") or _attr(raw, "poiname")
        text = f"[位置] {label}".strip()

    elif t == T_CARD:
        kind = "card"
        nick = _attr(raw, "nickname") or _attr(raw, "nickName")
        text = f"[名片] {nick}".strip()

    elif t == T_CALL:
        kind = "call"
        text = "[通话]"
        if "cancel" in raw or "取消" in raw:
            text = "[通话] 已取消"

    elif t == T_SHORTVIDEO:
        kind = "video"
        text = "[小视频]"

    elif t == T_APP:
        r = _render_app(raw, sub)
        r["type"] = t
        return r

    elif t == T_SYSTEM:
        kind = "system"
        text = _strip_tags(text) or "[系统消息]"

    elif t == T_SYSTEM_XML:
        kind = "system"
        text = _render_sysmsg(raw)

    elif t == T_STATUS:
        kind = "system"
        text = "[状态] " + _strip_tags(text)

    elif t == 37:
        kind = "system"
        text = "[好友申请] " + _strip_tags(text)

    elif t == T_IMAGE + 0 and False:
        pass
    else:
        kind = "unknown"
        text = f"[未知消息类型 {t}] " + _strip_tags(text)[:120]

    return {"kind": kind, "text": text, "media": media, "quote": quote, "type": t}


def _render_sysmsg(raw: str) -> str:
    m = re.search(r'<sysmsg[^>]*type="([^"]+)"', raw)
    typ = m.group(1) if m else ""
    if typ == "revokemsg":
        who = _tag(raw, "replacemsg")
        return _strip_tags(who) or "[消息已撤回]"
    txt = _strip_tags(_tag(raw, "content") or raw)
    return txt or "[系统消息]"


def _render_app(raw: str, sub: int = 0) -> dict:
    app_type = _tag(raw, "type").strip() or str(sub or "")
    title = _cdata(_tag(raw, "title"))
    des = _cdata(_tag(raw, "des"))
    url = _cdata(_tag(raw, "url"))
    kind = "app"
    text = title or des or "[卡片消息]"
    media: list[dict] = []
    quote = ""

    if app_type == "57":
        kind = "quote"
        ref = _tag(raw, "refermsg")
        q_content = _strip_tags(_tag(ref, "content"))
        q_name = _tag(ref, "displayname").strip()
        inner = _render_text_or_xml(_tag(ref, "content"))
        quote = (f"{q_name}: {inner}" if q_name else inner).strip()
        text = title or "[引用]"
    elif app_type in ("6", "74"):
        kind = "file"
        total = _attr(_tag_full(raw, "appattach"), "totallen") or _attr(raw, "totallen")
        text = title or "[文件]"
        media.append({"type": "file", "name": title, "size": total})
    elif app_type == "2000":
        kind = "transfer"
        text = f"[转账] {des or title}"
    elif app_type == "2001":
        kind = "redpacket"
        text = f"[红包] {title or des}"
    elif app_type in ("4", "5"):
        kind = "link"
        text = title or url or "[链接]"
        if url:
            media.append({"type": "link", "url": url, "title": title})
    elif app_type in ("3",):
        kind = "music"
        text = f"[音乐] {title}" if title else "[音乐]"
    elif app_type in ("33", "36"):
        kind = "miniprogram"
        text = f"[小程序] {title}"
    elif app_type == "19":
        kind = "chatrecord"
        text = f"[聊天记录] {title}"
    elif app_type == "51":
        kind = "channel"
        text = f"[视频号] {title}"
    else:
        label = _APP_TYPE_TEXT.get(app_type, "卡片")
        kind = "app"
        text = f"[{label}] {title}" if title else f"[{label}]"

    text = re.sub(r"\s+", " ", text).strip()
    return {"kind": kind, "text": text, "media": media, "quote": quote,
            "app_type": app_type}


def _render_text_or_xml(content: str) -> str:
    c = (content or "").strip()
    if not c:
        return ""
    if c.startswith("<"):
        t = _strip_tags(c)
        return t
    return c
