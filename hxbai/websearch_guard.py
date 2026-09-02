#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys

_WRITEUP_RX = re.compile(r"(?i)write[\s-]?up|walk[\s-]?through|题\s*解|通关攻略|解题\s*(?:思路|步骤|过程|攻略|报告)|"
                         r"官方\s*题解|wp\s*(?:writeup|题解)|complete\s+solution\s+(?:for|of)")
_PLATFORM_RX = re.compile(r"(?i)tsecbench|redamon|zc\.tencent|云鼎|安全应急响应中心.*攻防"
                          r"|sekai\s?ctf|project[\s-]?sekai|imaginary\s?ctf|glacier\s?ctf|\bictf\b"
                          r"|hkcert\s?ctf|losfuzzys|ctftime\.org"
                          r"|\bsekai\b[^\n]{0,40}\bctf\b|\bctf\b[^\n]{0,40}\bsekai\b")
_CODEFAM_RX = re.compile(r"(?i)\bxben[\s-]?\d{1,4}(?:-\d{1,4})?\b"
                         r"|(?<![0-9a-z])[a-g]\d?-\d{2}(?![0-9a-z])")
_CTFFLAG_RX = re.compile(r"(?i)\bctf\b[^\n]{0,80}\b(?:flag|solution|solve)\b"
                         r"|\b(?:flag|solution|solve)\b[^\n]{0,80}\bctf\b")


def _decision(reason: str):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


def main() -> None:
    try:
        ev = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = (ev.get("tool_name") or "").strip()
    if tool not in ("WebSearch", "WebFetch"):
        sys.exit(0)
    if os.environ.get("HXBAI_WEB_BLOCK_ALL") == "1":
        _decision("本场禁联网(HXBAI_WEB_BLOCK_ALL=1):不要联网搜索——改用 /opt/kb 离线 CVE/PoC 库 + "
                  "对本题 Target 的真实黑盒探测自主打通。")
    if os.environ.get("HXBAI_WEBSEARCH_GUARD", "1") != "1":
        sys.exit(0)
    ti = ev.get("tool_input") or {}
    hay = " ".join(str(ti.get(k, "")) for k in ("query", "url", "prompt")).strip()
    if not hay:
        sys.exit(0)

    code = platform = ""
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "websearch_guard.json")
        if os.path.exists(cfg_path):
            cfg = json.load(open(cfg_path, encoding="utf-8"))
            code = (cfg.get("code") or "").strip()
            platform = (cfg.get("platform") or "").strip()
    except Exception:
        pass

    steer = ("作弊红线:禁止按题号/题名/靶场平台名或 writeup/题解/walkthrough 搜任何题的现成答案。"
             "只允许按你从靶机识别出的【产品/版本/CVE/技术】检索通用漏洞原理与公开 PoC"
             "(如 `<产品> <版本> RCE CVE PoC`),搜到的只当漏洞原理参考,不得照搬解题步骤。"
             "改用产品/CVE 关键词重搜,或直接对本题 Target 手动探测。")

    if _WRITEUP_RX.search(hay):
        _decision("检索里出现题解/攻略词(writeup/题解/walkthrough 等)——" + steer)
    if _PLATFORM_RX.search(hay) or (platform and platform.lower() in hay.lower()):
        _decision("检索里出现靶场平台名/域名——不得去平台/题解站找答案。" + steer)
    if code:
        if re.search(r"(?<![0-9a-zA-Z])" + re.escape(code) + r"(?![0-9a-zA-Z])", hay, re.IGNORECASE):
            _decision(f"检索里出现本题题号 `{code}`——无合法理由搜赛题编号。" + steer)
    if _CODEFAM_RX.search(hay):
        _decision("检索里出现赛题题号格式(xben-###/字母-两位数,含 cybench g 族)——无合法理由搜任何赛题编号(邻题也不行)。" + steer)
    if _CTFFLAG_RX.search(hay):
        _decision("检索是'CTF 赛题+要 flag/solution'式——按题名找现成题解=作弊。" + steer)
    sys.exit(0)


if __name__ == "__main__":
    main()
