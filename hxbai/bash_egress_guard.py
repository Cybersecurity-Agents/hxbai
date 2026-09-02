#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys

_EGRESS_RX = re.compile(
    r"https?://|ftp://|gopher://|wss?://"
    r"|\b(?:curl|wget|nc|ncat|socat|telnet|ftp|tftp|scp|sftp|rsync|git\s+clone|"
    r"lynx|links|links2|w3m|httpie|xh|aria2c|youtube-dl|yt-dlp)\b"
    r"|\bssh\s|\bdig\s|\bnslookup\b|\bdrill\b"
    r"|urllib|urllib2|http\.client|requests\.(?:get|post|put|request|head|Session)|"
    r"httpx\.|aiohttp|socket\.create_connection|urlopen|wget\.download", re.I)
_HOST_RX = re.compile(
    r"(?:https?|ftp|gopher|ws|wss)://([A-Za-z0-9_.:\[\]-]+)"
    r"|(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?"
    r"|(?<![\w.@/])([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?", re.I)
_CHEAT_RX = re.compile(
    r"(?i)write[\s-]?up|walk[\s-]?through|题\s*解|walkthrough"
    r"|ctftime\.org|tsecbench|redamon|zc\.tencent|云鼎|hatenablog"
    r"|sekai\s?ctf|sekaictf|project[\s-]?sekai|glacier\s?ctf|imaginary\s?ctf|hkcert\s?ctf|losfuzzys")


def _decision(reason: str):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


_LOCAL_FIRST_OCTET = frozenset((10, 127, 172, 192))


def _host_only(host: str) -> str:
    h = host.strip().lower()
    if h.startswith("["):
        return h[1:].split("]", 1)[0]
    if h.count(":") == 1:
        return h.rsplit(":", 1)[0]
    return h


def _is_local(host: str) -> bool:
    h = _host_only(host)
    if h in ("localhost",) or h.endswith(".local") or h.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.version == 4 and int(ip.packed[0]) in _LOCAL_FIRST_OCTET:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local


def main() -> None:
    if os.environ.get("HXBAI_BASH_EGRESS_GUARD", "1") != "1":
        sys.exit(0)
    try:
        ev = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    if (ev.get("tool_name") or "").strip() != "Bash":
        sys.exit(0)
    cmd = str((ev.get("tool_input") or {}).get("command", ""))
    if not cmd or not _EGRESS_RX.search(cmd):
        sys.exit(0)

    target_hosts = set()
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "websearch_guard.json")
        if os.path.exists(cfg_path):
            cfg = json.load(open(cfg_path, encoding="utf-8"))
            for t in (cfg.get("targets") or []):
                target_hosts.add(str(t).strip().lower())
    except Exception:
        pass

    steer = "改用 /opt/kb 离线 CVE/PoC 库 + 对本题 Target(私网靶机)的真实黑盒探测,不要连公网。"
    block_all = os.environ.get("HXBAI_WEB_BLOCK_ALL") == "1"

    if _CHEAT_RX.search(cmd):
        _decision("Bash 出网命中题解站/平台/赛名/writeup——禁止 curl/wget 抄题解。" + steer)

    for h in [h for tup in _HOST_RX.findall(cmd) for h in tup if h]:
        hl = _host_only(h)
        if hl in target_hosts or _is_local(h):
            continue
        if block_all:
            _decision(f"本场禁联网(HXBAI_WEB_BLOCK_ALL=1):Bash 出网到公网 `{h}` 被拦。" + steer)
    sys.exit(0)


if __name__ == "__main__":
    main()
