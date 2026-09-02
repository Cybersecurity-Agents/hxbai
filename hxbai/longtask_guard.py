#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys

_PRODUCER = re.compile(
    r"(?i)\b(?:hydra|medusa|john|hashcat|nuclei|ffuf|gobuster|dirb|nikto|masscan|"
    r"\w*spray\w*|\w*brute\w*|\w*crack\w*)\b|authspray")
_RECON_TOOL = re.compile(r"(?i)\b(?:nmap|sqlmap)\b")
_NMAP_HEAVY = re.compile(r"(?i)-p-|-p\s*1-65535|--allports|\b\d+\.\d+\.\d+\.\d+/\d{2}\b")
_SQLMAP_HEAVY = re.compile(
    r"(?i)--dump(?:-all)?\b|--tables\b|--columns\b|--os-shell\b|--level\s*[3-5]\b|--risk\s*[2-3]\b|--threads")
_BIGSCAN = re.compile(r"(?i)\b\d+\.\d+\.\d+\.\d+/\d{2}\b")
_TIMEOUT = re.compile(r"\btimeout\s+(\d+)")
_BG = re.compile(r"(?i)\b(?:tmux|nohup|setsid|systemd-run|screen)\b|&\s*$")
_PIPE_TAIL = re.compile(r"(?i)\|\s*(?:\/\w+\/)?(?:tail|head)\b")
_READER = re.compile(r"(?i)^\s*(?:tail|head|cat|less|more|grep|egrep|rg|awk|sed|wc|nl|strings|find|ls|ps|tmux\s+ls)\b(?!\s*[>+])")

_R1_TMPL = ("拒绝:长任务的管道接进 tail/head——管道缓冲会吞掉全部输出,SIGTERM 时结果全丢"
            "(实测:一次定向爆破结果因此一份不剩)。改写为后台+落盘:\n"
            "  tmux new-session -d -s <名> '<原命令> >> /tmp/<名>.log 2>&1'\n"
            "然后轮询 `tail -5 /tmp/<名>.log` 取进度,绝不重启同任务。")
_R2_TMPL = ("拒绝:爆破/大扫描/长超时任务禁止前台跑——会话随时被掐,前台长任务=白干。改写:\n"
            "  tmux new-session -d -s <名> '<原命令> >> /tmp/<名>.log 2>&1'\n"
            "认证喷洒优先 `python3 /opt/tools/authspray.py`(自带 SUMMARY 错误核算);"
            "结果必须落盘,下个会话 tail 日志续力。")

_WIDE_OE_GREP = re.compile(r"(?i)\b(?:grep|egrep)\b[^;|&]*\s-o[^;|&]*\.\{0,(?:[5-9]\d|\d{3,})\}")
_R4_TMPL = ("拒绝:宽窗口正则(grep -o '.{0,N}',N>=50)在大文件/超长单行上是线性慢(-o 每个位置都要试,"
            "实测 120s)。改写:加命中上限 `-m 20`、或把窗口降到 .{0,30} 以内、或先 `wc -c` 确认文件规模"
            "再决定;超大文件用 python 逐块读。")

_BARE_STDIN = re.compile(
    r"(?i)^\s*(?:(?:grep|egrep)|(?:awk|sed))\s+(?:-[a-zA-Z]+\s+)*('[^']*'|\"[^\"]*\"|\S+)\s*$")


_R5_TMPL = ("拒绝:这条 grep/awk/sed 没有文件参数也没有管道输入——它在等 stdin,会一直阻塞/无输出。"
            "改写:补上文件参数,或结尾加 `</dev/null`,或接进管道 `echo ... | <命令>`。")


def decide(command: str) -> tuple[str, str]:
    if not command or not os.environ.get("HXBAI_LONGTASK_GUARD", "1") == "1":
        return "allow", ""
    if _WIDE_OE_GREP.search(command) and not re.search(r"(?:^|\s)(?:-[a-zA-Z]*m(?:\s|\d|$)|--max-count)", command):
        return "deny", _R4_TMPL
    if "|" not in command and "<" not in command and _BARE_STDIN.match(command):
        return "deny", _R5_TMPL
    if _READER.match(command):
        return "allow", ""
    if re.search(r"socat\s+TCP-LISTEN", command, re.I):
        if not re.search(r"setsid|nohup|tmux", command, re.I):
            if "&" in command:
                return "deny", ("拒绝:裸 & 启动的 socat 中继在 session 结束时被 SIGHUP 杀死,下个 session 又要重建"
                                "(实测 69 次重建/0 次存活检查)。改写:\n"
                                "  # 先检查已有的:\n"
                                "  nc -z <web_ip> 2222 && echo RELAY_OK || \\\n"
                                "  bash rce.sh 'setsid nohup socat TCP-LISTEN:2222,reuseaddr,fork TCP:<target>:22 >/dev/null 2>&1 &'\n"
                                "setsid 使进程脱离 session 进程组,session 结束后存活。")
    if _BG.search(command):
        return "allow", ""
    m = _TIMEOUT.search(command)
    secs = int(m.group(1)) if m else 0
    _has_producer = bool(_PRODUCER.search(command) or _BIGSCAN.search(command))
    if _RECON_TOOL.search(command):
        _has_producer = _has_producer or bool(_NMAP_HEAVY.search(command)) or bool(_SQLMAP_HEAVY.search(command))
    if _has_producer:
        if re.search(r"(?:--help|-h\b|\?\s*$)", command):
            return "allow", ""
        if _PIPE_TAIL.search(command):
            return "deny", _R1_TMPL
        if secs == 0 or secs >= 30:
            return "deny", _R2_TMPL
        return "allow", ""
    if secs >= 120:
        if _PIPE_TAIL.search(command):
            return "deny", _R1_TMPL
        return "deny", _R2_TMPL
    return "allow", ""


def main() -> int:
    try:
        evt = json.load(sys.stdin)
    except Exception:
        return 0
    if evt.get("tool_name") != "Bash":
        return 0
    cmd = (evt.get("tool_input") or {}).get("command", "") or ""
    decision, reason = decide(cmd)
    if decision == "deny":
        json.dump({"decision": "block", "reason": reason,
                   "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}},
                  sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
