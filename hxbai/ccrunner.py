from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import SolverConfig

_FLAG_BODY = r"[A-Za-z0-9_!?@#$%.+*~^-]{1,200}"
_BUILTIN_PREFIXES = ("flag", "HTB", "SEKAI", "gctf")
_FINAL_RX = re.compile(r"<FinalAnswer>(.*?)</FinalAnswer>", re.IGNORECASE | re.DOTALL)
_HANDOFF_RX = re.compile(r"<Handoff>(.*?)</Handoff>", re.IGNORECASE | re.DOTALL)


def _flag_rxes(flag_format):
    prefixes = list(_BUILTIN_PREFIXES)
    for _fmt in re.split(r"[,\|;]", flag_format or ""):
        if "{" in _fmt:
            p = _fmt.split("{", 1)[0].strip()
            if p and p not in ("...", "*") and p.lower() not in (x.lower() for x in prefixes):
                prefixes.insert(0, p)
    return [re.compile(re.escape(p) + r"\{" + _FLAG_BODY + r"\}", re.IGNORECASE) for p in prefixes]

_MAX_TOOL_CHARS = 20000
_SLOW_CALL_S = float(os.environ.get("HXBAI_SLOW_CALL_S", "60") or "60")
_MAX_EVIDENCE = 400_000


def _first_flag_output_idx(outs, flag: str) -> int:
    if not flag:
        return -1
    import urllib.parse as _up
    for i, (_t, _a, o) in enumerate(outs):
        s = str(o)
        if flag in s:
            return i
        try:
            if flag in _up.unquote(s):
                return i
        except Exception:
            pass
    return -1


@dataclass
class CCResult:
    final_text: str = ""
    final_answer: str = ""
    handoff: str = ""
    flags: list[str] = field(default_factory=list)
    observed_output: str = ""
    tool_outputs: list[tuple] = field(default_factory=list)
    num_turns: int = 0
    tokens_used: int = 0
    slow_calls: list = field(default_factory=list)
    is_error: bool = False
    error: str = ""

    def evidence_for(self, flag: str) -> str:
        return (self.observed_output or "")[:_MAX_EVIDENCE]

    def flag_from_probe_echo(self, flag: str) -> bool:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        if isinstance(a, dict):
            cmd += " " + " ".join(f"{k}={v}" for k, v in a.items() if k != "command")
        return bool(flag) and (flag in cmd or flag.lower() in cmd.lower())

    def flag_from_own_narration(self, flag: str) -> bool:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        return _is_notes_read(outs[idx][0], outs[idx][1])

    def flag_from_static_source(self, flag: str) -> bool:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        cl = cmd.lower()
        if not any(r in cl for r in ("cat ", "less ", "more ", "head ", "tail ", "strings ",
                                     "xxd ", "nl ", "sed -n", "type ", "get-content", "read ")):
            return False
        _SRC_EXT = (".py", ".js", ".ts", ".php", ".java", ".rb", ".go", ".c", ".cpp", ".rs", ".pl",
                    ".env", ".yml", ".yaml", ".conf", ".cnf", ".ini", ".xml", ".json", ".toml",
                    ".properties", ".cfg", ".config")
        if any(e in cl for e in _SRC_EXT):
            return True
        return any(w in cl for w in ("config", "settings", "source", "src/", "application.", "web.xml"))

    def flag_source_hint(self, flag: str) -> str:
        import re as _re
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return ""
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        m = _re.search(r"url=([^\s&'\"]+)", cmd)
        if m:
            return m.group(1)[:60]
        for rx in (r"/api/[\w/-]+", r"/challenge/flag\d+\.txt", r"/[\w./-]+\.(?:txt|php|json|conf|env)"):
            m = _re.search(rx, cmd)
            if m:
                return m.group(0)[:60]
        return ""

    def flag_producer_endpoints(self, flag: str) -> set:
        import re as _re
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return set()
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        eps = set()
        for m in _re.finditer(r"(https?://)?((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?", cmd):
            scheme, host, port = m.group(1) or "", m.group(2), m.group(3)
            if port:
                eps.add((host, int(port)))
            elif scheme == "https://":
                eps.add((host, 443))
            elif scheme == "http://":
                eps.add((host, 80))
            else:
                eps.add((host, None))
        return eps

    def evidence_window(self, flag: str) -> str:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx >= 0:
            window = outs[max(0, idx - 2): idx + 3]
            body = "\n".join(f"$ {(a.get('command') if isinstance(a, dict) else a)}\n{str(o)[:2000]}"
                             for _t, a, o in window)
            return (body + "\n\n[FinalAnswer]\n" + (self.final_answer or ""))[:12000]
        if outs:
            tail = "\n".join(f"$ {(a.get('command') if isinstance(a, dict) else a)}\n{str(o)[:1200]}"
                             for _t, a, o in outs[-4:])
            return ((self.final_answer or "") + "\n\n[近期输出]\n" + tail)[:12000]
        o = self.observed_output or ""
        return (o[:3000] + "\n...\n" + o[-3000:] + "\n\n" + (self.final_answer or ""))[:12000]


def extract_final_answer(text: str) -> str:
    m = _FINAL_RX.search(text or "")
    return m.group(1).strip() if m else ""


def extract_handoff(text: str) -> str:
    m = _HANDOFF_RX.search(text or "")
    return m.group(1).strip() if m else ""


def _is_notes_read(tool, args) -> bool:
    cmd = (args.get("command") if isinstance(args, dict) else str(args or "")) or ""
    note_path = str((args.get("file_path") or args.get("path") or "") if isinstance(args, dict) else "")
    low = (cmd + " " + note_path).lower()
    if "memory.md" not in low:
        return False
    return tool == "Read" or any(v in low for v in
                                 ("cat ", "head ", "tail ", "less ", "more ", "grep ", "nl ", "strings "))


def extract_flags(text: str, flag_format: Optional[str] = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _emit(v: str):
        v = v.strip()
        if not v or "{" not in v or "}" not in v:
            return
        body = v[v.index("{") + 1:v.rindex("}")]
        if v in seen or not body or body in ("...", "…"):
            return
        seen.add(v)
        out.append(v)

    for rx in _flag_rxes(flag_format):
        for m in rx.finditer(text or ""):
            _emit(m.group(0))
    try:
        import urllib.parse as _up
        decoded = _up.unquote(text or "")
        if decoded != (text or ""):
            for rx in _flag_rxes(flag_format):
                for m in rx.finditer(decoded):
                    _emit(m.group(0))
    except Exception:
        pass
    return out


def _egress_host(t: str) -> str:
    h = str(t).strip().lower()
    if h.startswith("["):
        return h[1:].split("]", 1)[0]
    if h.count(":") == 1:
        return h.rsplit(":", 1)[0]
    return h


def _install_longtask_guard(workdir: str, targets=None) -> None:
    import shutil
    try:
        claude_dir = os.path.join(workdir, ".claude")
        os.makedirs(claude_dir, exist_ok=True)
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "longtask_guard.py")
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(claude_dir, "longtask_guard.py"))
        esrc = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bash_egress_guard.py")
        if os.path.exists(esrc):
            shutil.copyfile(esrc, os.path.join(claude_dir, "bash_egress_guard.py"))
        wsrc = os.path.join(os.path.dirname(os.path.abspath(__file__)), "websearch_guard.py")
        if os.path.exists(wsrc):
            shutil.copyfile(wsrc, os.path.join(claude_dir, "websearch_guard.py"))
            try:
                import urllib.parse
                _host = urllib.parse.urlparse(os.environ.get("BENCHMARK_BASE_URL", "") or "").hostname or ""
                _tgt_hosts = sorted({_egress_host(t) for t in (targets or []) if str(t).strip()})
                with open(os.path.join(claude_dir, "websearch_guard.json"), "w", encoding="utf-8") as f:
                    json.dump({"code": os.path.basename(workdir.rstrip("/")), "platform": _host,
                               "targets": _tgt_hosts}, f, ensure_ascii=False)
            except Exception:
                pass
        settings_path = os.path.join(claude_dir, "settings.json")
        settings: dict = {}
        if os.path.exists(settings_path):
            try:
                with open(settings_path, encoding="utf-8") as f:
                    settings = json.load(f)
            except Exception:
                settings = {}
        hooks = settings.setdefault("hooks", {})
        pre = hooks.setdefault("PreToolUse", [])
        entry = {"matcher": "Bash",
                 "hooks": [{"type": "command",
                            "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/longtask_guard.py"'},
                           {"type": "command",
                            "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/bash_egress_guard.py"'}]}
        if entry not in pre:
            pre.append(entry)
        wentry = {"matcher": "WebSearch|WebFetch",
                  "hooks": [{"type": "command",
                             "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/websearch_guard.py"'}]}
        if wentry not in pre:
            pre.append(wentry)
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def solve_with_claude_code(
    prompt: str,
    workdir: str,
    solver: SolverConfig,
    *,
    flag_format: Optional[str] = None,
    on_fact: Optional[Callable[[str, dict, str], None]] = None,
    claude_bin: Optional[str] = None,
    extra_args: Optional[list] = None,
    transcript_path: Optional[str] = None,
    targets: Optional[list] = None,
) -> CCResult:
    os.makedirs(workdir, exist_ok=True)
    _install_longtask_guard(workdir, targets=targets)
    binary = claude_bin or os.getenv("CLAUDE_BIN", "claude")
    env = dict(os.environ)
    for _k in ("BENCHMARK_TOKEN", "BENCHMARK_BASE_URL", "SOLVER_API_KEY"):
        env.pop(_k, None)
    env.update(solver.anthropic_env())
    try:
        _tmpdir = os.path.join(workdir, "tmp")
        os.makedirs(_tmpdir, exist_ok=True)
        env["TMPDIR"] = _tmpdir
        env.setdefault("TEMP", _tmpdir)
        env.setdefault("TMP", _tmpdir)
    except OSError:
        pass

    argv = [
        binary, "-p",
        "--output-format", "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
        "--max-turns", str(solver.max_turns),
        "--model", solver.model,
    ]
    if extra_args:
        argv.extend(extra_args)

    res = CCResult()
    pending: dict[str, tuple] = {}
    assistant_text_parts: list[str] = []
    evidence_len = 0
    assistant_turns = 0

    try:
        proc = subprocess.Popen(
            argv, cwd=workdir, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        res.is_error = True
        res.error = f"claude CLI not found ({binary}): {e}"
        return res
    except Exception as e:
        res.is_error = True
        res.error = f"failed to launch claude: {e}"
        return res

    import threading as _th

    stamped: list = []
    stderr_buf: list = []

    def _pump_out():
        try:
            for ln in proc.stdout:
                stamped.append((time.monotonic(), ln))
        except Exception:
            pass

    def _pump_err():
        try:
            for ln in proc.stderr:
                stderr_buf.append(ln)
        except Exception:
            pass

    _to = _th.Thread(target=_pump_out, daemon=True)
    _te = _th.Thread(target=_pump_err, daemon=True)
    _to.start()
    _te.start()
    try:
        proc.stdin.write(prompt)
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=solver.session_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=15)
        except Exception:
            pass
        res.error = "session timeout (normal for a long solve)"
    except Exception as e:
        res.error = f"session wait failed: {e}"
    _to.join(timeout=5)
    _te.join(timeout=5)
    stdout = "".join(ln for _ts, ln in stamped)
    stderr = "".join(stderr_buf)

    if transcript_path:
        try:
            os.makedirs(os.path.dirname(transcript_path) or ".", exist_ok=True)
            with open(transcript_path, "w", encoding="utf-8") as tf:
                tf.write("=== MODEL: " + solver.model + " | BASE: " + solver.base_url + " ===\n")
                tf.write("=== TASK PROMPT ===\n" + prompt + "\n=== STREAM-JSON (raw) ===\n")
                tf.write(stdout or "")
                if stderr:
                    tf.write("\n=== STDERR ===\n" + stderr[:4000])
        except Exception:
            pass

    for _arr, line in (stamped or []):
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        etype = ev.get("type")
        if etype == "assistant":
            assistant_turns += 1
            try:
                _u = (ev.get("message", {}) or {}).get("usage") or {}
                if isinstance(_u, dict):
                    res.tokens_used += sum(int(_u.get(k, 0) or 0) for k in
                                           ("input_tokens", "output_tokens",
                                            "cache_creation_input_tokens", "cache_read_input_tokens"))
            except Exception:
                pass
            for block in (ev.get("message", {}) or {}).get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    assistant_text_parts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    pending[block.get("id", "")] = (block.get("name", ""), block.get("input", {}) or {},
                                                    _arr)
        elif etype == "user":
            for block in (ev.get("message", {}) or {}).get("content", []) or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                name, args, t0 = pending.pop(block.get("tool_use_id", ""), ("tool", {}, _arr))
                output = _tool_result_text(block.get("content"))
                _dur = _arr - t0
                if _dur > _SLOW_CALL_S:
                    try:
                        res.slow_calls.append((name, round(_dur),
                                               str(args.get("command", args))[:100] if isinstance(args, dict) else str(args)[:100]))
                    except Exception:
                        pass
                if not output:
                    continue
                snippet = output[:_MAX_TOOL_CHARS]
                res.tool_outputs.append((name, args, snippet))
                if evidence_len < _MAX_EVIDENCE:
                    res.observed_output += snippet + "\n"
                    evidence_len += len(snippet) + 1
                if on_fact is not None:
                    try:
                        on_fact(name, args, snippet)
                    except Exception:
                        pass
        elif etype == "result":
            res.final_text = ev.get("result", "") or ""
            res.num_turns = int(ev.get("num_turns", 0) or 0)
            if ev.get("is_error") or ev.get("subtype") not in (None, "success"):
                res.is_error = True

    if not res.num_turns:
        res.num_turns = assistant_turns
    if not res.final_text:
        res.final_text = "\n".join(assistant_text_parts).strip()
    if (not res.final_text) and stderr:
        res.error = (res.error + " | " if res.error else "") + f"stderr: {stderr[:400]}"

    res.final_answer = extract_final_answer(res.final_text)
    res.handoff = extract_handoff(res.final_text)
    ordered: list[str] = []
    seen: set[str] = set()
    for src in (res.final_answer, res.final_text, res.observed_output):
        for f in extract_flags(src, flag_format):
            if f not in seen:
                seen.add(f)
                ordered.append(f)
    verbatim = [f for f in ordered if f in res.observed_output]
    res.flags = verbatim + [f for f in ordered if f not in verbatim]
    return res


def _tool_result_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return str(content)
