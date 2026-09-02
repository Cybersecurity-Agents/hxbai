#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

_MAX_BODY_SNIPPET = 160


def parse_url(url: str):
    p = urlsplit(url if "://" in url else "http://" + url)
    host, port = p.hostname, p.port or (443 if p.scheme == "https" else 80)
    return p.scheme, host, port


def parse_request_file(text: str, *, default_method="GET", default_path="/", default_data=None):
    lines = text.replace("\r\n", "\n").split("\n")
    method, path = default_method, default_path
    headers: dict = {}
    body = default_data or ""
    i = 0
    if lines and lines[0].split(" ")[:1] and lines[0].split(" ")[0].upper() in (
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        parts = lines[0].split(" ")
        method = parts[0].upper()
        if len(parts) > 1:
            path = parts[1]
        i = 1
    while i < len(lines):
        line = lines[i]
        if line == "":
            body = "\n".join(lines[i + 1:]).strip("\n")
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        i += 1
    headers.setdefault("host", "")
    return method, path, headers, body


class _Lane:

    def __init__(self, name, scheme, host, port, req, timeout):
        self.name = name
        self._conn = (http.client.HTTPSConnection(host, port, context=ssl._create_unverified_context(),
                                                  timeout=timeout)
                      if scheme == "https" else http.client.HTTPConnection(host, port, timeout=timeout))
        self._req = req
        self.result = None

    def warmup(self):
        try:
            self._conn.request("GET", "/", headers={"accept": "*/*"})
            self._conn.getresponse().read(64)
        except Exception:
            try:
                self._conn.close()
            except Exception:
                pass

    def fire(self, barrier: threading.Barrier):
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        method, path, headers, body = self._req
        h = dict(headers)
        if body and "content-length" not in h and "transfer-encoding" not in h:
            h["content-length"] = str(len(body.encode()))
        try:
            self._conn.request(method, path, body=body or None, headers=h)
            resp = self._conn.getresponse()
            data = resp.read(8192)
            self.result = (resp.status, len(data), resp.getheader("location") or "-",
                           resp.getheader("server") or "-",
                           data[:_MAX_BODY_SNIPPET].decode("utf-8", "replace").replace("\n", " "))
        except Exception as e:
            self.result = ("ERR", 0, "-", "-", f"{type(e).__name__}: {e}"[:_MAX_BODY_SNIPPET])
        finally:
            try:
                self._conn.close()
            except Exception:
                pass


def _race_round(lanes, timeout):
    for ln in lanes:
        ln.warmup()
    barrier = threading.Barrier(len(lanes))
    threads = [threading.Thread(target=ln.fire, args=(barrier,)) for ln in lanes]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=max(5.0, timeout))
    return time.monotonic() - t0


def main() -> int:
    ap = argparse.ArgumentParser(description="true-concurrency HTTP race executor (stdlib)")
    ap.add_argument("--url", required=True, help="base URL, e.g. http://10.0.0.5:8000")
    ap.add_argument("--reqs", help="comma-separated raw request FILES (>=2 lanes, distinct requests)")
    ap.add_argument("--file", help="ONE raw request file replicated into --count lanes")
    ap.add_argument("--count", type=int, default=20, help="lanes when using --file (default 20)")
    ap.add_argument("--rounds", type=int, default=10, help="race repetitions (default 10)")
    ap.add_argument("--method", default="POST", help="default method when a file lacks a request line")
    ap.add_argument("--path", default="/", help="default path when a file lacks a request line")
    ap.add_argument("--data", default="", help="default body when a file lacks one")
    ap.add_argument("--cookie", default="", help='Cookie header added to EVERY lane, e.g. "sid=abc"')
    ap.add_argument("--header", action="append", default=[], help="extra header 'K: V' (repeatable)")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds")
    args = ap.parse_args()

    scheme, host, port = parse_url(args.url)
    specs = []
    if args.reqs:
        for f in [x.strip() for x in args.reqs.split(",") if x.strip()]:
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    specs.append((f, fh.read()))
            except OSError as e:
                print(f"[race] cannot read {f}: {e}")
                return 2
    elif args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                specs = [(f"{args.file}#{i}", fh.read()) for i in range(max(2, args.count))]
        except OSError as e:
            print(f"[race] cannot read {args.file}: {e}")
            return 2
    else:
        ap.error("need --reqs (distinct files) or --file (one file x --count)")

    extra = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra[k.strip().lower()] = v.strip()
    if args.cookie:
        extra["cookie"] = (extra.get("cookie", "") + ("; " if extra.get("cookie") else "") + args.cookie).strip("; ")

    lanes = []
    for name, text in specs:
        method, path, headers, body = parse_request_file(
            text, default_method=args.method, default_path=args.path, default_data=args.data)
        headers.setdefault("host", f"{host}:{port}")
        headers.update(extra)
        lanes.append(_Lane(name, scheme, host, port, (method, path, headers, body), args.timeout))

    print(f"[race] {len(lanes)} lanes x {args.rounds} rounds -> {scheme}://{host}:{port}")
    print(f"[race] lanes: {', '.join(f'{ln.name}({ln._req[0]} {ln._req[1]})' for ln in lanes)}")
    first_diverge = None
    for r in range(1, args.rounds + 1):
        took = _race_round(lanes, args.timeout)
        sigs = [(ln.name, *ln.result) for ln in lanes]
        statuses = {s[1] for s in sigs}
        lens = {s[2] for s in sigs}
        div = len(statuses) > 1 or len(lens) > 1
        mark = "  <-- DIVERGENT" if div else ""
        if div and first_diverge is None:
            first_diverge = r
        print(f"round {r:3d} ({took*1000:6.0f} ms){mark}")
        for name, st, ln_, loc, srv, snip in sigs:
            print(f"    {name[:28]:28} status={st} len={ln_:5} loc={loc[:40]:40} server={srv[:16]:16} {snip[:70]}")
    if first_diverge is not None:
        print(f"\n[race] VERDICT: lanes diverged first at round {first_diverge} — the race window "
              f"IS reachable. Differential above is the exploit signal (craft the mixed-state from it).")
    else:
        print("\n[race] VERDICT: no divergence in "
              f"{args.rounds} rounds. Try: more rounds / tighter target endpoint / check replica "
              f"headers above (different `server:` = multi-replica; pin via --cookie).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
