from __future__ import annotations

import json
import os
import sys

_REQUIRED = ("id", "product", "versions", "fingerprint", "impact", "exploit")
_LIST_FIELDS = ("fingerprint", "anti_fingerprint")


def check(path: str | None = None) -> list[str]:
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve-quick.json")
    errs: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"cannot load {path}: {e}"]
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        return ["'entries' missing or empty"]
    seen: set[str] = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            errs.append(f"entry[{i}] is not an object")
            continue
        eid = e.get("id", f"<{i}>")
        for k in _REQUIRED:
            if not e.get(k):
                errs.append(f"{eid}: missing/empty required field '{k}'")
        for k in _LIST_FIELDS:
            if k in e and not isinstance(e[k], list):
                errs.append(f"{eid}: field '{k}' must be a list")
        if not e.get("fingerprint"):
            errs.append(f"{eid}: fingerprint must have >=1 entry (recall needs a signal)")
        if eid in seen:
            errs.append(f"duplicate id '{eid}'")
        seen.add(eid)
    return errs


def main() -> int:
    errs = check()
    if errs:
        print("cve-quick.json FAILED validation:", file=sys.stderr)
        for e in errs:
            print("  - " + e, file=sys.stderr)
        return 1
    print("cve-quick.json OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
