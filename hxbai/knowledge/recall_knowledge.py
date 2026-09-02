#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def main() -> int:
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    top_k = 3
    for a in sys.argv[1:]:
        if a.startswith("--top"):
            try:
                top_k = int(a.split("=", 1)[1]) if "=" in a else int(sys.argv[sys.argv.index(a) + 1])
            except Exception:
                top_k = 3
    query = " ".join(argv).strip()
    if not query:
        print("usage: recall_knowledge.py \"<技术/现象关键词>\" [--top N]", file=sys.stderr)
        return 2
    from hxbai.knowledge.store import KnowledgeStore
    try:
        store = KnowledgeStore()
    except Exception as e:
        print(f"[recall_knowledge] store 不可用: {e}", file=sys.stderr)
        return 1
    hits = store.recall(query, top_k=top_k, min_score=2)
    if not hits:
        print("[recall_knowledge] 无命中(卡是假设库,不是答案库;无命中就继续自研路径)")
        return 0
    print(f"[recall_knowledge] query={query!r} top{len(hits)} (卡=假设:先验其指纹,不符即弃)")
    for rank, (e, s) in enumerate(hits, 1):
        print(f"\n===== #{rank} {e.id} (score={s}) =====")
        try:
            print(e.render())
        except Exception:
            print(f"title: {e.title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
