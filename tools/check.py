#!/usr/bin/env python3
"""Validate this civic repo. Exit 0 clean, 1 violation, 2 could-not-judge.

    python tools/check.py
    python tools/check.py --require-law --corpus /data/global-law
    python tools/check.py --json

The rules live in the pinned copy at tools/civic_schema.py; this file is only the
door. stdlib only, Python 3.10 compatible.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import civic_schema as schema  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=HERE.parent)
    ap.add_argument("--require-law", action="store_true",
                    help="law_refs must resolve in a pinned global-law checkout")
    ap.add_argument("--corpus", type=Path, default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        ok, lines = schema.self_test()
        print("\n".join(lines))
        return 0 if ok else 1
    code, findings, n = schema.check_root(a.root, require_law=a.require_law,
                                          corpus_root=a.corpus)
    if a.json:
        print(json.dumps({"exit": code, "records": n,
                          "findings": [{"code": f.code, "record": f.record,
                                        "message": f.message, "unjudged": f.unjudged}
                                       for f in findings]}, indent=2))
    else:
        for f in findings:
            print(f)
    print(f"check: {n} record(s), {len(findings)} finding(s), exit {code}",
          file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
