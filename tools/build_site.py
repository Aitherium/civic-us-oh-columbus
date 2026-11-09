#!/usr/bin/env python3
"""Render this civic repo as a static site (out/index.html, out/index.json).

Refuses to build (exit 1) when tools/check.py finds anything: a public page is
never published past a failing gate. Exit 2 when there are no records.

    python tools/build_site.py --out <dir>
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import civic_schema as schema  # noqa: E402

TIERS = ("submitted", "source-reachable", "source-proven", "corroborated")


def _rows(records: list) -> str:
    e = html.escape
    out = []
    for r in sorted(records, key=lambda x: (x.kind, str(x.raw.get("title", "")).lower())):
        if r.kind == "source":
            continue
        eff = schema.effective(r.raw)
        title = str(eff.get("title") or eff.get("name") or r.id)
        tier = TIERS[schema.trust(r.raw)]
        detail = ""
        if r.kind == "official":
            person = eff.get("person") or {}
            # Every interpolated field is escaped: a full_name is submitter-controlled
            # (an intake issue) and this page is published on push to main.
            detail = e(str(person.get("full_name") or ""))
            office = str(eff.get("office") or eff.get("body") or "")
            detail += f" &middot; {e(office)}" if office else ""
        elif r.kind == "body":
            detail = f"{e(str(eff.get('seats', '')))} seat(s) &middot; " \
                     f"{e(str(eff.get('selection', '')))}"
        elif r.kind == "office":
            detail = e(str(eff.get("body") or ""))
        out.append(f'<tr id="{e(r.id, quote=True)}"><td>{e(r.kind)}</td>'
                   f"<td>{e(title)}<div class='m'>{detail}</div></td>"
                   f"<td class='m'>{e(tier)}</td></tr>")
    return "".join(out)


def _page(jur: dict, records: list) -> str:
    e = html.escape
    cov = jur.get("coverage") or {}
    gaps = "".join(f"<li>{e(str(g))}</li>" for g in cov.get("gaps") or [])
    law = jur.get("law") or {}
    nearest = ", ".join(e(str(n.get("path"))) for n in law.get("nearest") or []) or "none"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(str(jur.get('title') or jur.get('id')))}</title>
<style>
:root{{--bg:#fbfaf7;--fg:#1d1b18;--mute:#6b665d;--line:#e4e0d8;--acc:#3b5bdb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141311;--fg:#ece8e1;--mute:#9a948a;
--line:#2c2a26;--acc:#8ea2ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;
margin:0 auto;max-width:1000px;padding:24px 16px}}
h1{{margin:0 0 4px}} .m{{color:var(--mute);font-size:13px}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
a{{color:var(--acc)}} code{{font-size:13px}}
</style></head><body>
<h1>{e(str(jur.get('title') or jur.get('id')))}</h1>
<p class="m">{e(str(jur.get('id')))} &middot; {e(str(jur.get('level')))} &middot;
law: {nearest}</p>
<div class="wrap"><table><thead><tr><th>kind</th><th>record</th>
<th>trust</th></tr></thead><tbody>{_rows(records)}</tbody></table></div>
<h2>Known gaps</h2><ul>{gaps}</ul>
<p class="m">Every record names who added it and what backs it. A correction is a
pull request; nothing here is asserted without a source.</p>
</body></html>
"""


def build(root: Path, out: Path) -> int:
    code, findings, n = schema.check_root(root)
    if not n:
        print(f"could not build: no records under {root}")
        return 2
    if code:
        for f in findings:
            print(f)
        print("refusing to publish a failing repo")
        return 1
    records, _ = schema.load(root)
    jur = next((r.raw for r in records if r.kind == "jurisdiction"), {})
    out.mkdir(parents=True, exist_ok=True)
    payload = {"jurisdiction": jur, "source_sha": _sha(root),
               "records": [{"id": r.id, "kind": r.kind, "raw": schema.effective(r.raw),
                            "trust": schema.trust(r.raw)} for r in records]}
    (out / "index.json").write_text(json.dumps(payload, indent=1, ensure_ascii=False),
                                    encoding="utf-8", newline="\n")
    (out / "index.html").write_text(_page(jur, records), encoding="utf-8", newline="\n")
    print(f"built {out}: {len(records)} records")
    return 0


def _sha(root: Path) -> str:
    import subprocess
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(["git", "-C", str(root), "log", "-1", "--format=%H", "--", "."],
                           capture_output=True, text=True, encoding="utf-8",
                           timeout=30, creationflags=flags)
        return r.stdout.strip() or "uncommitted"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=HERE.parent)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    return build(a.root, a.out)


if __name__ == "__main__":
    sys.exit(main())
