#!/usr/bin/env python3
"""Plain-language summaries of meetings and measures, written by a small local model.

    python tools/summarize.py --endpoint http://127.0.0.1:8080 [--limit 20] [--ids a b]

The model is Bonsai (1-bit, runs on a CPU), served by llama.cpp's OpenAI-compatible
server inside the refresh workflow, so the summaries cost nothing but the free
CI minutes of a public repo.

A summary is MACHINE-WRITTEN and is labelled so everywhere it appears. It never
goes into records/: a record is the sourced fact and carries its content hash;
a summary is a reading aid that lives beside it under summaries/<id>.json and
names the model, the source it read and when. If the source page cannot be read,
there is no summary, never a guess from the title alone.

Stdlib only. Exit 0 wrote or skipped cleanly, 1 the model endpoint failed,
2 nothing to summarise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:                       # the pinned copy ships beside this file in a generated repo
    import civic_schema as schema  # noqa: E402
except ImportError:        # the template tree itself has no pinned copy (dev tests)
    schema = None

ROOT = HERE.parent
RECORDS = ROOT / "records"
OUT = ROOT / "summaries"
KINDS = ("meeting", "measure")
MAX_SOURCE_CHARS = 6000
UA = "civic-summarize/1 (+https://aitherium.com)"

PROMPT = (
    "You explain local and national government to ordinary residents. Using ONLY the "
    "source text below, write 2-4 short sentences in plain language: what this {kind} "
    "is, what was decided or proposed, and when. If the text does not say, write "
    "\"The source does not say.\" Do not add facts. No preamble.\n\n"
    "Title: {title}\n\nSource text:\n{text}"
)


def _records(ids):
    for path in sorted(RECORDS.rglob("*.json")):
        if "_retired" in path.relative_to(RECORDS).parts:
            continue                           # retired records get no new summary
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if rec.get("kind") not in KINDS or (ids and rec.get("id") not in ids):
            continue
        yield rec


def _summary_path(rid: str) -> Path:
    """``summaries/<safe_filename(id)>``: a meeting id carries ``/`` and must not nest."""
    if schema is not None:
        return OUT / schema.safe_filename(rid)
    # Only reachable when the template is imported without its pinned schema copy
    # (AitherOS' own tests); test_civic_template_summarize pins it to the real one.
    return OUT / (re.sub(r"[^a-z0-9._-]+", "_", str(rid).lower()) + ".json")


def _fetchable(url: str, allow: list[str]) -> bool:
    """The two gates verify.py applies: an allowlisted host that resolves public.

    A meeting's ``provenance.sources[].url`` is crowd-supplied; without this the
    model fetches an arbitrary host (SSRF) and its text is published under this
    repo's name.
    """
    import verify
    host = urlsplit(url).hostname or ""
    return verify.host_allowed(host, allow) and verify.resolves_public(host)


def _source_url(rec: dict, allow: list[str]) -> str:
    for src in (rec.get("provenance") or {}).get("sources") or []:
        url = (src or {}).get("url", "")
        if url.startswith("https://") and _fetchable(url, allow):
            return url
    return ""


def _page_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 -- https only
        raw = resp.read(400_000).decode("utf-8", "replace")
    raw = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", raw)
    text = html.unescape(re.sub(r"(?s)<[^>]+>", " ", raw))
    return re.sub(r"\s+", " ", text).strip()[:MAX_SOURCE_CHARS]


#: Anti-bot interstitials. Measured 2026-11-09: federalregister.gov answered a
#: scraper with a "request access" page and the model dutifully summarised THAT.
_BLOCK_MARKERS = ("captcha", "request access", "automated scraping", "are you a robot",
                  "access denied", "enable javascript", "unusual traffic", "cloudflare ray id")
_STOP = {"the", "and", "for", "of", "to", "a", "an", "in", "on", "at", "by", "or", "with"}


def unreadable_reason(title: str, text: str) -> str:
    """Why this page is not the record's source, or '' when it plausibly is."""
    low = text.lower()
    if len(text) < 200:
        return "too little text"
    hit = next((m for m in _BLOCK_MARKERS if m in low[:3000]), "")
    if hit:
        return f"looks like a block page ({hit!r})"
    words = {w for w in re.findall(r"[a-z]{3,}", title.lower()) if w not in _STOP}
    if words and sum(1 for w in words if w in low) < max(1, len(words) // 2):
        return "page does not mention the record's title"
    return ""


def _ask(endpoint: str, prompt: str, model: str) -> str:
    body = json.dumps({"model": model, "temperature": 0.2, "max_tokens": 220,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(endpoint.rstrip("/") + "/v1/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310 -- local server
        out = json.loads(resp.read())
    return (out["choices"][0]["message"]["content"] or "").strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--endpoint", default="http://127.0.0.1:8080")
    ap.add_argument("--model", default="Bonsai-8B-Q1_0")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--force", action="store_true", help="rewrite existing summaries")
    args = ap.parse_args(argv)

    todo = [r for r in _records(set(args.ids or []))
            if args.force or not _summary_path(r["id"]).exists()]
    if not todo:
        print("summarize: nothing to summarise")
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    import verify
    allow = verify._allowlist(ROOT)
    wrote = skipped = 0
    for rec in todo[: args.limit]:
        url = _source_url(rec, allow)
        if not url:
            print(f"skip {rec['id']}: no source url on an allowlisted public host")
            skipped += 1
            continue
        try:
            text = _page_text(url)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"skip {rec['id']}: source unreadable ({type(exc).__name__})")
            skipped += 1
            continue
        why = unreadable_reason(rec.get("title", ""), text)
        if why:
            print(f"skip {rec['id']}: {why}")
            skipped += 1
            continue
        prompt = PROMPT.format(kind=rec["kind"], title=rec.get("title", ""), text=text)
        try:
            summary = _ask(args.endpoint, prompt, args.model)
        except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError) as exc:
            print(f"summarize: model endpoint failed: {type(exc).__name__}: {exc}")
            return 1
        with open(_summary_path(rec["id"]), "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"id": rec["id"], "summary": summary, "machine_written": True,
                       "model": args.model, "source": url,
                       "at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                      fh, indent=2)
            fh.write("\n")
        wrote += 1
        print(f"wrote {rec['id']}")
    print(f"summarize: wrote {wrote}, skipped {skipped}, left {max(0, len(todo) - args.limit)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
