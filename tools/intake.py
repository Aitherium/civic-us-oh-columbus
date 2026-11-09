#!/usr/bin/env python3
"""Turn a civic issue form into record files. Run by .github/workflows/intake.yml.

The issue body is UNTRUSTED: it is read from the event JSON (never a shell
argument), every field is length-capped and pattern-checked, and every id is
DERIVED from the submitted facts, never chosen by the submitter. A record enters
at tier 0 (``submitted``) with the source that backs it, and is written only if the
validator accepts the repo with both in place -- a submission that would break the
repo is rejected, not saved.

CV050 keeps the source allowlist honest: a host that is not on
``config/official_domains.txt`` is refused, and the message names the line a
maintainer adds in the PR.

    python tools/intake.py --event "$GITHUB_EVENT_PATH"
    python tools/intake.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import civic_schema as schema  # noqa: E402

_SAFE = re.compile(r"[^a-z0-9._-]+")
_URL = re.compile(r"^https://([A-Za-z0-9.-]+)(?::\d+)?(?:/[^\s]*)?$")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)")
#: Labels that would put personal data into a public-official record. The record
#: model allows OFFICE contact only; a submission that carries one of these is
#: rejected before anything is written (CV020/CV022 at the record layer).
_FORBIDDEN_LABELS = ("home address", "home phone", "personal email", "personal phone",
                     "date of birth", "dob", "ssn", "social security", "spouse",
                     "children", "health", "medical", "immigration")
_OFFICE_CONTACT_LABELS = ("office email", "office phone", "office address")
TYPES = ("body", "official", "meeting", "error", "jurisdiction")


def screen(form: dict) -> None:
    """Refuse personal data in any field. Office contact is the only exception."""
    for label, value in form.items():
        low = label.lower()
        if any(bad in low for bad in _FORBIDDEN_LABELS):
            raise ValueError(f"'{label}' is never recorded: office contact only")
        if low in _OFFICE_CONTACT_LABELS:
            continue
        if _EMAIL.search(value) or _PHONE.search(value):
            raise ValueError(f"'{label}' carries a personal email or phone; "
                             "the record accepts office contact only")


def parse_form(body: str) -> dict:
    """GitHub issue forms render as '### Label' followed by the value."""
    out: dict = {}
    key = None
    for line in (body or "").splitlines():
        if line.startswith("### "):
            key = line[4:].strip().lower()
            out[key] = []
        elif key is not None:
            out[key].append(line)
    joined = {k: "\n".join(v).strip() for k, v in out.items()}
    return {k: v for k, v in joined.items() if v not in ("", "_No response_")}


def _slug(text: str, limit: int = 48) -> str:
    return _SAFE.sub("-", str(text).strip().lower()).strip("-")[:limit].strip("-")


def _get(form: dict, *names: str) -> str:
    for n in names:
        v = str(form.get(n, "")).strip()
        if v:
            return v
    return ""


def _safe_title(title: str, number) -> str:
    """The issue title becomes a published source title, so it is screened too.

    A title is free text the submitter chose; ``Jane Doe, 123 Main St`` or a
    personal email must not land in a public record just because it was typed in
    the title box rather than a form field.
    """
    text = str(title or "").strip()[:160]
    if not text or _EMAIL.search(text) or _PHONE.search(text):
        return f"civic submission #{number or 'unknown'}"[:160]
    return text


def _url(form: dict) -> str:
    url = _get(form, "source url", "source", "url")
    m = _URL.match(url)
    if not m or len(url) > 300:
        raise ValueError("a source url is required, must be https:// and at most 300 chars")
    return url


def _source_id(url: str) -> str:
    return "source:" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _prov(url: str, login: str, today: dt.date, method: str = "submitted") -> dict:
    return {"added_by": f"github:{login}", "added_at": today.isoformat(),
            "sources": [{"source_id": _source_id(url), "url": url,
                         "retrieved_at": today.isoformat(), "license": "see source"}],
            "validated": {"at": today.isoformat(), "by": f"github:{login}",
                          "method": method},
            "vouches": [], "evidence": {}}


def source_record(url: str, title: str, login: str, today: dt.date) -> dict:
    rec = {"schema_version": schema.SCHEMA_VERSION, "id": _source_id(url),
           "kind": "source", "title": title[:160], "url": url,
           "publisher": _URL.match(url).group(1),
           "media_type": "pdf" if url.lower().endswith(".pdf") else "html",
           "retrieved_at": today.isoformat(), "http_status": 0,
           "license": "see source", "note": "submitted; not yet fetched",
           "privacy": "public-record", "provenance": _prov(url, login, today),
           "overrides": []}
    return _seal(rec)


def _seal(rec: dict) -> dict:
    if not rec.get("generation"):
        rec["generation"] = {"generator": "intake/1", "at": dt.datetime.now(
            dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "source_snapshot": {},
            "content_hash": ""}
        rec["generation"]["content_hash"] = schema.content_hash(rec)
    return rec


_KIND_LABELS = {"jurisdiction": "jurisdiction", "body": "bodies", "office": "offices",
                "official": "officials", "meeting": "meetings", "measure": "measures",
                "source": "sources"}


def sync_coverage(root: Path) -> None:
    """Rewrite ``coverage.json`` counts from the records on disk.

    A submission writes a record, so the counts it leaves behind must include it:
    CV060 compares coverage.json to the disk, and stale counts make every later
    ``tools/check.py`` fail -- so the PR never opens and the submitter sees nothing.
    """
    cp = Path(root) / "coverage.json"
    try:
        cov = json.loads(cp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    records, _ = schema.load(root)
    counts = {label: 0 for label in _KIND_LABELS.values()}
    for rec in records:
        label = _KIND_LABELS.get(rec.kind)
        if label:
            counts[label] += 1
    cov["counts"] = counts
    cov["sources"] = sorted(r.id for r in records if r.kind == "source")
    cp.write_text(json.dumps(cov, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                  encoding="utf-8", newline="\n")


def apply_retraction(root: Path, rec: dict) -> int:
    """Resolve the record a retraction names. A retraction that resolves nothing is
    refused: otherwise every ``error:`` issue produces a pull request that changes
    no record at all."""
    records, _ = schema.load(root)
    target = next((r for r in records if r.id == rec["id"]), None)
    if target is None or target.path is None:
        print(f"rejected: no live record with id {rec['id']}", file=sys.stderr)
        return 1
    raw = json.loads(target.path.read_text(encoding="utf-8"))
    prov = raw.setdefault("provenance", {})
    evidence = prov.setdefault("evidence", {})
    evidence["retraction"] = {"reason": rec["reason"][:1000], "by": rec["by"],
                              "at": rec["at"], "source": rec["url"]}
    raw["retracted"] = True
    if raw.get("generation"):
        raw["generation"]["content_hash"] = schema.content_hash(raw)
    target.path.write_text(json.dumps(raw, indent=2, sort_keys=True,
                                      ensure_ascii=False) + "\n",
                           encoding="utf-8", newline="\n")
    line = json.dumps({k: rec[k] for k in ("id", "reason", "by", "at", "url")},
                      sort_keys=True)
    with (root / "RETRACTIONS.md").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")
    print(rec["id"])
    return 0


def record_from(form: dict, login: str, today: dt.date, jid: str) -> dict:
    screen(form)
    kind = _get(form, "record type", "type").lower()
    if kind not in TYPES:
        raise ValueError(f"record type must be one of {list(TYPES)}")
    url = _url(form)
    prov = _prov(url, login, today)

    if kind == "jurisdiction":
        name = _get(form, "name", "town name")
        state = _get(form, "state").upper()
        geoid = re.sub(r"[^0-9]", "", _get(form, "census geoid"))
        if not name or len(name) > 120:
            raise ValueError("a name is required")
        if not re.match(r"^[A-Z]{2}$", state):
            raise ValueError("state must be a two-letter postal code")
        if geoid and not re.match(r"^\d{5,15}$", geoid):
            raise ValueError("census geoid must be digits")
        return {"kind": "request", "id": f"request:{_slug(f'{state}-{name}')}",
                "name": name, "state": state, "geoid": geoid,
                "by": f"github:{login}", "at": today.isoformat(), "url": url}
    if kind == "body":
        slug = _slug(_get(form, "name", "title"))
        if not slug:
            raise ValueError("body needs a name")
        digits = re.sub(r"[^0-9]", "", _get(form, "seats") or "0") or "0"
        seats = int(digits)
        if not 0 < seats <= 999:
            raise ValueError("seats must be a number between 1 and 999")
        rec = {"schema_version": schema.SCHEMA_VERSION, "id": f"body:{jid}-{slug}",
               "kind": "body", "title": _get(form, "name", "title")[:120],
               "jurisdiction": jid,
               "body_type": _get(form, "body type").lower() or "board",
               "name": _get(form, "name", "title")[:120], "seats": seats,
               "selection": _get(form, "selection").lower() or "elected",
               "status": "active", "parent_body": None, "provenance": prov,
               "privacy": "public-record", "overrides": []}
    elif kind == "official":
        office = _get(form, "office id", "office")
        if not re.match(r"^office:body:jur:.+/[a-z0-9][a-z0-9-]*$", office):
            raise ValueError("office id must be the office's full id (office:body:jur:...)")
        name = _get(form, "full name", "name")
        if not name or len(name) > 120:
            raise ValueError("full name is required")
        end = _get(form, "term end")
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", end):
            raise ValueError("term end must be YYYY-MM-DD")
        rec = {"schema_version": schema.SCHEMA_VERSION,
               "id": f"official:{office}/{end[:4]}", "kind": "official",
               "title": f"{name} ({_get(form, 'district') or 'seat'})"[:160],
               "jurisdiction": jid, "person": {"full_name": name[:120]},
               "term": {"start": None, "end": end, "status": "current"},
               "status": "current", "district": _get(form, "district")[:24],
               "office": office, "privacy": "public-official",
               "provenance": prov, "overrides": []}
        party = _get(form, "party (optional)", "party")
        if party:
            rec["person"]["party"] = party[:40]
    elif kind == "meeting":
        body = _get(form, "body id", "body")
        if not re.match(r"^body:jur:.+-[a-z0-9][a-z0-9-]*$", body):
            raise ValueError("body id must be the body's full id (body:jur:...)")
        date = _get(form, "date")
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
            raise ValueError("date must be YYYY-MM-DD")
        seq = _get(form, "meeting number") or "1"
        if not seq.isdigit():
            raise ValueError("meeting number must be a whole number")
        rec = {"schema_version": schema.SCHEMA_VERSION,
               "id": f"meeting:{body}/{date}-{int(seq)}@r01", "kind": "meeting",
               "title": f"{date} meeting"[:120], "jurisdiction": jid, "body": body,
               "meeting_key": f"{_slug(body.rsplit('-', 1)[-1])}/{date}-{int(seq)}",
               "revision": 1, "date": date,
               "meeting_type": _get(form, "meeting type").lower() or "regular",
               "status": _get(form, "status").lower() or "scheduled",
               "agenda": {"source_id": _source_id(url), "url": url},
               "provenance": prov, "privacy": "public-record", "overrides": []}
    else:
        rid = _get(form, "record id")
        reason = _get(form, "what is wrong", "reason")
        if not rid or not reason or len(reason) > 1000:
            raise ValueError("a record id and a reason are required")
        rec = {"kind": "retraction", "id": rid, "reason": reason,
               "by": f"github:{login}", "at": today.isoformat(), "url": url}
        return rec
    return _seal(rec)


def _self_test() -> int:
    day = dt.date(2026, 11, 9)
    jid = "jur:us-ca:place:0644000"
    ok = True
    body = ("### Record type\n\nbody\n\n### Name\n\nRent Stabilization Board\n\n"
            "### Seats\n\n9\n\n### Selection\n\nelected\n\n### Body type\n\nboard\n\n"
            "### Source URL\n\nhttps://lacity.gov/rsob\n")
    rec = record_from(parse_form(body), "alice", day, jid)
    ok = ok and rec["id"] == f"body:{jid}-rent-stabilization-board"
    ok = ok and rec["seats"] == 9
    ok = ok and rec["provenance"]["validated"]["method"] == "submitted"
    ok = ok and source_record("https://lacity.gov/rsob", "t", "alice", day)["id"] \
        == _source_id("https://lacity.gov/rsob")
    req = record_from({"record type": "jurisdiction", "name": "Yucca Valley",
                       "state": "ca", "source url": "https://www.yucca-valley.org/"},
                      "alice", day, jid)
    ok = ok and req["kind"] == "request" and req["id"] == "request:ca-yucca-valley"
    for bad in ({"record type": "admin", "source url": "https://x.gov/a"},
                {"record type": "body", "name": "X", "seats": "0",
                 "source url": "https://x.gov/a"},
                {"record type": "body", "name": "X", "seats": "5",
                 "source url": "http://x.gov/a"},
                {"record type": "official", "full name": "A",
                 "office id": "mayor", "term end": "2027-01-01",
                 "source url": "https://x.gov/a"},
                {"record type": "official", "full name": "A",
                 "office id": "office:body:jur:x/mayor", "term end": "2027-01-01",
                 "source url": "https://x.gov/a", "personal email": "a@b.example"},
                {"record type": "body", "name": "X", "seats": "5",
                 "source url": "https://x.gov/a", "summary": "call 213-555-1212"}):
        try:
            record_from(bad, "m", day, jid)
            ok = False
        except ValueError:
            continue
    ok = ok and record_from(
        {"record type": "body", "name": "X", "seats": "5",
         "source url": "https://x.gov/a", "office email": "clerk@x.gov"}, "m", day, jid)[
             "kind"] == "body"
    # the issue form renders "Party (optional)", so the label carries the suffix
    ok = ok and record_from(
        {"record type": "official", "office id": "office:body:jur:x/mayor",
         "full name": "A", "term end": "2027-01-01", "source url": "https://x.gov/a",
         "party (optional)": "Green"}, "m", day, jid)["person"].get("party") == "Green"
    # an issue title is free text and is screened like any other field
    ok = ok and _safe_title("Jane Doe, jane@example.com", 7) == "civic submission #7"
    ok = ok and _safe_title("call 213-555-1212", 7) == "civic submission #7"
    ok = ok and _safe_title("civic: a body", 7) == "civic: a body"
    # a submission updates coverage.json, and a retraction resolves its record
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        item = dict(rec, id=f"body:{jid}-rent-stabilization-board")
        (root / "records" / "body").mkdir(parents=True)
        (root / "records" / "body" / schema.safe_filename(item["id"])).write_text(
            json.dumps(item), encoding="utf-8")
        (root / "coverage.json").write_text(json.dumps({"counts": {"bodies": 0}}),
                                            encoding="utf-8")
        sync_coverage(root)
        ok = ok and json.loads((root / "coverage.json").read_text(
            encoding="utf-8"))["counts"]["bodies"] == 1
        retr = record_from({"record type": "error", "record id": item["id"],
                            "what is wrong": "the seats are wrong",
                            "source url": "https://lacity.gov/x"}, "bob", day, jid)
        ok = ok and apply_retraction(root, retr) == 0
        saved = json.loads((root / "records" / "body"
                            / schema.safe_filename(item["id"])).read_text(encoding="utf-8"))
        ok = ok and saved.get("retracted") is True
        ok = ok and bool(((saved.get("provenance") or {}).get("evidence") or {})
                         .get("retraction", {}).get("reason"))
        ghost = record_from({"record type": "error",
                             "record id": "body:jur:us-ca:place:0099999-gone",
                             "what is wrong": "nothing here",
                             "source url": "https://lacity.gov/x"}, "bob", day, jid)
        ok = ok and apply_retraction(root, ghost) == 1
    print("PASS intake" if ok else "FAIL intake")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--event", type=Path)
    ap.add_argument("--root", type=Path, default=HERE.parent)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    if not a.event:
        ap.error("--event is required unless --self-test")
    event = json.loads(a.event.read_text(encoding="utf-8"))
    issue = event.get("issue") or {}
    root = a.root
    jid = str(json.loads((root / "jurisdiction.json").read_text(
        encoding="utf-8")).get("id") or "")
    login = str((issue.get("user") or {}).get("login") or "unknown")
    title = _safe_title(str(issue.get("title") or ""), issue.get("number"))
    # Account age is friction, NOT trust: a younger account never earns a computed
    # tier. It goes to a maintainer with no record written.
    created = str((issue.get("user") or {}).get("created_at") or "")
    try:
        created_at = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
        age_days = (dt.datetime.now(dt.timezone.utc) - created_at).days
    except (ValueError, AttributeError):
        age_days = None
    if age_days is None or age_days < 30:
        note = ("account age is unknown" if age_days is None
                else f"account is {age_days} day(s) old")
        target = root / "requests" / f"needs-human-{issue.get('number') or 'unknown'}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(
            {"reason": f"needs-human: {note}; a maintainer reviews the submission",
             "by": f"github:{login}", "at": dt.date.today().isoformat()},
            indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"needs-human: {note}")
        return 0
    try:
        rec = record_from(parse_form(issue.get("body", "")), login, dt.date.today(), jid)
    except ValueError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 1
    if rec["kind"] == "retraction":
        return apply_retraction(root, rec)
    if rec["kind"] == "request":
        target = root / "requests" / f"{rec['id'][len('request:'):]}.json"
        if target.exists():
            print(f"already requested: {rec['id']}", file=sys.stderr)
            return 3
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(rec, indent=2, sort_keys=True,
                                     ensure_ascii=False) + "\n",
                          encoding="utf-8", newline="\n")
        print(rec["id"])
        return 0
    src = source_record(rec["provenance"]["sources"][0]["url"], title, login,
                        dt.date.today())
    target = root / "records" / rec["kind"] / schema.safe_filename(rec["id"])
    if target.exists():
        print(f"already recorded: {rec['id']}", file=sys.stderr)
        return 3
    existing, _ = schema.load(root)
    src_path = root / "records" / "source" / schema.safe_filename(src["id"])
    extra = [schema.Record(rec)] + ([] if src_path.exists() else [schema.Record(src)])
    findings = schema.validate([*existing, *extra], root=root)
    mine = [f for f in findings if f.record in (rec["id"], src["id"])]
    if mine:
        for f in mine:
            print(f, file=sys.stderr)
        for f in mine:
            if f.code == "CV050":
                host = f.message.split(" ")[0]
                print(f"add this line to config/official_domains.txt in the PR: {host}",
                      file=sys.stderr)
        print("rejected: this submission would break the repo", file=sys.stderr)
        return 1
    for item in (src, rec):
        p = root / "records" / item["kind"] / schema.safe_filename(item["id"])
        if p.exists():
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(item, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                     encoding="utf-8", newline="\n")
    sync_coverage(root)
    print(rec["id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
