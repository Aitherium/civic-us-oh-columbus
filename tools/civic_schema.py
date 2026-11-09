"""The civic repo schema: one record model, one validator, one trust function.

Slice 1 of the per-jurisdiction civic repos (``civic-<hierarchy>``). This module is
the SOURCE OF TRUTH: the generator imports it, the checker imports it, and every
generated repo carries a byte-identical copy at ``tools/civic_schema.py`` pinned by
``tools/TOOLS_VERSION``. A repo whose copy differs from this file is rejected by the
aggregator, because a pure copy would silently drift.

Nothing here fetches, writes a remote, or stores law text. ``load`` reads files,
``validate`` judges them against rule set ``civic-check/1`` and ``trust`` computes a
tier from evidence in the record. The exit contract is the AitherOS one: 0 clean,
1 violation, 2 could-not-judge -- never 0 on silence.

Field naming note: the envelope ``kind`` is the record kind (``meeting``,
``measure`` ...). The meeting's regular/special/... field is ``meeting_type`` and
the body's is ``body_type``, so an envelope field is never shadowed.

Python 3.10 compatible; stdlib only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "civic/1"
SCHEMA_MAJOR = "1"
RULE_SET = "civic-check/1"

KINDS = ("jurisdiction", "body", "office", "official", "meeting", "measure", "source")
LEVELS = ("world", "continent", "country", "subdivision", "county", "city", "town", "village")

#: Every rule id and what it catches. Kept in one place so a finding always names a
#: rule a reader can look up.
RULES = {
    "CV000": "unreadable JSON / not an object",
    "CV001": "required field / unknown kind / schema_version",
    "CV002": "duplicate id or file name != id",
    "CV003": "id grammar",
    "CV004": "enum value",
    "CV005": "parent/child mismatch",
    "CV006": "dangling reference",
    "CV007": "non-https URL",
    "CV008": "provenance required / bad or future date / invalid method",
    "CV009": "schema major != rule set",
    "CV010": "stored trust",
    "CV011": "free-text contact leak",
    "CV012": "generated record without generation",
    "CV013": "orphan or invalid override",
    "CV020": "forbidden PII key",
    "CV021": "non-office contact on an official",
    "CV022": "unredacted private individual",
    "CV030": "broken meeting revision chain",
    "CV031": "meeting status/date inconsistency",
    "CV040": "law_ref unresolved in the pinned commit",
    "CV041": "embedded law/document text",
    "CV050": "source host not on the official allowlist",
    "CV051": "tier-2 claim without archive snapshot",
    "CV060": "coverage counts != records on disk",
    "CV061": "retraction without a record id and reason",
}

ENUMS = {
    "level": set(LEVELS),
    "body_type": {"legislature", "council", "board", "commission", "school_board",
                  "committee", "authority", "special_district_board"},
    "selection": {"elected", "appointed", "mixed"},
    "body_status": {"active", "dissolved", "unknown"},
    "meeting_type": {"regular", "special", "emergency", "workshop", "hearing", "committee"},
    "meeting_status": {"scheduled", "held", "cancelled", "rescheduled", "adjourned"},
    "measure_type": {"ordinance", "resolution", "bill", "motion", "proclamation",
                     "budget", "zoning"},
    "measure_status": {"introduced", "passed", "vetoed", "enacted", "failed",
                       "withdrawn", "in_force", "repealed"},
    "media_type": {"html", "pdf", "json", "csv"},
    "privacy": {"public-record", "public-official"},
    "official_status": {"current", "former", "elect", "vacant"},
    "coverage_status": {"empty", "seed", "partial", "covered"},
}

REQUIRED = {
    "jurisdiction": ("schema_version", "id", "kind", "title", "jurisdiction", "level",
                     "name", "slug", "codes", "parent", "coverage", "provenance", "privacy"),
    "body": ("schema_version", "id", "kind", "title", "jurisdiction", "body_type", "name",
             "seats", "selection", "status", "provenance", "privacy"),
    "office": ("schema_version", "id", "kind", "title", "body", "jurisdiction", "title",
               "selection", "status", "provenance", "privacy"),
    "official": ("schema_version", "id", "kind", "title", "jurisdiction", "person", "term",
                 "status", "privacy", "provenance"),
    "meeting": ("schema_version", "id", "kind", "title", "body", "jurisdiction",
                "meeting_key", "revision", "date", "meeting_type", "status",
                "provenance", "privacy"),
    "measure": ("schema_version", "id", "kind", "title", "jurisdiction", "measure_type",
                "status", "provenance", "privacy"),
    "source": ("schema_version", "id", "kind", "title", "url", "retrieved_at",
               "http_status", "provenance", "privacy"),
}

#: Provenance validation methods. ``owner-asserted`` is deliberately absent: an
#: official rarely controls the clerk's domain, so it proves nothing here.
METHODS = {"submitted", "source-fetched", "archived-snapshot", "generated-official",
           "human-review"}

#: Forbidden keys anywhere in an official/person object. CV021 for an official,
#: CV020 elsewhere.
FORBIDDEN_KEYS = {
    "home_address", "residence", "personal_email", "personal_phone", "date_of_birth",
    "dob", "ssn", "family", "spouse", "children", "health", "medical",
    "immigration_status", "precise_location",
}

#: Keys allowed inside ``official.contact``.
OFFICE_CONTACT_KEYS = {"office_address", "office_phone", "office_email",
                       "official_website", "social"}

#: Free-text fields scanned for a contact leak.
FREE_TEXT_FIELDS = ("summary", "decisions_summary", "note", "bio", "description", "why")

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}")

_CC = r"[a-z]{2}"
_SUB = r"[a-z0-9]{1,3}"
_JUR_TAIL = (r"(?:county:\d{5}|place:\d{7}|cousub:\d{10}|school:\d{5,7}"
             r"|special:[a-z0-9-]+|[a-z_]+:[a-z0-9-]+)")
_JUR_RE = re.compile(rf"^jur:{_CC}(?:-{_SUB})?(?::{_JUR_TAIL})?$")
_ID_RES = {
    "jurisdiction": _JUR_RE,
    "body": re.compile(r"^body:jur:[a-z0-9:.\-]+-([a-z0-9][a-z0-9-]*)$"),
    "office": re.compile(r"^office:body:jur:.+/[a-z0-9][a-z0-9-]*$"),
    "official": re.compile(r"^official:.+/\d{4}(?:-\d{2}-\d{2})?$"),
    "meeting": re.compile(r"^meeting:body:jur:.+/\d{4}-\d{2}-\d{2}-\d+@r\d{2}$"),
    "measure": re.compile(r"^measure:jur:.+-\d{4}-[a-z0-9-]+$"),
    "source": re.compile(r"^source:[0-9a-f]{16}$"),
}

#: field -> enum name, per kind.
_ENUM_FIELDS = {
    "jurisdiction": (("level", "level"), ("privacy", "privacy")),
    "body": (("body_type", "body_type"), ("selection", "selection"),
             ("status", "body_status"), ("privacy", "privacy")),
    "office": (("selection", "selection"), ("status", "body_status"),
               ("privacy", "privacy")),
    "official": (("status", "official_status"), ("privacy", "public-official")),
    "meeting": (("meeting_type", "meeting_type"), ("status", "meeting_status"),
                ("privacy", "privacy")),
    "measure": (("measure_type", "measure_type"), ("status", "measure_status"),
                ("privacy", "privacy")),
    "source": (("media_type", "media_type"), ("privacy", "privacy")),
}

_URL_FIELDS = {"url", "official_website", "agenda_portal_url", "minutes_portal_url",
               "video_url", "virtual_url", "target", "geojson_url", "source_url",
               "well_known"}


@dataclass
class Finding:
    code: str
    record: str
    message: str
    unjudged: bool = False

    def __str__(self) -> str:
        return f"{self.code} {self.record}: {self.message}"


@dataclass
class Record:
    """One record file. ``raw`` is the JSON object; ``path`` is where it came from."""

    raw: dict
    path: Optional[Path] = None

    @property
    def id(self) -> str:
        return str(self.raw.get("id") or "")

    @property
    def kind(self) -> str:
        return str(self.raw.get("kind") or "")


# ── Canonical JSON and hashing ──────────────────────────────────────────────


def canonical(value: Any) -> str:
    """Byte-stable JSON: sorted keys, no spaces, UTF-8 characters kept."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(record: dict) -> str:
    """sha256 of the record body, excluding ``generation`` and ``overrides``.

    This is the stale-override detector and the meeting-revision integrity check:
    the generated body never changes when a person stores an override beside it.
    """
    body = {k: v for k, v in record.items() if k not in ("generation", "overrides")}
    return "sha256:" + hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def _get_path(obj: Any, dotted: str) -> Tuple[bool, Any]:
    cur = obj
    for part in str(dotted).split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return False, None
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return False, None
        else:
            return False, None
    return True, cur


def _set_path(obj: Any, dotted: str, value: Any) -> bool:
    parts = str(dotted).split(".")
    cur = obj
    for part in parts[:-1]:
        if isinstance(cur, dict):
            if part not in cur or not isinstance(cur[part], (dict, list)):
                return False
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return False
        else:
            return False
    leaf = parts[-1]
    if isinstance(cur, dict):
        cur[leaf] = value
        return True
    if isinstance(cur, list):
        try:
            cur[int(leaf)] = value
            return True
        except (ValueError, IndexError):
            return False
    return False


def effective(record: dict) -> dict:
    """The record a reader should see: generated values with overrides applied."""
    out = json.loads(json.dumps(record))
    for ov in record.get("overrides") or []:
        if isinstance(ov, dict) and "path" in ov:
            _set_path(out, ov["path"], ov.get("value"))
    return out


# ── Trust, computed from evidence ───────────────────────────────────────────

_METHOD_TIER = {
    "submitted": 0,
    "source-fetched": 1,
    "generated-official": 2,
    "archived-snapshot": 2,
    "human-review": 2,
}


def trust(record: dict) -> int:
    """0 submitted · 1 source-reachable · 2 source-proven · 3 corroborated.

    Never stored (CV010). A self-vouch and a double vouch are dropped. Two distinct
    non-submitter vouches, one a maintainer, lift a tier-2 record to 3. A person
    record is capped at 2 until a human maintainer reviewed it. ``contradicted_by``
    evidence forces tier 0.
    """
    prov = record.get("provenance") or {}
    method = str((prov.get("validated") or {}).get("method", ""))
    tier = _METHOD_TIER.get(method, 0)
    added_by = str(prov.get("added_by") or "")
    vouchers = set()
    maintainer = False
    for v in prov.get("vouches") or []:
        if not isinstance(v, dict):
            continue
        who = str(v.get("by") or "")
        if not who or who == added_by:
            continue
        if who in vouchers:
            continue
        vouchers.add(who)
        if v.get("maintainer") or who.startswith("maintainer:") or v.get("role") == "maintainer":
            maintainer = True
    if tier >= 2 and len(vouchers) >= 2 and maintainer:
        tier = 3
    if record.get("kind") == "official" and method != "human-review":
        tier = min(tier, 2)
    if (prov.get("evidence") or {}).get("contradicted_by"):
        tier = 0
    return tier


TIER_NAMES = {0: "submitted", 1: "source-reachable", 2: "source-proven", 3: "corroborated"}


# ── Loading ─────────────────────────────────────────────────────────────────


def _read_json(path: Path, findings: List[Finding]) -> Optional[dict]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        findings.append(Finding("CV000", path.name, f"unreadable JSON: {exc}"))
        return None
    if not isinstance(raw, dict):
        findings.append(Finding("CV000", path.name, "top level is not an object"))
        return None
    return raw


def load(root: Path) -> Tuple[List[Record], List[Finding]]:
    """Every record under ``root``: ``jurisdiction.json`` plus ``records/**/*.json``.

    Unreadable JSON is a finding, never an exception. ``_retired/`` is kept in git
    but is not a live record.
    """
    root = Path(root)
    records: List[Record] = []
    findings: List[Finding] = []
    jp = root / "jurisdiction.json"
    if jp.is_file():
        raw = _read_json(jp, findings)
        if raw is not None:
            records.append(Record(raw, jp))
    rdir = root / "records"
    if rdir.is_dir():
        for path in sorted(rdir.rglob("*.json")):
            if "_retired" in path.parts:
                continue
            raw = _read_json(path, findings)
            if raw is not None:
                records.append(Record(raw, path))
    return records, findings


# ── Validation helpers ──────────────────────────────────────────────────────


def _date_ok(value: Any) -> bool:
    try:
        dt.date.fromisoformat(str(value))
        return True
    except (TypeError, ValueError):
        return False


def _iter_dicts(obj: Any) -> Iterable[dict]:
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _iter_dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_dicts(v)


def _iter_strings(obj: Any, key: str = "") -> Iterable[Tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_strings(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v, key)
    elif isinstance(obj, str):
        yield key, obj


def _host(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/?#]+)", str(url), re.I)
    return (m.group(1).split("@")[-1].split(":")[0].lower()) if m else ""


def _load_allowlist(root: Optional[Path]) -> List[str]:
    # ``gov`` and ``mil`` are registration-controlled. A bare ``us`` is NOT: the
    # ``.us`` ccTLD is open registration, so ``evil.us`` would pass the suffix test
    # as an "official source". A ``.us`` host must be listed explicitly in
    # ``config/official_domains.txt``.
    entries = ["gov", "mil"]
    if root is None:
        return entries
    p = Path(root) / "config" / "official_domains.txt"
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        # A repo with no allowlist file falls back to the built-in suffixes; an
        # unreadable file is reported by the CV050 arm on the records that cite it.
        return entries
    for line in text.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


#: The .us LOCALITY namespace (RFC 1480): <org>.state.<st>.us, ci.<city>.<st>.us,
#: co.<county>.<st>.us, k12.<st>.us ... is delegated to governments, unlike open
#: second-level .us (evil.us). Measured 2026-11-09: dropping the bare "us" suffix
#: rejected www.sos.state.oh.us, assembly.state.ny.us and www.ci.la.ca.us.
_US_STATES = set("al ak az ar ca co ct de dc fl ga hi id il in ia ks ky la me md ma mi mn "
                 "ms mo mt ne nv nh nj nm ny nc nd oh ok or pa ri sc sd tn tx ut vt va wa "
                 "wv wi wy as gu mp pr vi".split())
_US_LOCALITY = re.compile(r"(?:^|\.)(?:state|ci|co|city|town|vil|twp|k12|cog)\."
                          r"(?:[a-z0-9-]+\.)?([a-z]{2})\.us$")


def us_locality(host: str) -> bool:
    m = _US_LOCALITY.search((host or "").lower().rstrip("."))
    return bool(m) and m.group(1) in _US_STATES


def _host_allowed(host: str, allow: List[str]) -> bool:
    return any(host == e or host.endswith("." + e) for e in allow) or us_locality(host)


def safe_filename(rid: str) -> str:
    """The file name a record with this id must have under ``records/``."""
    return re.sub(r"[^a-z0-9._-]+", "_", str(rid).lower()) + ".json"


def _filename_ok(rec: Record) -> bool:
    """A record's file name must be exactly ``safe_filename(id)``.

    No substring and no "last segment" arm: accepting either lets a crowd
    contribution rename a generated record's file (``mv .../council.json``) and
    then edit it, which the refresh cannot see. Exact equality is the only rule
    that keeps ``records/<kind>/<name>`` a function of the id.
    """
    if rec.path is None or rec.path.name == "jurisdiction.json":
        return True
    return rec.path.name == safe_filename(rec.id)


def _free_text_contact(rec: Record) -> List[Finding]:
    out: List[Finding] = []
    kind = rec.kind
    for key, text in _iter_strings(rec.raw):
        if key not in FREE_TEXT_FIELDS:
            continue
        hit = _EMAIL.search(text) or _PHONE.search(text)
        if not hit:
            continue
        code = "CV022" if kind in ("official", "meeting") else "CV011"
        out.append(Finding(code, rec.id, f"{key} carries a contact detail ({hit.group(0)[:40]})"))
    if kind == "official":
        contact = rec.raw.get("contact") or {}
        for key in contact:
            if key not in OFFICE_CONTACT_KEYS:
                out.append(Finding("CV021", rec.id, f"contact.{key} is not an office contact"))
    return out


def _forbidden_keys(rec: Record) -> List[Finding]:
    out: List[Finding] = []
    code = "CV021" if rec.kind == "official" else "CV020"
    for d in _iter_dicts(rec.raw):
        for key in d:
            if str(key) in FORBIDDEN_KEYS:
                out.append(Finding(code, rec.id, f"forbidden key {key}"))
    return out


#: Path roots an override may never rewrite. An override is a human correction to a
#: value, not a way to re-label the record, its privacy, or its own evidence: an
#: override that could set ``provenance.validated.method`` would self-award tier 2
#: ``human-review`` and then freeze the record against every later revision.
OVERRIDE_PROTECTED = ("id", "kind", "privacy", "status", "schema_version",
                      "provenance", "generation", "overrides")


def _override_payload(rec: Record, value: Any) -> List[Finding]:
    """Judge an override's payload by the same PII rules as the record body.

    The key of an override is literally ``value``, so the per-key free-text scan
    never sees it; without this an override could park a personal email or phone
    number (or a ``home_address`` key) in the published record.
    """
    out: List[Finding] = []
    code = "CV022" if rec.kind in ("official", "meeting") else "CV011"
    for _, text in _iter_strings(value):
        hit = _EMAIL.search(text) or _PHONE.search(text)
        if hit:
            out.append(Finding(code, rec.id,
                               f"override value carries a contact detail "
                               f"({hit.group(0)[:40]})"))
            break
    for d in _iter_dicts(value):
        for key in d:
            if str(key) in FORBIDDEN_KEYS:
                out.append(Finding("CV021" if rec.kind == "official" else "CV020",
                                   rec.id, f"override value carries forbidden key {key}"))
    return out


def _overrides(rec: Record) -> List[Finding]:
    out: List[Finding] = []
    body = {k: v for k, v in rec.raw.items() if k not in ("generation", "overrides")}
    for ov in rec.raw.get("overrides") or []:
        if not isinstance(ov, dict):
            out.append(Finding("CV013", rec.id, "override is not an object"))
            continue
        for need in ("path", "value", "by", "at", "reason"):
            if need not in ov:
                out.append(Finding("CV013", rec.id, f"override missing {need}"))
        by = str(ov.get("by") or "")
        if by and not by.startswith("maintainer:"):
            out.append(Finding("CV013", rec.id,
                               "an override must be authored by a maintainer:<name>"))
        out.extend(_override_payload(rec, ov.get("value")))
        path = ov.get("path")
        if not path:
            continue
        root = str(path).split(".")[0]
        if root in OVERRIDE_PROTECTED:
            out.append(Finding("CV013", rec.id,
                               f"override may not rewrite {root}"))
            continue
        exists, _ = _get_path(body, path)
        if not exists and not (ov.get("orphan_ok") and ov.get("reason")):
            out.append(Finding("CV013", rec.id, f"orphan override path {path}"))
        repl = ov.get("replaces_hash")
        if repl:
            exists, old = _get_path(body, path)
            if exists:
                want = "sha256:" + hashlib.sha256(canonical(old).encode("utf-8")).hexdigest()
                if repl != want:
                    # Stale is a warning upstream, not a hard violation.
                    out.append(Finding("CV013", rec.id,
                                       f"override {path} replaces_hash does not match "
                                       "the generated value"))
    return out


def _url_fields(rec: Record) -> List[Finding]:
    out: List[Finding] = []
    for d in _iter_dicts(rec.raw):
        for key, value in d.items():
            if str(key) not in _URL_FIELDS or not isinstance(value, str) or not value:
                continue
            if value.startswith("http://"):
                out.append(Finding("CV007", rec.id, f"{key} is http://, not https://"))
    return out


def _references(rec: Record) -> Iterable[str]:
    prov = rec.raw.get("provenance") or {}
    for src in prov.get("sources") or []:
        if isinstance(src, dict) and src.get("source_id"):
            yield str(src["source_id"])
    for field in ("body", "office", "parent_body"):
        val = rec.raw.get(field)
        if isinstance(val, str) and val:
            yield val
    for field in ("agenda", "packet", "minutes", "video"):
        block = rec.raw.get(field)
        if isinstance(block, dict) and block.get("source_id"):
            yield str(block["source_id"])
    for field in ("supersedes", "superseded_by"):
        val = rec.raw.get(field)
        if isinstance(val, str) and val:
            yield val
    for refs in (rec.raw.get("supersedes") or [], rec.raw.get("superseded_by") or []):
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, str) and r:
                    yield r
    for ref in rec.raw.get("law_refs") or []:
        if isinstance(ref, dict) and ref.get("measure"):
            yield str(ref["measure"])


def _meeting_chain(records: Iterable[Record], findings: List[Finding]) -> None:
    groups: dict = {}
    for rec in records:
        if rec.kind != "meeting":
            continue
        key = str(rec.raw.get("meeting_key") or "")
        groups.setdefault(key, []).append(rec)
    for key, recs in groups.items():
        recs.sort(key=lambda r: int(r.raw.get("revision") or 0))
        revisions = [int(r.raw.get("revision") or 0) for r in recs]
        if revisions != list(range(1, len(recs) + 1)):
            findings.append(Finding("CV030", key, f"revision chain is {revisions}"))
        for rec in recs:
            gen = rec.raw.get("generation") or {}
            want = gen.get("content_hash")
            if want and want != content_hash(rec.raw):
                findings.append(Finding("CV030", rec.id,
                                        "revision body was edited after publication "
                                        "(content_hash mismatch)"))
        for idx, rec in enumerate(recs):
            prev = recs[idx - 1] if idx else None
            nxt = recs[idx + 1] if idx + 1 < len(recs) else None
            want_sup = prev.id if prev else None
            if prev and rec.raw.get("supersedes") != want_sup:
                findings.append(Finding("CV030", rec.id,
                                        f"supersedes must be {want_sup}"))
            want_by = nxt.id if nxt else None
            if nxt and rec.raw.get("superseded_by") != want_by:
                findings.append(Finding("CV030", rec.id,
                                        f"superseded_by must be {want_by}"))
            if not nxt and rec.raw.get("superseded_by") is not None:
                findings.append(Finding("CV030", rec.id, "head revision has superseded_by"))


def _meeting_private(rec: Record) -> List[Finding]:
    out: List[Finding] = []
    for item in rec.raw.get("items") or []:
        if not isinstance(item, dict):
            continue
        for person in item.get("people") or []:
            if not isinstance(person, dict):
                continue
            role = str(person.get("role") or "")
            official = role.lower() in ("council member", "councilmember", "mayor",
                                        "staff", "presenter", "official")
            ref = str(person.get("ref") or "")
            if not official and (person.get("name") or not ref.startswith("redacted:")):
                out.append(Finding("CV022", rec.id,
                                   "a private individual must be stored by role and "
                                   "redacted ref only"))
    return out


def _meeting_status(rec: Record, today: dt.date) -> List[Finding]:
    out: List[Finding] = []
    date = str(rec.raw.get("date") or "")
    if not _date_ok(date):
        out.append(Finding("CV031", rec.id, "date is not YYYY-MM-DD"))
        return out
    if rec.raw.get("status") == "held" and dt.date.fromisoformat(date) > today:
        out.append(Finding("CV031", rec.id, "a future meeting cannot be held"))
    return out


def _law_refs(rec: Record, corpus_root: Optional[Path], require_law: bool,
              findings: List[Finding]) -> None:
    refs = rec.raw.get("law_refs") or []
    if not refs:
        return
    if corpus_root is None or not Path(corpus_root).is_dir():
        if require_law:
            findings.append(Finding("CV040", rec.id,
                                    "could not judge: no global-law checkout", unjudged=True))
        return
    root = Path(corpus_root)
    for ref in refs:
        if not isinstance(ref, dict):
            findings.append(Finding("CV040", rec.id, "law_ref is not an object"))
            continue
        path = str(ref.get("path") or "")
        if not path or not (root / path).is_file():
            findings.append(Finding("CV040", rec.id, f"law_ref path {path!r} not found"))


def _embedded_text(rec: Record) -> List[Finding]:
    out: List[Finding] = []
    if rec.kind == "measure":
        text = rec.raw.get("text")
        if isinstance(text, str) and len(text) > 400:
            out.append(Finding("CV041", rec.id,
                               f"a measure stores {len(text)} chars of text; store a pointer"))
        for doc in rec.raw.get("documents") or []:
            if isinstance(doc, dict) and isinstance(doc.get("text"), str) \
                    and len(doc["text"]) > 400:
                out.append(Finding("CV041", rec.id, "a document stores embedded text"))
    return out


def _source_rules(rec: Record, allow: List[str]) -> List[Finding]:
    out: List[Finding] = []
    url = str(rec.raw.get("url") or "")
    if url and not _host_allowed(_host(url), allow):
        out.append(Finding("CV050", rec.id, f"{_host(url)} is not on the official allowlist"))
    method = str(((rec.raw.get("provenance") or {}).get("validated") or {}).get("method", ""))
    archive = rec.raw.get("archive") or {}
    if method == "archived-snapshot" and not (archive.get("url") and archive.get("captured_at")):
        out.append(Finding("CV051", rec.id, "archived-snapshot without an archive URL"))
    return out


def _coverage_counts(records: Iterable[Record], root: Path,
                     findings: List[Finding]) -> None:
    cp = root / "coverage.json"
    try:
        cov = json.loads(cp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    counts = cov.get("counts") or {}
    seen = {k: 0 for k in KINDS}
    for rec in records:
        if rec.kind in seen:
            seen[rec.kind] += 1
    mapping = {"bodies": "body", "offices": "office", "officials": "official",
               "meetings": "meeting", "measures": "measure", "sources": "source",
               "jurisdiction": "jurisdiction"}
    for label, kind in mapping.items():
        if label in counts and int(counts[label]) != seen[kind]:
            findings.append(Finding("CV060", label,
                                    f"coverage says {counts[label]}, disk has {seen[kind]}"))


def _retractions(root: Path, records: Iterable[Record], findings: List[Finding]) -> None:
    recs = list(records)
    live = {rec.id for rec in recs}
    p = Path(root) / "RETRACTIONS.md"
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                findings.append(Finding("CV061", "RETRACTIONS.md", "unreadable retraction entry"))
                continue
            if not entry.get("id") or not entry.get("reason"):
                findings.append(Finding("CV061", "RETRACTIONS.md",
                                        "a retraction needs an id and a reason"))
            elif str(entry["id"]) not in live:
                # A retraction must resolve something, or the pull request it
                # produces changes no record at all.
                findings.append(Finding("CV061", "RETRACTIONS.md",
                                        f"retraction cites {entry['id']!r}, which is not "
                                        "a live record"))
    for rec in recs:
        if rec.raw.get("status") == "retracted" or rec.raw.get("retracted") is True:
            evidence = (rec.raw.get("provenance") or {}).get("evidence") or {}
            reason = evidence.get("reason") or (evidence.get("retraction") or {}).get("reason")
            if not reason:
                findings.append(Finding("CV061", rec.id, "retracted without a reason"))


def _parent_child(records: Iterable[Record], root: Path,
                  findings: List[Finding]) -> None:
    jur = next((r for r in records if r.kind == "jurisdiction"), None)
    if jur is not None:
        parent = str(jur.raw.get("parent") or "")
        own = jur.id
        if parent:
            if not _JUR_RE.match(parent):
                findings.append(Finding("CV005", own, f"parent {parent!r} is not a jur id"))
            elif not own.startswith(parent + ":"):
                findings.append(Finding("CV005", own,
                                        f"parent {parent!r} is not an ancestor of {own}"))
        idx = root / "index.json"
        try:
            index = json.loads(idx.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for child in index.get("children") or []:
            if not isinstance(child, dict):
                continue
            cid = str(child.get("id") or "")
            claimed = child.get("parent")
            if cid and cid == own:
                findings.append(Finding("CV005", cid, "a repo cannot be its own child"))
            if claimed and own and claimed != own:
                findings.append(Finding("CV005", cid,
                                        f"index says parent {claimed!r}, repo is {own!r}"))


# ── validate ────────────────────────────────────────────────────────────────


def validate(records: Iterable[Record], today: Optional[dt.date] = None,
             root: Optional[Path] = None, require_law: bool = False,
             corpus_root: Optional[Path] = None) -> List[Finding]:
    """Judge every record against rule set ``civic-check/1``. Empty list = clean."""
    today = today or dt.date.today()
    recs = list(records)
    out: List[Finding] = []
    ids: dict = {}
    allow = _load_allowlist(root)
    id_index: dict = {}

    for rec in recs:
        rid = rec.id or (rec.path.name if rec.path else "?")
        if rid in ids:
            out.append(Finding("CV002", rid, f"duplicate id (also {ids[rid]})"))
        ids[rid] = rec.path.name if rec.path else rid
        if not _filename_ok(rec):
            out.append(Finding("CV002", rid, f"file name {rec.path.name} != id"))
        if rid not in id_index:
            id_index[rid] = rec

    for rec in recs:
        rid = rec.id or (rec.path.name if rec.path else "?")
        raw = rec.raw
        kind = rec.kind
        if kind not in KINDS:
            out.append(Finding("CV001", rid, f"unknown kind {kind!r}"))
            continue
        if raw.get("schema_version") != SCHEMA_VERSION:
            major = str(raw.get("schema_version") or "").split("/")[-1]
            if major != SCHEMA_MAJOR:
                out.append(Finding("CV009", rid,
                                   f"schema {raw.get('schema_version')!r} != {SCHEMA_VERSION}"))
            else:
                out.append(Finding("CV001", rid, "schema_version is required"))
        for need in REQUIRED[kind]:
            if need not in raw:
                out.append(Finding("CV001", rid, f"missing required field {need}"))
        regex = _ID_RES.get(kind)
        if regex is not None and not regex.match(rid):
            out.append(Finding("CV003", rid, f"id does not match the {kind} grammar"))
        for field, enum_name in _ENUM_FIELDS.get(kind, ()):
            if field in raw:
                allowed = ENUMS.get(enum_name)
                if enum_name == "public-official":
                    allowed = {"public-official"}
                if allowed and raw[field] not in allowed:
                    out.append(Finding("CV004", rid,
                                       f"{field}={raw[field]!r} not in {sorted(allowed)}"))
        if "trust" in raw:
            out.append(Finding("CV010", rid, "trust is computed, never stored"))
        prov = raw.get("provenance")
        if not isinstance(prov, dict) or not prov.get("added_by") or not prov.get("sources"):
            out.append(Finding("CV008", rid, "provenance.added_by and sources are required"))
        else:
            if not _date_ok(prov.get("added_at", "")):
                out.append(Finding("CV008", rid, "provenance.added_at is not YYYY-MM-DD"))
            val = prov.get("validated") or {}
            method = str(val.get("method") or "")
            if not val.get("at") or not val.get("by") or not method:
                out.append(Finding("CV008", rid, "provenance.validated needs at, by, method"))
            elif method not in METHODS:
                out.append(Finding("CV008", rid, f"validation method {method!r} is invalid"))
            elif not _date_ok(val["at"]):
                out.append(Finding("CV008", rid, "validated.at is not YYYY-MM-DD"))
            elif dt.date.fromisoformat(str(val["at"])) > today:
                out.append(Finding("CV008", rid, "validated.at is in the future"))
        if str(prov.get("added_by", "") if isinstance(prov, dict) else "").startswith("gen:"):
            if not isinstance(raw.get("generation"), dict):
                out.append(Finding("CV012", rid, "generated record without generation"))
        out.extend(_overrides(rec))
        out.extend(_forbidden_keys(rec))
        out.extend(_free_text_contact(rec))
        out.extend(_url_fields(rec))
        out.extend(_embedded_text(rec))
        if kind == "source":
            out.extend(_source_rules(rec, allow))
        if kind == "meeting":
            out.extend(_meeting_private(rec))
            out.extend(_meeting_status(rec, today))
        if kind == "measure":
            _law_refs(rec, corpus_root, require_law, out)

    for rec in recs:
        for ref in _references(rec):
            if ref and ref not in id_index:
                out.append(Finding("CV006", rec.id, f"dangling reference {ref!r}"))

    _meeting_chain(recs, out)
    _parent_child(recs, root or Path("."), out)
    if root is not None:
        _coverage_counts(recs, Path(root), out)
        _retractions(Path(root), recs, out)
    return out


# ── check_root: the shared 0/1/2 contract ───────────────────────────────────


def check_root(root: Path, require_law: bool = False,
               corpus_root: Optional[Path] = None,
               today: Optional[dt.date] = None) -> Tuple[int, List[Finding], int]:
    """(exit code, findings, record count). 0 clean, 1 violation, 2 could-not-judge."""
    root = Path(root)
    if not root.is_dir():
        return 2, [Finding("CV000", str(root), "not a directory", unjudged=True)], 0
    records, findings = load(root)
    if not records:
        findings.append(Finding("CV000", str(root), "no records found", unjudged=True))
        return 2, findings, 0
    kinds = {r.kind for r in records}
    if "jurisdiction" not in kinds and "body" not in kinds:
        findings.append(Finding("CV000", str(root),
                                "zero jurisdiction and body records", unjudged=True))
        return 2, findings, len(records)
    findings += validate(records, today=today, root=root, require_law=require_law,
                         corpus_root=corpus_root)
    unjudged = sum(1 for f in findings if f.unjudged)
    hard = [f for f in findings if not f.unjudged]
    if hard:
        return 1, findings, len(records)
    if unjudged:
        return 2, findings, len(records)
    return 0, findings, len(records)


# ── Self-test (rules 1-9, 12-16) ────────────────────────────────────────────


def _mk(kind: str, rid: str, **extra: Any) -> dict:
    base = {
        "schema_version": SCHEMA_VERSION,
        "id": rid,
        "kind": kind,
        "title": "T",
        "jurisdiction": "jur:us-ca:place:0644000",
        "privacy": "public-record",
        "provenance": {"added_by": "gen:civic_repo_gen@0.1.0", "added_at": "2026-01-01",
                       "sources": [{"source_id": "source:0000000000000000",
                                    "url": "https://example.gov/x",
                                    "retrieved_at": "2026-01-01",
                                    "license": "public-domain"}],
                       "validated": {"at": "2026-01-01", "by": "gen",
                                     "method": "generated-official"}},
        "generation": {"generator": "gen", "at": "2026-01-01T00:00:00Z",
                       "source_snapshot": {}, "content_hash": ""},
    }
    base.update(extra)
    base["generation"]["content_hash"] = content_hash(base)
    return base


def _codes(findings: Iterable[Finding]) -> set:
    return {f.code for f in findings}


def self_test() -> Tuple[bool, List[str]]:
    """Prove each pure rule can still fire. Returns (ok, printed lines)."""
    lines: List[str] = []
    ok = True

    def arm(label: str, got: set, want: set) -> None:
        nonlocal ok
        passed = got == want
        ok = ok and passed
        verdict = "PASS" if passed else "FAIL"
        lines.append(f"{verdict} {label}: want {sorted(want)} got {sorted(got)}")

    def run(recs, **kw):
        return validate([Record(r) for r in recs], today=dt.date(2026, 11, 9),
                        root=None, **kw)

    good = _mk("body", "body:jur:us-ca:place:0644000-council",
               body_type="council", name="Council", seats=15, selection="elected",
               status="active")
    # 1 id grammar
    arm("id grammar", {f.code for f in run([_mk("body", "jur:us-ca-0644000",
                                                 body_type="council", name="C", seats=1,
                                                 selection="elected", status="active")])
                       if f.code == "CV003"}, {"CV003"})
    # 2 duplicate id / filename mismatch
    arm("duplicate id", {f.code for f in run([good, good]) if f.code == "CV002"}, {"CV002"})
    arm("filename mismatch", _codes(validate(
        [Record(good, Path("wrong.json"))], today=dt.date(2026, 11, 9))) & {"CV002"}, {"CV002"})
    # 3 provenance missing / future date
    bad_prov = json.loads(json.dumps(good))
    bad_prov["provenance"] = {}
    arm("missing provenance", _codes(run([bad_prov])) & {"CV008"}, {"CV008"})
    fut = json.loads(json.dumps(good))
    fut["provenance"]["validated"]["at"] = "2999-01-01"
    arm("future validation", _codes(run([fut])) & {"CV008"}, {"CV008"})
    # 4 PII
    off = _mk("official", "official:ocd-person/x/2024-01-01",
              person={"full_name": "A"}, term={"start": "2024-01-01", "status": "current"},
              status="current", privacy="public-official", contact={"home_address": "1 St"})
    arm("official home_address", _codes(run([off])) & {"CV021"}, {"CV021"})
    leak = json.loads(json.dumps(good))
    leak["summary"] = "email me at a@b.com"
    arm("free-text contact", _codes(run([leak])) & {"CV011"}, {"CV011"})
    # 5 parent chain
    jur = _mk("jurisdiction", "jur:us-ca:place:0644000", level="city", name="LA",
              slug="los-angeles", codes={}, parent="jur:us-ny", coverage={})
    arm("broken parent", _codes(run([jur])) & {"CV005"}, {"CV005"})
    # 6 dangling source_id
    dangling = json.loads(json.dumps(good))
    dangling["provenance"]["sources"][0]["source_id"] = "source:ffffffffffffffff"
    arm("dangling source", _codes(run([dangling])) & {"CV006"}, {"CV006"})
    # 7 stored trust
    stored = json.loads(json.dumps(good))
    stored["trust"] = 3
    arm("stored trust", _codes(run([stored])) & {"CV010"}, {"CV010"})
    # 8 meeting r01 edited after r02 (hash mismatch)
    m1 = _mk("meeting", "meeting:body:jur:us-ca:place:0644000-council/2026-11-01-1@r01",
             body="body:jur:us-ca:place:0644000-council", meeting_key="council/2026-11-01-1",
             revision=1, date="2026-11-01", meeting_type="regular", status="held",
             superseded_by="meeting:body:jur:us-ca:place:0644000-council/2026-11-01-1@r02")
    m2 = _mk("meeting", "meeting:body:jur:us-ca:place:0644000-council/2026-11-01-1@r02",
             body="body:jur:us-ca:place:0644000-council", meeting_key="council/2026-11-01-1",
             revision=2, date="2026-11-01", meeting_type="regular", status="held",
             supersedes=m1["id"])
    m1["title"] = "edited after r02"
    arm("meeting revision edited", _codes(run([m1, m2])) & {"CV030"}, {"CV030"})
    # 9 trust
    tiers = []
    for method in ("submitted", "source-fetched", "generated-official", "archived-snapshot"):
        r = _mk("body", "body:jur:us-ca:place:0644000-council", body_type="council",
                name="C", seats=1, selection="elected", status="active")
        r["provenance"]["validated"]["method"] = method
        tiers.append(trust(r))
    body3 = _mk("body", "body:jur:us-ca:place:0644000-council", body_type="council",
                name="C", seats=1, selection="elected", status="active")
    body3["provenance"]["vouches"] = [{"by": "maintainer:ann", "at": "2026-01-02",
                                       "maintainer": True},
                                      {"by": "github:bob", "at": "2026-01-02"}]
    vouch_tier = trust(body3)
    self_vouch = json.loads(json.dumps(body3))
    self_vouch["provenance"]["vouches"] = [{"by": self_vouch["provenance"]["added_by"],
                                            "at": "2026-01-02", "maintainer": True}]
    arm("trust tiers", set(tiers + [vouch_tier, trust(self_vouch)]),
        {0, 1, 2, 2, 3, 2})
    # 12 empty root exits 2 / zero meetings valid
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        code, _, _ = check_root(Path(d))
    no_meet = _mk("jurisdiction", "jur:us-ca:place:0644000", level="city", name="LA",
                  slug="los-angeles", codes={}, parent="jur:us-ca", coverage={})
    src = _mk("source", "source:0000000000000000", url="https://www.census.gov/x",
              retrieved_at="2026-01-01", http_status=200)
    code2 = check_root_docs([no_meet, src])
    arm("empty root / zero meetings", {code, code2}, {2, 0})
    # 13 unknown kind / schema major
    unk = json.loads(json.dumps(good))
    unk["kind"] = "alien"
    arm("unknown kind", _codes(run([unk])) & {"CV001"}, {"CV001"})
    major = json.loads(json.dumps(good))
    major["schema_version"] = "civic/2"
    arm("schema major", _codes(run([major])) & {"CV009"}, {"CV009"})
    # 14 law_ref unresolved / unjudged without a checkout
    meas = _mk("measure", "measure:jur:us-ca:place:0644000-2026-1", measure_type="ordinance",
               status="enacted",
               law_refs=[{"corpus": "united-states/california/statutes",
                          "path": "united-states/california/statutes/nope.md",
                          "commit": "x", "relation": "implements"}])
    import tempfile as _tf
    with _tf.TemporaryDirectory() as d:
        corpus = Path(d)
        (corpus / "united-states/california/statutes").mkdir(parents=True)
        miss = _codes(run([meas], corpus_root=corpus, require_law=True)) & {"CV040"}
        unj = [f for f in run([meas], require_law=True) if f.unjudged]
    arm("law_ref unresolved", miss | ({"UNJUDGED"} if unj else set()),
        {"CV040", "UNJUDGED"})
    # 15 coverage drift
    with _tf.TemporaryDirectory() as d:
        root = Path(d)
        (root / "coverage.json").write_text(json.dumps({"counts": {"bodies": 2}}),
                                            encoding="utf-8")
        drift = _codes(validate([Record(good)], today=dt.date(2026, 11, 9), root=root))
    arm("coverage drift", drift & {"CV060"}, {"CV060"})
    # 16 retraction without id
    with _tf.TemporaryDirectory() as d:
        root = Path(d)
        (root / "RETRACTIONS.md").write_text('{"reason": "x"}\n', encoding="utf-8")
        retr = _codes(validate([Record(good)], today=dt.date(2026, 11, 9), root=root))
    arm("retraction without id", retr & {"CV061"}, {"CV061"})
    # 17 a retraction that resolves nothing
    with _tf.TemporaryDirectory() as d:
        root = Path(d)
        (root / "RETRACTIONS.md").write_text(
            '{"id": "body:jur:us-ca:place:0644000-gone", "reason": "x"}\n',
            encoding="utf-8")
        gone = _codes(validate([Record(good)], today=dt.date(2026, 11, 9), root=root))
    arm("retraction of a missing record", gone & {"CV061"}, {"CV061"})
    # 18 a bare .us domain is not an official source
    us_src = _mk("source", "source:1111111111111111", url="https://evil.us/x",
                 retrieved_at="2026-01-01", http_status=0)
    arm("bare .us is not allowlisted", _codes(run([us_src])) & {"CV050"}, {"CV050"})
    # 19 an override cannot smuggle PII or rewrite its own evidence
    smug = json.loads(json.dumps(good))
    smug["overrides"] = [{"path": "title", "value": "call 213-555-1212, jane@home.example",
                          "by": "maintainer:ann", "at": "2026-01-02", "reason": "x"}]
    arm("override carries a contact detail", _codes(run([smug])) & {"CV011"}, {"CV011"})
    award = json.loads(json.dumps(good))
    award["overrides"] = [{"path": "provenance.validated.method", "value": "human-review",
                           "by": "github:stranger", "at": "2026-01-02", "reason": "x"}]
    arm("override may not rewrite provenance", _codes(run([award])) & {"CV013"}, {"CV013"})
    # 20 a rename cannot capture a generated record
    renamed = _codes(validate([Record(good, Path("council.json"))],
                              today=dt.date(2026, 11, 9))) & {"CV002"}
    arm("filename must equal the id", renamed, {"CV002"})

    return ok, lines


def check_root_docs(records: List[dict]) -> int:
    """Helper for the self-test: validate a record list as if it were a root."""
    findings = validate([Record(r) for r in records], today=dt.date(2026, 11, 9))
    hard = [f for f in findings if not f.unjudged]
    return 1 if hard else 0
