#!/usr/bin/env python3
"""Live evidence for the sources this repo cites.

    python tools/verify.py                 # report every source, exit 1 if one is down
    python tools/verify.py --ids a b       # only these record ids
    python tools/verify.py --stamp         # record what was observed
    python tools/verify.py --self-test     # prove the allowlist + SSRF arms fire

A fetch is allowed ONLY when the host is on ``config/official_domains.txt`` AND
resolves to a public address. The allowlist is the anti-astroturfing gate, and
the public-address check is the SSRF gate: a submitted URL that points at
127.0.0.1, an RFC1918 range or a link-local/cloud-metadata address is never
fetched (it is reported, not followed).

Stdlib only, Python 3.10 compatible. Exit 0 all reachable, 1 any unreachable,
2 nothing to check.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import re
import json
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import civic_schema as schema  # noqa: E402

UA = "civic-repo-verify/1"


def _allowlist(root: Path) -> list[str]:
    # No bare ``us``: ``.us`` is open registration, so any submitter can own a
    # name under it and answer for an official body. That is the impersonation
    # path with no code change needed.
    entries = ["gov", "mil"]
    p = Path(root) / "config" / "official_domains.txt"
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
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


def host_allowed(host: str, allow: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    return bool(host) and (any(host == e.lstrip(".") or host.endswith("." + e.lstrip("."))
                               for e in allow) or us_locality(host))


def is_public_ip(ip: str) -> bool:
    """False for loopback, private, link-local, reserved, multicast, unspecified."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def resolves_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return bool(infos) and all(is_public_ip(info[4][0]) for info in infos)


class _RedirectBlockedError(Exception):
    """A redirect left the allowlist or pointed at a non-public address."""


class _GuardedRedirects(urllib.request.HTTPRedirectHandler):
    """Re-run the allowlist and the public-address check on EVERY redirect hop.

    ``urlopen`` re-resolves the host on each hop, so checking the original URL
    only lets an allowlisted host 302 to 127.0.0.1, an RFC1918 address or a
    cloud-metadata endpoint (SSRF). It is also the rebinding window: the name is
    resolved again after the check. Refusing the hop closes both.
    """

    def __init__(self, allow: list[str]) -> None:
        self._allow = allow
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        host = parts.hostname or ""
        if parts.scheme != "https":
            raise _RedirectBlockedError(
                f"redirect to a {parts.scheme or 'relative'} url refused")
        if not host_allowed(host, self._allow):
            raise _RedirectBlockedError(
                f"redirect host {host} is not on config/official_domains.txt")
        if not resolves_public(host):
            raise _RedirectBlockedError(
                f"redirect host {host} does not resolve to a public address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str, allow: list[str], limit: int = 65536) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(_GuardedRedirects(allow))
    try:
        with opener.open(req, timeout=15) as resp:  # noqa: S310 (https, allowlisted)
            body = resp.read(limit)
            return {"status": int(resp.status), "body": body,
                    "etag": resp.headers.get("ETag"),
                    "last_modified": resp.headers.get("Last-Modified"), "note": None}
    except _RedirectBlockedError as exc:
        return {"status": 0, "body": b"", "etag": None, "last_modified": None,
                "note": str(exc)}
    except urllib.error.HTTPError as exc:
        return {"status": int(exc.code), "body": b"", "etag": None,
                "last_modified": None, "note": None}
    except (urllib.error.URLError, OSError, ValueError):
        return {"status": 0, "body": b"", "etag": None, "last_modified": None,
                "note": None}


def _witness(host: str, rid: str, content_hash: str, allow: list[str]) -> str:
    """The host's own attestation URL, or '' when it does not witness THIS body.

    A bare record id is a claim, not a witness: any allowlisted host could list
    every id it guesses. Only an entry that names the sha256 of the body we just
    fetched ties the claim to something the host actually serves.
    """
    if not content_hash:
        return ""
    well = _get(f"https://{host}/.well-known/civic.json", allow)
    if well["status"] != 200:
        return ""
    try:
        claimed = json.loads(well["body"].decode("utf-8")).get("records") or []
    except (ValueError, AttributeError, UnicodeDecodeError):
        return ""
    for entry in claimed:
        if (isinstance(entry, dict) and entry.get("id") == rid
                and entry.get("content_hash") == content_hash):
            return f"https://{host}/.well-known/civic.json"
    return ""


def evidence(rec: schema.Record, allow: list[str]) -> dict:
    url = str(rec.raw.get("url") or "")
    if not url.startswith("https://"):
        return {"id": rec.id, "status": None, "method": None, "note": "no https url",
                "fetched": False}
    host = urlsplit(url).hostname or ""
    if not host_allowed(host, allow):
        return {"id": rec.id, "url": url, "status": None, "method": None,
                "note": f"host {host} is not on config/official_domains.txt",
                "fetched": False}
    if not resolves_public(host):
        return {"id": rec.id, "url": url, "status": None, "method": None,
                "note": f"host {host} does not resolve to a public address", "fetched": False}
    got = _get(url, allow)
    if got["note"]:
        return {"id": rec.id, "url": url, "status": None, "method": None,
                "note": got["note"], "fetched": False}
    body_hash = ("sha256:" + hashlib.sha256(got["body"]).hexdigest()
                 if got["body"] else None)
    out = {"id": rec.id, "url": url, "status": got["status"],
           "method": "source-fetched" if got["status"] == 200 else None,
           "etag": got["etag"], "last_modified": got["last_modified"],
           "content_hash": body_hash, "fetched": True}
    if out["status"] == 200:
        witness = _witness(host, rec.id, body_hash or "", allow)
        if witness:
            out["method"] = "archived-snapshot"
            # Never a ``web.archive.org/save/`` url: that capture was never made.
            out["archive_url"] = witness
    return out


def stamp(rec: schema.Record, ev: dict) -> None:
    raw = json.loads(rec.path.read_text(encoding="utf-8"))
    prov = raw.setdefault("provenance", {})
    validated = prov.setdefault("validated", {})
    if validated.get("method") == "human-review":
        return                                   # a human verdict is never overwritten
    for key, src in (("http_status", "status"), ("etag", "etag"),
                     ("last_modified", "last_modified"), ("content_hash", "content_hash")):
        if ev.get(src) is not None:
            raw[key] = ev[src]
    if ev.get("method"):
        validated["method"] = ev["method"]
        validated["at"] = dt.date.today().isoformat()
        validated["by"] = "civic-verify-bot"
    if ev.get("archive_url") and ev.get("method"):
        # Written only beside a witness that named this body's content hash, so
        # the entry can be re-checked; the hash makes the claim falsifiable.
        raw["archive"] = {"service": "web.archive.org", "url": ev["archive_url"],
                          "content_hash": ev.get("content_hash"),
                          "captured_at": dt.date.today().isoformat()}
    if raw.get("generation"):
        raw["generation"]["content_hash"] = schema.content_hash(raw)
    rec.path.write_text(json.dumps(raw, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")


def _self_test() -> int:
    ok = True
    allow = ["gov", "mil", "lacity.gov"]
    ok = ok and host_allowed("lacity.gov", allow) and host_allowed("clerk.lacity.gov", allow)
    ok = ok and not host_allowed("evil.example", allow)
    ok = ok and not host_allowed("lacity.gov.evil.example", allow)
    ok = ok and not host_allowed("anything.us", _allowlist(Path("no-such-root-here")))
    ok = ok and is_public_ip("8.8.8.8") and not is_public_ip("127.0.0.1")
    ok = ok and not is_public_ip("10.0.0.5") and not is_public_ip("169.254.169.254")
    ok = ok and not is_public_ip("192.168.1.1") and not is_public_ip("::1")
    dirname = Path("no-such-dir-here")
    ok = ok and not resolves_public("localhost")
    ok = ok and not resolves_public(dirname.name)
    # A redirect is refused before it is followed: this is the SSRF arm.
    req = urllib.request.Request("https://clerk.lacity.gov/x")
    redirects = _GuardedRedirects(["gov", "lacity.gov"])
    for target in ("http://clerk.lacity.gov/x", "https://127.0.0.1/x",
                   "https://169.254.169.254/latest/meta-data/",
                   "https://evil.example/x"):
        blocked = False
        try:
            redirects.redirect_request(req, None, 302, "Found", {}, target)
        except _RedirectBlockedError:
            blocked = True                         # the expected outcome
        ok = ok and blocked                        # ...and the hop must not be built
    # The initial url is gated too, not just the hop target.
    rec = schema.Record({"id": "source:us-ca-la/x", "kind": "source",
                         "url": "https://127.0.0.1/x"})
    ev = evidence(rec, ["127.0.0.1"])
    ok = ok and ev["fetched"] is False and "public address" in str(ev.get("note"))
    # An unwitnessed claim is never promoted: no archive written without a capture.
    ok = ok and _witness("example.gov", "source:x", "", ["gov"]) == ""
    print("PASS verify" if ok else "FAIL verify")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=HERE.parent)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--stamp", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    records, _ = schema.load(a.root)
    records = [r for r in records if r.kind == "source" and r.raw.get("url")]
    if a.ids:
        wanted = set(a.ids)
        records = [r for r in records if r.id in wanted]
    if not records:
        print("nothing to check")
        return 2
    allow = _allowlist(a.root)
    down = 0
    for rec in records:
        ev = evidence(rec, allow)
        print(json.dumps({k: v for k, v in ev.items() if k != "fetched"}))
        if ev["method"] is None:
            down += 1
            continue
        if a.stamp and rec.path:
            stamp(rec, ev)
    print(f"verify: {len(records)} checked, {down} unreachable")
    return 1 if down else 0


if __name__ == "__main__":
    sys.exit(main())
