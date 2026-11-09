# Contributing

Two ways in: a correction to something already here, or a new record. Both are
pull requests, and the gate is `python tools/check.py` returning 0.

## Corrections (never lost on regeneration)

A generated record's body is rebuilt by the generator. A correction is stored
beside it in `overrides`, so regeneration keeps both:

```json
"overrides": [
  {"path": "seats", "value": 16, "by": "maintainer:ann", "at": "2026-01-02",
   "reason": "charter article IV says sixteen", "replaces_hash": "sha256:..."}
]
```

`replaces_hash` is the hash of the value the correction replaced. If the
generator later produces a different value, the override goes stale: it is
REPORTED (`civic_repo_gen refresh` prints `STALE OVERRIDE`) and the validator
raises CV013. It is never silently dropped, and a stale override is never
auto-deleted — a person re-reads the source and decides.

Readers see `schema.effective(record)`: the generated value with overrides applied.

## New records

Open the matching issue form. `tools/intake.py` turns it into files at tier 0
(`submitted`) and refuses anything the validator rejects. The id is derived from
what you submit, not chosen by you:

- body → `body:<jurisdiction id>-<slug>`
- office → `office:body:<body id>/<slug>`
- official → `official:<office id>/<term start year>`
- meeting → `meeting:<body id>/<date>-<n>@r01`

A source record is created alongside every submission. If the host is not on
`config/official_domains.txt`, the intake is refused and names the line to add.

## What a maintainer does in the PR

1. `python tools/check.py` — must exit 0.
2. `python tools/verify.py` — is the cited page reachable?
3. For an official, read the page: does it name the person in that seat today?
4. Set `provenance.validated.method` to `human-review` and add a vouch.
   Two distinct non-submitter vouches, one with `"maintainer": true`, lift a
   tier-2 record to tier 3.

## Removing something

Never delete a record that was once published: append a line to `RETRACTIONS.md`
with the record id and a reason, and set the record's `status` if it has one. The
validator raises CV061 for a retraction without both.

## Never

No home address, personal phone or email, date of birth, or family detail about
any person. `PRIVACY.md` lists the forbidden keys and the validator enforces them.
No copied law text: reference global-law by path and pinned commit.
