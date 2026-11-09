# Sources for City of Columbus

Every URL this repo cites, and what it is. The validator refuses a host that is
not on `config/official_domains.txt` (CV050), so this list is the audit trail for
where any fact came from.

| source id | url | what it is | license |
|---|---|---|---|
| | | | |

## The generated records come from

- **Census of Governments, 2022** — the local-government listing (units, seats).
  US Government work, public domain.
- **TIGERweb** — boundary geometry, referenced by URL and never copied. Public domain.
- **unitedstates/congress-legislators** (CC0-1.0) — federal officials.
- **openstates/people** (CC0-1.0) — state and large-city officials.
- **global-law** — referenced by path and pinned commit only. Its text is never
  copied into this repo, so this repo never becomes a stale second copy of it.

## How a source is trusted

`provenance.validated.method` is one of `submitted`, `source-fetched`,
`archived-snapshot`, `generated-official`, `human-review`. Trust tiers are computed:

- 0 `submitted` — someone said so.
- 1 `source-reachable` — the URL answered.
- 2 `source-proven` — a generator or an archived snapshot backs it (a person record
  is capped here until a maintainer reviews it).
- 3 `corroborated` — two distinct non-submitter vouches, one a maintainer.

`owner-asserted` is deliberately absent: an official rarely controls the clerk's
domain, so their word proves nothing that the clerk's page does not already prove.
