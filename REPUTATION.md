# Reputation and review

Trust is computed, never stored (CV010). `tools/civic_schema.py` holds the one
function:

| tier | name | how it is reached |
|---|---|---|
| 0 | submitted | `validated.method` is `submitted` |
| 1 | source-reachable | the source URL answered |
| 2 | source-proven | `generated-official`, `archived-snapshot` or `human-review` |
| 3 | corroborated | tier 2 plus two distinct non-submitter vouches, one a maintainer |

A self-vouch and a duplicate vouch are dropped. A person record is capped at tier
2 until a maintainer reviews it. Evidence with `contradicted_by` forces tier 0.

## Vouches

```json
"vouches": [{"by": "maintainer:ann", "at": "2026-01-02",
             "role": "maintainer", "note": "read the clerk's page"}]
```

`by` identifies the person, `maintainer: true` (or a `maintainer:` prefix, or
`role: maintainer`) marks a maintainer. Vouching is review, not endorsement: say
what you checked.

## Why a correction keeps its own history

An override carries `by`, `at` and `reason` for the same purpose: a reader can see
who changed a generated value and why, without reading the git log. The
generator's `content_hash` proves the body is unchanged; `replaces_hash` proves the
correction still targets the value it was written against.
