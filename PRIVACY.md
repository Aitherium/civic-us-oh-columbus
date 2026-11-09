# Privacy

This repo describes public offices and the people who hold them. That is a public
record and it is published. A person's private life is not.

## Forbidden keys (CV020, CV021 for an official)

`home_address`, `residence`, `personal_email`, `personal_phone`, `date_of_birth`,
`dob`, `ssn`, `family`, `spouse`, `children`, `health`, `medical`,
`immigration_status`, `precise_location`.

The validator scans every object in every record. There is no allowlist.

## Contact details

Only office contact is kept, inside `official.contact`, and only these keys:
`office_address`, `office_phone`, `office_email`, `official_website`, `social`.
Any other key in `contact` is a finding (CV021).

Free-text fields (`summary`, `decisions_summary`, `note`, `bio`, `description`,
`why`) are scanned for an email address or a phone number; a hit in an official or
meeting record is CV022, anywhere else CV011. If a correction needs a contact
detail, it goes in the structured `contact` block, not in prose.

## Redaction

A private individual named in a meeting document is replaced at ingestion, not at
publish time. `redaction` is `{redacted, method, at, by}`. A record that names a
private person without a redaction block is CV022.

## Requests

If you are named here and want something removed, open an issue. A correction is a
pull request; a removal that has already been published is a retraction
(`RETRACTIONS.md`), because the history is part of the record.
