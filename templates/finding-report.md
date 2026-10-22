# Reverse-engineering finding report

> Copy this, fill it in, delete the guidance lines. One report per
> investigation; one row in the findings table per question.

## Scope (from the authorisation gate)

- **Target(s):** <one artifact, or each version compared, with name and path>
- **Sample identity:** SHA-256 `<digest>`, size `<bytes>` (one line per sample; original and copy digests match: yes/no)
- **Authority:** basis <owned / licensed / sanctioned>, approved by <name>, reference <ticket, contract or email>, date <date>, expiry <date or none>
- **Question(s):** <what the analysis had to answer>
- **Mode:** static | live
- **Live steps (if any):** <session envelope verbatim, approver, time, environment checks passed, teardown and export confirmed>
- **Analyst / host / skill version / date:** <who, where, version, when>
- **Handling:** <how this report may be shared, e.g. internal only>

## Summary

<Two to four sentences, plain language: what was asked, what was found, how confident.>

## Findings

| # | Question | Observation (tool and version · command · location) | Inference | Evidence type | Confidence | Status | Unknowns / boundary |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |
| 2 | | | | | | | |

> Observation = what the tool showed, reproducible from the digest + command.
> Inference = what you conclude, marked as such. Keep them in separate columns.
> Evidence type = static / live / metadata. Large per-item results (a permission
> map, an SBOM) go in an appendix table, not this one.
> Confidence: high = two independent signals; medium = one signal (an import, or a
> banner or version string inside the file); low = a file name or path alone.
> Status = answered / partial / unresolved.

## Tools used

| Tool | Version | Used for |
|---|---|---|
| | | |

## Open questions

<Anything the evidence did not settle, with the boundary of each negative claim.>

## Stop events and scope changes

<Every time the work stopped to ask (section 6A) and every scope change approved, with the approval reference.>

## Secrets and personal data

<Counts only: type, length and location of each kind found; a hash only for a
high-entropy value. No prefixes, no raw values.>

## Appendix tables

<Large per-item results (permission-to-code map, SBOM, host list). One row per item.>

## Notes

<Chain of custody for nested payloads (what was carved from where), the ledger
hash at close, where the evidence is retained, and anything a future pass should
know. A vulnerability found in third-party code is reported to the operator;
disclosing it is the organisation's decision, not the analyst's. No raw
credentials or personal data.>
