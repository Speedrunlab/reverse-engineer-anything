# Reverse-engineering finding report

> Copy this, fill it in, delete the guidance lines. One report per
> investigation; one row in the findings table per question.

## Scope (from the authorisation gate)

- **Target(s):** <one artifact, or each version compared, with name and path>
- **Sample identity:** SHA-256 `<digest>`, size `<bytes>` (one line per sample; original and copy digests match: yes/no)
- **Authority:** basis <owned / licensed / sanctioned>, approved by <name>, reference <ticket, contract or email>, date <date>, expiry <date or none>
- **Question(s):** <what the analysis had to answer>
- **Mode:** static | live
- **Live steps (if any):** <each approval verbatim, approver, time, environment checks passed, teardown confirmed>
- **Analyst / host / skill version / date:** <who, where, version, when>

## Summary

<2–4 sentences, plain language: what was asked, what was found, how confident.>

## Findings

| # | Question | Observation (tool and version · command · location) | Inference | Confidence | Unknowns / boundary |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |

> Observation = what the tool showed, reproducible from the digest + command.
> Inference = what you conclude, marked as such. Keep them in separate columns.
> Confidence: high = two independent signals, medium = one, low = a string or name alone.

## Tools used

| Tool | Version | Used for |
|---|---|---|
| | | |

## Open questions

<Anything the evidence did not settle, with the boundary of each negative claim.>

## Stop events and scope changes

<Every time the work stopped to ask (section 6A) and every scope change approved, with the approval reference.>

## Secrets and personal data

<Counts only: what kinds were found and where, masked (prefix, length, hash). No raw values.>

## Notes

<Chain of custody for nested payloads (what was carved from where), the ledger
hash at close, where the evidence is retained, and anything a future pass should
know. No raw credentials or personal data.>
