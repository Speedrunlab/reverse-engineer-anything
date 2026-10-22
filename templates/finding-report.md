# Reverse-engineering finding report

> Copy this, fill it in, delete the guidance lines. One report per
> investigation; one row in the findings table per question.

## Scope (from the authorisation gate)

- **Target:** <one artifact, name and path>
- **Sample identity:** SHA-256 `<digest>`, size `<bytes>`
- **Authority:** <why this analysis is authorised, owned / licensed / sanctioned>
- **Question(s):** <what the analysis had to answer>
- **Mode:** static | live (if live: what ran, where it was isolated, who approved)
- **Analyst / date:** <who, when>

## Summary

<2–4 sentences, plain language: what was asked, what was found, how confident.>

## Findings

| # | Question | Observation (tool · command · location) | Inference | Confidence | Unknowns / boundary |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |

> Observation = what the tool showed, reproducible from the digest + command.
> Inference = what you conclude, marked as such. Keep them in separate columns.

## Tools used

| Tool | Version | Used for |
|---|---|---|
| | | |

## Open questions

<Anything the evidence did not settle, with the boundary of each negative claim.>

## Notes

<Chain of custody for nested payloads (what was carved from where), redactions
made, and anything a future pass should know. No raw credentials or personal
data.>
