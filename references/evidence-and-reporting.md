# Evidence, comparison and verification

How to keep the analysis trustworthy: the ledger, version diffing, corroboration
and a final verification pass. This is what separates a reverse-engineering
finding from a guess.

## The ledger

Keep one running record for the whole investigation. Every finding is one entry:

- **Question** it answers (from the section 0 checklist).
- **Evidence**: the sample's SHA-256, the exact tool and command, and the
  location (function, offset, file path, packet, table).
- **Observation**: what the tool showed, verbatim enough to reproduce.
- **Inference**: what you conclude from it, marked as inference.
- **Confidence** and **evidence type** (static / live / metadata).
- **Unknowns**: what this does not settle, and the boundary of any negative
  claim.

A reader should be able to take the digest and the command and get the same
observation. If they cannot, the entry is not finished.

## Observation vs inference vs unknown

The single most important discipline:

- **Observation:** "The import table lists `libcrypto.so.3`." Reproducible from
  the bytes.
- **Inference:** "It performs AES encryption." True only once you show the call
  into the AES routine, until then it is an inference from linkage.
- **Unknown:** "Whether it verifies the server certificate." Not settled by what
  you have looked at; name it as open.

Never promote an inference to an observation, and never imply static analysis
observed execution. "The code can reach host X" is not "the app contacted X".

## Version diffing

A common and high-value task: what changed between two releases.

- **Layout.** Each version gets its own subdirectory and its own digest:
  `work/v1.2/` and `work/v1.3/`, each with `original/`, `extracted/` and `out/`.
  The one `work/ledger.md`, `work/commands.log` and `work/out/` (for the diffs)
  stay at the top level. The report lists both identities.
- Normalise both sides the same way before diffing: extract/decompile/format
  each with the **same tool at the same version and settings**, or the diff is
  dominated by tooling noise.
- **Neutralise links first** (SKILL.md section 1): GNU `diff` follows symlinks, so
  a planted link would pull outside content in. Replace out-of-tree links with
  empty files before diffing, and use `--no-dereference` where the local `diff`
  supports it (GNU diffutils 3.3+; the macOS BSD `diff` may not, so run diffs in
  the Linux VM).
- **Summary first.** `diff -rq --no-dereference work/v1.2/extracted
  work/v1.3/extracted > work/out/diff-files.txt` lists which files changed; then
  `diff -u` one file at a time into `work/out/`, reading with `head`. Never pour a
  whole-tree diff into your context.
- **Obfuscated or minified builds** rename symbols between versions, so a code
  diff is mostly noise. Compare what survives renaming: manifests and permissions
  (`aapt2 dump badging` for each APK), component lists, native libraries and
  asset hashes (`shasum -a 256` per file), string tables and import lists.
- Report "added" or "removed" only when both sides were fully inventoried; state
  the boundary otherwise.
- For binaries, compare inventories first (symbols, imports, strings, section
  sizes); a changed import or a new string is a cheap signal before you diff
  decompiled functions.
- Report changes as observations ("function `foo` gained a bounds check") and
  keep intent ("to fix a vulnerability") as a labelled inference.

## Corroboration

Match a conclusion to the evidence type it needs:

- A behavioural claim wants a shown code path, and ideally a runtime observation
  under SKILL.md section 6, not a string alone.
- A "uses library X" claim wants the import or the linked code, not just a
  version string that could be vendored or stale.
- When two independent signals agree (an import and a call site; a manifest
  permission and the API call), say so, it raises confidence.

## Final verification pass

Before reporting complete:

1. Walk the section 0 question list. Mark each answered / partial / unresolved
   **by its evidence**, not by impression.
2. Check every conclusion still traces to a ledger entry with a reproducible
   command and the sample digest.
3. Confirm negative claims carry their boundary.
4. Confirm nothing in the report presents an inference as an observation, and no
   credential-shaped data was pasted in raw.
5. If a required question is unresolved, say so plainly, a bounded "not
   determined" is a better finding than a confident guess.
