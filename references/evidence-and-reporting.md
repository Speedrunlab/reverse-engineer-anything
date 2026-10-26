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

- **Layout.** Each version gets its own subdirectory, its own extraction roots
  (SKILL.md section 1 rules apply to each) and its own digest:
  `$W/v1.2/` and `$W/v1.3/`, each with `original/`, `extracted/` and `out/`.
  The one `$W/ledger.md`, `$W/commands.log` and `$W/out/` (for the diffs)
  stay at the top level. The report lists both identities.
- Normalise both sides the same way before diffing: extract/decompile/format
  each with the **same tool at the same version and settings**, or the diff is
  dominated by tooling noise.
- Give both versions' extraction roots the **same name** (`$W/v1.2/extracted/app/`
  and `$W/v1.3/extracted/app/`), so files pair up instead of all reading as
  "Only in"; each version keeps its link record and manifests in its own
  `$W/<version>/out/`.
- **Neutralise links first**: apply the SKILL.md section 1 link step to each root.
  GNU `diff` follows symlinks, so a planted link would pull outside content in.
  Use `--no-dereference` where the local `diff`
  supports it (GNU diffutils 3.3+; the macOS BSD `diff` may not, so run diffs in
  the Linux VM).
- Compare the two link records as well, since a retargeted link is a change the
  file diff cannot show: for each version, `tr '\0' '\n' < "$W/<version>/out/links-<name>.nul" | sed "s|^$W/<version>/extracted/<name>/||" | paste - - | LC_ALL=C sort > "$W/<version>/out/links-<name>.txt"`
  (each line is one link and its target, sorted, so extraction order does not matter),
  then `diff` the two `.txt` files into `$W/out/`.
- **Summary first.** `"$W/scripts/run.sh" diff -rq --no-dereference "$W/v1.2/extracted"
  "$W/v1.3/extracted" > "$W/out/diff-files-<name>.txt"` lists which files changed (exit 0:
  no differences; 1: differences found, the normal result; 2: an error); then
  `diff -u` one file at a time into `$W/out/`, reading with `head`. Never pour a
  whole-tree diff into your context.
- **Obfuscated or minified builds** rename symbols between versions, so a code
  diff is mostly noise. Compare what survives renaming: manifests and permissions
  (`aapt2 dump badging` for each APK, to a file and read as the Android guide says), component lists, native libraries and
  asset hashes (`shasum -a 256` per file), string tables and import lists.
- Report "added" or "removed" only when both sides were fully inventoried; state
  the boundary otherwise.
- For binaries, compare inventories first (symbols, imports, strings, section
  sizes); a changed import or a new string is a cheap signal before you diff
  decompiled functions.
- **Pairing functions across two builds:** BinDiff (Apache 2.0) scores matches
  between two exports made by its BinExport plugin from Ghidra, IDA or Binary
  Ninja: `bindiff <a>.BinExport <b>.BinExport --output_dir "$W/out/bindiff-<name>"`;
  Ghidra's Version Tracking does the same in its GUI. A match is a candidate with
  a similarity score, not an identity: confirm a changed pair by reading both
  decompiles, and call a function added or removed only when both binaries were
  fully analysed.
- **A call path** ("does `main` reach `send`?") comes from the call graph
  (Ghidra's Function Call Graph, rizin `agC`) and is bounded by indirect calls:
  with unresolved indirect targets, "no path" is an unknown, not a negative.
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

## Verifying a reconstruction

When the user builds a reimplementation from the findings, verify it the way a
finding is verified. Write the observed behaviours as a finite list of typed
claims (input, expected output, and the ledger entry each came from: a code path
read, or a recorded session), run the reimplementation against that list, and
give every claim one outcome: passed, failed, not applicable (the claim does not
apply to this build) or could not be tested (the input or the environment was
not available), reporting the count of each against the claim total, with the
vectors kept as evidence in `$W/out/verify-<name>.txt` (free of recorded
credentials). Passed and failed are results; not applicable is closed; could not
be tested stays open. A full pass means every claim passed or was not applicable,
with none left could-not-be-tested; it covers the declared claims only, never
equivalence; a behaviour nobody wrote down stays
unknown, and a claim that needed a live observation to state is marked so.

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
