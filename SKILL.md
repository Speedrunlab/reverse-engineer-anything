---
name: reverse-engineer-anything
description: Analyse a shipped binary, package, firmware image, mobile app or captured traffic to explain how it works, when source is not available. Static-first and evidence-led, driving standard open-source tools through the agent's own terminal and file tools. Authorisation-gated; skip it for ordinary source-repository work. Use when a question depends on a compiled artifact, a decompile, a version diff, or recorded runtime evidence.
license: MIT
compatibility: Any agent with a terminal/shell tool, file read/write, and permission to install the named open-source tools.
metadata:
  version: 1.0.0
  author: Speedrun AI Labs
  tags: reverse-engineering, binary-analysis, security-research, interoperability
---

# Reverse Engineer Anything

Analyse software you cannot read the source of: a compiled binary, a packaged
or mobile app, a firmware image, a model file, or a captured session. The skill
routes each target to the right open-source tool, keeps the work static and
read-only by default, and ties every conclusion to evidence. It is
**agent-agnostic**: it names no proprietary server and no bundled tool layer.
Every step is something the agent runs through its normal terminal and
file tools, against tools the operator has installed.

This skill is for **authorised** analysis: software your organisation owns,
ships, licenses, or is explicitly cleared to examine (interoperability,
security review, incident response, debugging a vendor artifact, verifying a
claim). It is not for defeating access controls, lifting protected assets, or
examining a third party's software without a right to. The first step is a gate
that makes that explicit.

---

## 0. AUTHORISATION AND SCOPE GATE

Before any tool runs, establish and record four things. If any is unclear, ask
once and wait; do not guess your way past this.

1. **The target**: one concrete artifact: a file path, a package, an image. If
   the user says only "my app", resolve it to one artifact before searching;
   never pick an example or a nearby fixture on their behalf.
2. **The authority**: the target is owned by, licensed to, or the analysis is
   explicitly sanctioned for, the person asking. Record it in one line.
3. **The question**: what the analysis must answer. This bounds how far to go.
   "Which crypto library does it bundle?" is a different depth from "reconstruct
   the protocol".
4. **The mode**: **static** (read-only inspection of a copy, the default) or
   **live** (running, attaching to, or driving the target). Live analysis is
   off until the operator approves it explicitly, per section 6.

Write these into the finding ledger (section 7) as the first entry. Everything
after inherits this scope; do not widen the target or the mode without a new
approval.

---

## 1. HANDLE THE SAMPLE SAFELY

A shipped artifact is untrusted input. Treat it like one, every time.

- **Work on a copy, in its own directory.** Never analyse the only copy, and
  never analyse in a directory that holds your scripts or the operator's work:
  a planted file next to an interpreter can run on import. Put the sample in a
  fresh, empty directory and pass it to tools by absolute path.
- **Do not execute it to inspect it.** Static tools read bytes; they do not run
  the target. Running, unpacking-that-executes, or opening in an app is live
  mode (section 6) and needs approval.
- **Record identity first.** Before anything else, take the size and a SHA-256
  of the sample and record it. Every later finding cites this digest, so a
  reader knows exactly which bytes produced it.
  - `shasum -a 256 <path>` (or `sha256sum`), and `ls -l` / `stat` for size.
- **Keep extraction output inside the sample directory**, in a named subfolder,
  so nothing lands where it can be run or confused for a source tree.
- **Redact before you report.** Decompiled strings and config can carry keys,
  tokens and personal data. Surface what answers the question; do not paste raw
  credential-shaped output into a report.

---

## 2. IDENTIFY THE TARGET

Do not infer the format from the file extension. Read the bytes.

- `file <path>`: first-pass type.
- `xxd <path> | head` / `head -c 64 <path> | xxd`: magic bytes when `file` is
  unsure.
- For a container you suspect holds more (an installer, a firmware image, a
  packed executable), note it and route to section 5 rather than guessing.

Map what you find to a route in section 3. When one artifact nests another (an
APK inside a ZIP, a native blob inside firmware), identify the outer layer,
extract it (section 5), then re-identify each payload. Anomalies, a mismatched
magic, an unexpected section, padding that is not padding, are usually where
the answer is.

---

## 3. ROUTE BY TARGET TYPE

Pick the first entry that matches the artifact. Each names the open-source tool
to drive and the reference guide to read before going deep. Read **only** the
guide for the route you are on.

| Target | First tools | Guide |
|---|---|---|
| Native executable / library (ELF, Mach-O, PE) | `file`, `nm`, `objdump`, `readelf`/`otool`, then Ghidra or rizin/radare2 for decompilation | [native and managed](references/native-and-managed.md) |
| .NET / managed assembly (PE/CLI) | ILSpy / `ilspycmd`, `monodis` | [native and managed](references/native-and-managed.md) |
| Go binary | `go version -m`, `strings`, Ghidra (current releases recover Go symbols) | [native and managed](references/native-and-managed.md) |
| Rust binary (built with cargo-auditable) | `rust-audit-info` or `cargo audit bin`, then Ghidra/rizin | [native and managed](references/native-and-managed.md) |
| JavaScript / Electron / ASAR | `asar extract`, a source-map reader, a beautifier/unminifier | [javascript and electron](references/javascript-and-electron.md) |
| Android APK (an AAB converts with `bundletool` first) | `apktool`, JADX, `aapt2 dump` | [android](references/android.md) |
| Firmware image / packed archive / installer | `binwalk`, `unblob`, `7z`, format-specific unpackers | [firmware and archives](references/firmware-and-archives.md) |
| WebAssembly (.wasm) | `wasm2wat` / `wasm-objdump` (WABT) | [native and managed](references/native-and-managed.md) |
| Model file (GGUF, safetensors) | a header reader for the format; `strings` for metadata | [firmware and archives](references/firmware-and-archives.md) |
| SQLite database | `sqlite3` (read-only, on a copy), schema first | [firmware and archives](references/firmware-and-archives.md) |
| Captured traffic (HAR, pcap, SAZ) | `tshark`/Wireshark, a HAR reader; mitmproxy for saved flows | [network and runtime](references/network-and-runtime.md) |
| A running app or live browser (approved) | see the live gate | [network and runtime](references/network-and-runtime.md) |

If nothing matches cleanly, start with `file` + `strings` + `binwalk` to
characterise the artifact, record what you observe, and ask before inventing a
route.

---

## 4. WORK SMALLEST-FIRST

Depth costs time and tokens; spend it only where the question needs it.

1. **Overview before detail.** A symbol table, an import list, a string scan, a
   manifest, the cheap passes often answer the question outright. Do the
   whole-file inventory before you decompile one function.
2. **Follow the question, not the whole binary.** From the question, pick the
   entry point (an export, a string, a symbol, a manifest permission) and work
   outward only as far as the answer needs.
3. **Do not repeat an identical pass.** If a decompile or an extraction is done
   and recorded, reuse it; re-run only when the input or a tool version changed.
4. **Batch around a hypothesis.** Group related lookups to test one idea, then
   expand only where the result leaves a concrete gap.
5. **Parallelise independent questions.** When several questions do not depend
   on one another and workers are available, give each a distinct scope and a
   pointer to the shared evidence, and have each return sources, conclusions and
   gaps.

---

## 5. UNPACK NESTED ARTIFACTS

Installers, firmware and packed executables carry the real target inside.

- `binwalk <image>` to map embedded contents; `binwalk -e -d <outdir>` (binwalk v3; v2 uses `-C`) or `unblob -e <outdir>` to
  carve them **into the sample subfolder**, never the working tree.
- Re-identify every carved payload (section 2) and route each (section 3).
- Record what each layer was and where it came from in the image, so the chain
  from the original bytes to the analysed payload is auditable.
- A carve that would execute anything (an auto-run unpacker, a self-extracting
  stub) is live mode, stop and get approval (section 6).

See [firmware and archives](references/firmware-and-archives.md) for per-format
carving and the model-file / SQLite / archive details.

---

## 6. LIVE ANALYSIS (APPROVAL-GATED)

Static evidence answers most questions. Reach for live analysis **only** when a
question genuinely cannot be answered from static evidence, observed runtime
behaviour, dynamic values, traffic the binary actually sends.

Live analysis is off by default. Before any of it:

- The operator approved **this** live step, naming what runs and why.
- It runs on an artifact the organisation owns, in an **isolated environment** -
  a disposable VM or container, not the host that holds credentials, keys or
  logged-in sessions, and never a personal, signed-in browser profile.
- The scope is the declared target and action only; do not broaden either.

Covered techniques and their isolation requirements are in
[network and runtime](references/network-and-runtime.md): recorded-capture
replay (static, no approval needed), running under a debugger in a sandbox,
observing a browser/Electron session the operator drives, and capturing traffic
in a controlled environment. Never attach to, inject into, or drive a process
outside the approved, isolated scope.

---

## 7. EVIDENCE AND REPORTING

Reverse engineering is only as good as its evidence trail. Keep a ledger and
report from it.

- **One identity, cited everywhere.** Every finding references the sample's
  SHA-256 (section 1) and the exact tool + command that produced it, so any
  claim can be reproduced.
- **Separate observation, inference and unknown.** "The import table lists
  `libcrypto`" is an observation. "It uses AES" is an inference until you show
  the call. "Whether it validates the cert" is an unknown until evidenced. Never
  present an inference as an observation, and never imply static analysis
  observed execution.
- **Bound negative claims.** "No network calls found" means "none found in the
  functions searched", state the boundary. Absence of evidence is not proof of
  absence.
- **Ledger entry per finding:** question → evidence (tool, command, digest,
  location) → observation → inference → confidence → remaining unknowns.
- **Close the loop.** Revisit the original question list; mark each answered,
  partial, or unresolved by its evidence. Do not call a broad investigation
  complete while required questions are open.

Use [templates/finding-report.md](templates/finding-report.md) for the report
shape, and [evidence and reporting](references/evidence-and-reporting.md) for
version-diffing, corroboration and verification workflows.

---

## 8. FINISH

Explain findings in plain language, tied to the evidence. When the user asks you
to **build** something from what you learned, switch to normal coding tools and
keep observed behaviour separate from your own design choices, a
reimplementation is informed by the analysis, not a copy of protected
expression. Clean up: remove extracted copies when the work is done unless the
operator wants them kept, and never leave a live session or a sandbox running.

---

## TOOLCHAIN

This skill drives standard open-source tools; it installs nothing on its own.
Install them deliberately, at pinned versions, with checksum verification, per
[references/toolchain.md](references/toolchain.md). Nothing here runs
`npx …@latest`, `curl | bash`, or edits any agent's global configuration. If a
needed tool is absent, say so and name the install step; do not auto-fetch it.

## MAP IT TO YOUR AGENT

| This skill says | Your agent provides |
|---|---|
| Run a tool | A terminal/shell tool |
| Read a file, record the ledger | File read/write |
| Decompile / carve / parse | The installed open-source tools (toolchain guide) |
| Parallel workers | Subagents, if available; otherwise work sequentially |

## CREDITS

Reverse Engineer Anything is written and maintained by Speedrun AI Labs
(speedrunlab.ai). It depends on no external package or server, only the
open-source tools you install yourself.
