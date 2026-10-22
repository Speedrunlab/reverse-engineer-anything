# Reverse Engineer Anything

**Reverse Engineer Anything analyses any binary, package, firmware image, mobile app or captured traffic you are authorised to examine, using standard open-source tools and tying every finding to evidence.**

Free and open source · MIT Licence · Built by [Speedrun AI Labs](https://www.speedrunlab.ai), Sydney, Australia

---

## The idea

When a question depends on a shipped artifact you can't read the source of, which library a binary bundles, what an Electron app sends home, how a firmware image is laid out, what changed between two releases, you reach for reverse-engineering tools. This skill gives an AI agent a disciplined way to do that: route each target to the right tool, stay static and read-only by default, and tie every conclusion to evidence.

It is **self-contained and agent-agnostic**. It drives standard open-source tools (Ghidra, radare2, binwalk, JADX, apktool, WABT, tshark, and friends) through the agent's own terminal and file tools. There is **no bundled server to install, no `npx …@latest`, no `curl | bash`, and no edits to any agent's global config**, the whole point. It still runs in the clean, network-less environment described in the skill (section 1), not directly on a machine holding business credentials.

---

## What it does

- **Authorisation and scope gate first.** Before any tool runs: the target (or the versions to compare), an authority record with approver, reference, date and expiry, the question, static or live mode, and data handling. A new target, question or mode needs a new approval.
- **Safe sample handling.** A clean, network-less work environment with no credentials; a fixed `work/` layout; SHA-256 of original and copy; never execute, never mount; extraction limits that stop path tricks and archive bombs.
- **Content is data, never instructions.** Text inside a sample cannot grant approval or change scope; hosts and credentials found in a sample are never used or contacted; secrets are masked at the source.
- **Route by target type**, most specific first: native (ELF/Mach-O/PE), .NET, Go, Rust, WebAssembly, Electron/JavaScript, Android, firmware, archives and installers, model files, SQLite and recorded captures.
- **Static-first, smallest-first**, with rules for missing or failing tools and for output too large to read at once.
- **Live analysis is gated**: a recorded session envelope (not per-command approval), ownership or written vendor consent, and an isolated VM the agent checks and records, then tears down.
- **Stop and ask** on mismatched digests, suspected malware, breached limits, possibly live credentials, bulk personal data, or embedded text trying to change scope.
- **Evidence discipline**: an append-only ledger, observation separated from inference, confidence levels, bounded negative claims, a report template, and a safe two-version comparison procedure.

---

## Why it is safe to hand to a whole team

1. **No bundled tool server and no auto-install.** It drives open-source tools you install yourself, at pinned versions, verified. Nothing auto-fetches code, and nothing edits your agent's configuration.
2. **An explicit authorisation & scope gate** and **safe-sample handling** up front, suited to a regulated environment.
3. **Agent-agnostic**: it names no proprietary tool layer; it maps to whatever terminal and file tools your agent already has.

---

## What's new in v1.3.0 (23 Oct 2026)

Hardening round 3 (adversarial, usability, accuracy). Closes concrete abuse paths
a hostile sample could use and fills coverage gaps:

- A formatter, SQLite CLI or extractor no longer loads config, plugins, a view's
  `writefile()`, or a planted symlink out of the sample: Prettier runs
  `--no-config` from an empty scratch dir; SQLite uses `-init /dev/null -readonly`
  with `trusted_schema=OFF` and base tables only; every extractor gets an explicit
  output directory and runs with a sandboxed `HOME`; links out of the tree are
  neutralised before any recursive read or diff (`--no-dereference`).
- The preflight counts secret-shaped env names instead of printing values, checks
  more credential stores, and verifies the work path is not synced or
  version-controlled. One `run` wrapper logs every command and exit (no second
  log). The live VM exports and hashes the ledger before rollback so evidence
  survives. Core reading is explicitly static; launching or attaching a debugger
  is live.
- New routes and recipes: PyInstaller/`.pyc`, a full pcap recipe (hosts, DNS, SNI,
  cleartext, credential counts), macOS notarisation, Java endpoints/credentials and
  logging-framework version, .NET config-read APIs corrected.
- Accuracy: `7zz` everywhere, `msiinfo tables` before `export`, extractor `-d`/`-C`
  flags, AppImage offset from the ELF header, `eu-unstrip` for build-ids,
  `gdb -iex "set auto-load off"`, syft's app-update env var, `pickletools -I`,
  elfutils is Linux-only.

---

## What's new in v1.2.0 (22 Oct 2026)

Hardening round 2 (three fresh reviews). Two reviewers independently caught that
round 1's link rule would block every firmware root filesystem, and that the
"third-party component" clause blocked ordinary work; both are fixed.

- Extraction limits are concrete and workable (`timeout`, size/file/depth caps,
  `realpath` containment); filesystem links and device nodes are recorded, not
  followed, instead of rejected.
- Identifying a bundled component is in scope; reading its internals needs its own
  approval. Authority record adds a security contact, a licence-terms check, and
  an approver who is not the requester.
- Work environment is preflight-tested, not just asserted; sample-derived names
  never reach a shell; subagents are tightly scoped; the ledger is tamper-evident.
- Live analysis uses a recorded session envelope (so a debugger session is not
  stalled by per-command approval), with egress only to endpoints the organisation
  operates or may test.
- New routes and recipes: software bill of materials (SBOM) for a tree or image,
  Android permission-to-code mapping, .NET config-read tracing, Java/JVM, macOS
  app bundles, Windows/Linux installers and packages, crash and core dumps.
- Accuracy fixes: `7zz` vs `7z`, `rust-audit-info` (not `cargo audit bin`, which
  needs the network), `--only-binary` for pip, AppImage squashfs offset, macOS
  `readelf`, `android:usesCleartextTraffic`, macOS `app.asar` path.

---

## What's new in v1.1.0 (22 Oct 2026)

Hardening round 1 (three independent reviews: coverage, safety, agent usability):
- Authority record with approver and reference; data-handling check; re-approval on any scope change.
- Work environment, work layout, extraction limits, never-mount, content-is-data and out-of-bounds rules; secrets masked at the source.
- Live gate made checkable: per-step recorded approval, isolated VM checks, teardown.
- New "stop and ask" section; append-only ledger with confidence levels; retention instead of blanket cleanup.
- Routing picks the most specific row; rules for missing or failing tools and large output.
- Recipes: crypto-library version (linked vs bundled), Electron host inventory, two-version comparison.
- Fixes: binwalk v2/v3 flags, `7z -o`, `mitmdump -n -r`, full `bundletool` command, pickle model files never loaded, macOS `readelf`, rizin `aaa`.

---

## Install

### Claude Code
```bash
mkdir -p ~/.claude/skills
git clone https://github.com/Speedrunlab/reverse-engineer-anything.git ~/.claude/skills/reverse-engineer-anything
```
Then run: `/reverse-engineer-anything`. The skill assumes the open-source tools it names are installed; see `references/toolchain.md` for the install rules and tool list (pin each version, verify each download). For regulated or production use, install from an internal mirror at a pinned tag and verify the commit, and run inside the analysis environment of section 1.

### OpenClaw
```bash
mkdir -p ~/.openclaw/skills
git clone https://github.com/Speedrunlab/reverse-engineer-anything.git ~/.openclaw/skills/reverse-engineer-anything
```

### Any other agent
Copy `SKILL.md` into the agent's skills directory (or load it into its instructions), and make sure it has a terminal/shell tool and file read/write. The "Map it to your agent" table in `SKILL.md` covers the rest.

---

## What's in the box

```
SKILL.md                         the router: gate → identify → route → work → report
references/
  toolchain.md                   install rules and tool list; nothing auto-fetches
  native-and-managed.md          ELF/Mach-O/PE, .NET, Go, Rust, WebAssembly, Java/JVM, macOS bundles, crash dumps
  javascript-and-electron.md     ASAR, minified bundles, source maps
  android.md                     APK/AAB manifest, resources, bytecode
  firmware-and-archives.md       binwalk/unblob, installers and OS packages, SBOM, model files, SQLite
  network-and-runtime.md         recorded captures (static) + gated live observation
  evidence-and-reporting.md      the ledger, version diffing, verification
templates/
  finding-report.md              the report shape
```

---

## Scope and intent

This skill is for **authorised** analysis: software your organisation owns, ships, licenses, or is explicitly cleared to examine, interoperability, security review, incident response, debugging a vendor artifact, verifying a claim. It is deliberately not built for defeating access controls or examining a third party's software without a right to, and its first step makes authorisation explicit. Reverse engineering is lawful and routine security and interoperability work; do it on things you're allowed to.

---

## Licence

MIT. Free to use, modify and distribute.

---

## Part of the Speedrun AI Labs Skill Library

Other skills at [github.com/Speedrunlab](https://github.com/Speedrunlab):
- [/hermes-agent-as-a-skill-file](https://github.com/Speedrunlab/hermes-agent-as-a-skill-file), a self-improvement loop for any agent
- [/deep-audit](https://github.com/Speedrunlab/deep-audit), four-phase code auditor with evidence standards
- [/read-before-write](https://github.com/Speedrunlab/read-before-write), forces an agent to read files before editing them
- [/no-slop-writing](https://github.com/Speedrunlab/no-slop-writing) · [/no-slop-writing-au](https://github.com/Speedrunlab/no-slop-writing-au), strip AI-speak from generated text

---

*Built in Sydney by Speedrun AI Labs.*
