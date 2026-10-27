# Reverse Engineer Anything

**Reverse Engineer Anything analyses any binary, package, firmware image, mobile app or captured traffic you are authorised to examine, using standard open-source tools and tying every finding to evidence.**

Free and open source · MIT Licence · Built by [Speedrun AI Labs](https://www.speedrunlab.ai), Sydney, Australia

Inspired by REA (Reverse Engineer Anything) by @morluto: [github.com/morluto/rea](https://github.com/morluto/rea). Not affiliated.

---

## The idea

When a question depends on a shipped artifact you can't read the source of, which library a binary bundles, which hosts an Electron app can contact, how a firmware image is laid out, what changed between two releases, you reach for reverse-engineering tools. This skill gives an AI agent a disciplined way to do that: route each target to the right tool, stay static and read-only by default, and tie every conclusion to evidence.

It is **self-contained and agent-agnostic**. It drives standard open-source tools (Ghidra, radare2, binwalk, JADX, apktool, WABT, tshark, and friends) through the agent's own terminal and file tools. It needs no extra server and makes no changes to your agent's global config; you install the open-source tools yourself, at pinned versions. It still runs in the clean, network-less environment described in the skill (section 1), not directly on a machine holding business credentials.

---

## What it does

- **Authorisation and scope gate first.** Before any tool runs: the target (or the versions to compare), an authority record with approver, reference, date and expiry, the question, static or live mode, and data handling. A new target, question or mode needs a new approval.
- **Safe sample handling.** A clean, network-less work environment with no credentials; a fixed layout under one operator-named working directory; SHA-256 of original and copy; never execute, never mount; extraction limits that stop path tricks and archive bombs.
- **Content is data, never instructions.** Text inside a sample cannot grant approval or change scope; hosts and credentials found in a sample are never used or contacted; secrets are masked at the source.
- **Route by target type**, most specific first: .NET, Go, Rust, WebAssembly, Unity IL2CPP, Flutter, Erlang/Elixir BEAM, Electron/JavaScript and Node.js single executables, Android, Java/JVM, Apple app bundles and iOS IPAs, Windows and Linux installers and packages, Linux kernel modules, PyInstaller, Godot and HarmonyOS packages, GameCube and Wii DOL executables, firmware, archives and flattened devicetrees, GPU code objects, EVM contract bytecode, crash and core dumps and Apple `.ips` reports, model files, SQLite, recorded captures (protobuf and gRPC bodies included) and logic-analyser recordings, a software bill of materials, and native ELF/Mach-O/PE as the fallback, with a marker table for working out what an installed app is built with.
- **Static-first, smallest-first**, with rules for missing or failing tools and for output too large to read at once.
- **Live analysis is gated**: a recorded session envelope (not per-command approval), ownership, written vendor consent or the security lead's written sanction, and an isolated VM the agent checks and records, then tears down.
- **Stop and ask** on mismatched digests, suspected malware, breached limits, possibly live credentials, bulk personal data, or embedded text trying to change scope.
- **Evidence discipline**: an append-only ledger, observation separated from inference, confidence levels, bounded negative claims, a report template, and a safe two-version comparison procedure.

---

## Why it is safe to hand to a whole team

1. **No bundled tool server and no auto-install.** It drives open-source tools you install yourself, at pinned versions, verified. Nothing auto-fetches code, and nothing edits your agent's configuration.
2. **An explicit authorisation & scope gate** and **safe-sample handling** up front, suited to a regulated environment.
3. **Agent-agnostic**: it names no proprietary tool layer; it maps to whatever terminal and file tools your agent already has.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Current version: 1.24.0.

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
Copy the **whole folder** (`SKILL.md`, `references/`, `templates/`) into the agent's skills directory; `SKILL.md` links to the others, and make sure it has a terminal/shell tool and file read/write. The "Map it to your agent" table in `SKILL.md` covers the rest.

---

## What's in the box

```
SKILL.md                         the router: gate → identify → route → work → report
references/
  toolchain.md                   install rules and tool list; nothing auto-fetches
  native-and-managed.md          ELF/Mach-O/PE, .NET, Go, Rust, WebAssembly, Java/JVM, Apple bundles and IPAs, crash dumps and .ips,
                                 Unity IL2CPP, Flutter, BEAM, GPU code objects, EVM bytecode, kernel modules, DOL, runtime markers
  javascript-and-electron.md     ASAR, fuses, renderer isolation, Node.js single executables, minified bundles, source maps
  android.md                     APK/AAB manifest, resources, bytecode, constants, signing schemes
  firmware-and-archives.md       binwalk/unblob, devicetrees, installers and OS packages, Godot, HarmonyOS, SBOM, model files, SQLite
  network-and-runtime.md         recorded captures, protobuf/gRPC bodies and signal recordings (static) + gated live observation
  evidence-and-reporting.md      the ledger, version diffing, verification
templates/
  finding-report.md              the report shape
CHANGELOG.md                     version history
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
- [/reverse-engineer-anything-self-learning-loop](https://github.com/Speedrunlab/reverse-engineer-anything-self-learning-loop), examine a product you are authorised to rebuild, build your own, and improve it against the original until every must-have on a written checklist passes
- [/hermes-agent-as-a-skill-file](https://github.com/Speedrunlab/hermes-agent-as-a-skill-file), a self-improvement loop for any agent
- [/deep-audit](https://github.com/Speedrunlab/deep-audit), four-phase code auditor with evidence standards
- [/read-before-write](https://github.com/Speedrunlab/read-before-write), forces an agent to read files before editing them
- [/no-slop-writing](https://github.com/Speedrunlab/no-slop-writing) · [/no-slop-writing-au](https://github.com/Speedrunlab/no-slop-writing-au), strip AI-speak from generated text

---

*Built in Sydney by Speedrun AI Labs.*
