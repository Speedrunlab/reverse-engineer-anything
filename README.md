# reverse-engineer-anything

**Reverse engineer anything you're authorised to: a binary, a package, firmware, a mobile app, captured traffic, using standard open-source tools, with evidence discipline.**

Free and open source · MIT Licence · Built by [Speedrun AI Labs](https://www.speedrunlab.ai), Sydney, Australia

---

## The idea

When a question depends on a shipped artifact you can't read the source of, which library a binary bundles, what an Electron app sends home, how a firmware image is laid out, what changed between two releases, you reach for reverse-engineering tools. This skill gives an AI agent a disciplined way to do that: route each target to the right tool, stay static and read-only by default, and tie every conclusion to evidence.

It is **self-contained and agent-agnostic**. It drives standard open-source tools (Ghidra, radare2, binwalk, JADX, apktool, WABT, tshark, and friends) through the agent's own terminal and file tools. There is **no bundled server to install, no `npx …@latest`, no `curl | bash`, and no edits to any agent's global config**, the whole point, so it's safe to hand to everyone on a team, including on machines that hold credentials.

---

## What it does

- **Authorisation & scope gate first.** Before any tool runs: name the one target, record why the analysis is authorised, state the question, and choose static or live mode. Scope is written down and inherited by everything after.
- **Safe sample handling.** Work on a copy in an isolated directory, record a SHA-256, never execute the sample to inspect it, redact credentials before reporting.
- **Route by target type.** Native (ELF/Mach-O/PE), .NET, Go, Rust, WebAssembly, Electron/JavaScript, Android APK, firmware, packed archives, model files, SQLite, and recorded network captures, each to the right open tool and a focused reference guide.
- **Static-first, smallest-first.** Cheap inventory passes before decompilation; follow the question, not the whole binary.
- **Live analysis is gated.** Running, debugging, driving a browser or capturing traffic is off by default and needs explicit approval, an owned target, and an isolated environment.
- **Evidence discipline.** A ledger that separates observation, inference and unknown; every finding cites the sample digest and the exact command; a report template and a verification pass.
- **Version diffing** as a first-class workflow.

---

## How it's different from REA

This skill is an independent, from-scratch take on the target-routing pattern that [REA](https://github.com/morluto/rea) (morluto, MIT) established. We audited REA, found it clean, and then wrote our own, **none of its text or code is used here**, with three deliberate changes for team-wide safety:

1. **No bundled tool server and no auto-install.** REA is built around its `rea-agents` MCP package fetched with `npx -y …@latest`. Ours drives tools you install yourself, at pinned versions, verified. Nothing auto-fetches, and nothing edits your agent config.
2. **An explicit authorisation & scope gate** and **safe-sample handling** up front, suited to a regulated environment.
3. **Agent-agnostic**: it names no proprietary tool layer; it maps to whatever terminal and file tools your agent already has.

---

## Install

### Claude Code
```bash
mkdir -p ~/.claude/skills
git clone https://github.com/Speedrunlab/reverse-engineer-anything.git ~/.claude/skills/reverse-engineer-anything
```
Then run: `/reverse-engineer-anything`. The skill assumes the open-source tools it names are installed; see `references/toolchain.md` for the pinned, verified install list.

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
  toolchain.md                   pinned, verified install list; no auto-fetch
  native-and-managed.md          ELF/Mach-O/PE, .NET, Go, Rust, WebAssembly
  javascript-and-electron.md     ASAR, minified bundles, source maps
  android.md                     APK/AAB manifest, resources, bytecode
  firmware-and-archives.md       binwalk/unblob, installers, model files, SQLite
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
