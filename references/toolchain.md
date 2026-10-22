# Toolchain

This skill drives standard open-source reverse-engineering tools. It installs
**nothing** on its own. You install what a task needs, deliberately, before the
agent uses it. This is the deliberate difference from a bundled tool server: no
auto-fetch, no `npx …@latest`, no `curl | bash`, no global-config edits, no
process that runs unreviewed code at install time.

## Install rules

1. **Install from the organisation's tool manifest.** Keep one list of approved
   tools with, for each, the exact version, the source and a checksum or signature
   obtained separately from the download itself. Ideally build it once into a
   pinned analysis image or VM and analyse inside that (see SKILL.md section 1).
2. **Pin the version.** Install an exact version, not "latest", and record which
   version produced each finding: a decompiler's output changes between releases.
   Homebrew cannot pin reliably; prefer a release download, a version-locked image,
   or a manager that pins.
3. **Verify the download** against the manifest's checksum or signature before
   running an installer. A checksum published next to the file proves it arrived
   intact, not who made it; a signature or an out-of-band hash does both. Never pipe
   a script into a shell.
4. **Stop install scripts.** Use `npm ci --ignore-scripts`,
   `pip install --require-hashes` and `cargo install --locked`. A dry run
   (`brew install --dry-run`, `apt-get -s install`) shows what would change but
   does not stop scripts; use it to spot an install that would upgrade shared
   system libraries, and stop if it would.
5. **Install once, for the host.** These are developer tools; install them to
   the machine, not per-analysis. The skill assumes they are present and says so
   when one is missing, it never installs on the fly mid-task.
6. **No tool here needs a global agent-config change.** If a workflow seems to
   need one, that is a signal to stop and reconsider, not to edit `~/.claude.json`
   or an MCP config.

## Tools by target (install only what the task needs)

| Target | Tool | Where | Notes |
|---|---|---|---|
| Any file: type, strings, hex | `file`, `binutils` (`strings`, `nm`, `objdump`, `readelf`), `xxd` | OS package manager | Usually already present on a dev host. |
| Native decompilation | **Ghidra** | NSA, github.com/NationalSecurityAgency/ghidra (releases list a SHA-256; verify it) | Needs a JDK. Headless mode drives it without the GUI. |
| Native disassembly / scripting | **rizin** or **radare2** | rizin.re / radare2.org | Lighter than Ghidra for quick passes; scriptable. |
| Mach-O (macOS) | `otool`, `nm`; `codesign -d` | `otool`/`nm` from Xcode command-line tools; `codesign` is built into macOS | `codesign -dvvv` reads signing identity. |
| .NET / managed | **ILSpy** / `ilspycmd` | github.com/icsharpcode/ILSpy | Decompiles CLI assemblies to C#. |
| Go binaries | `go version -m <bin>` | go.dev | Reads module/build metadata straight from the binary. |
| Rust (built with cargo-auditable) | `rust-audit-info`, `cargo audit bin` | github.com/rust-secure-code/cargo-auditable, RustSec `cargo-audit` | Read the `.dep-v0` dependency section. |
| Android | **apktool**, **JADX**, `aapt2` | github.com/iBotPeaches/Apktool, github.com/skylot/jadx | apktool for resources/manifest, JADX for Java/Kotlin. |
| JavaScript / Electron | `@electron/asar`, `prettier` (formatting), the `source-map` package | npm (pinned, `--ignore-scripts`) | Extract ASAR, then format and map back. |
| Android extras | `bundletool`, `apksigner` | github.com/google/bundletool; Android SDK build-tools | AAB to APK; signing certificates. |
| PE signatures | `osslsigncode` | github.com/mtrojnar/osslsigncode | Read Authenticode signatures. |
| JSON (HAR, metadata) | `jq` | jqlang.org | Query HAR files and JSON output. |
| Firmware / packed | **binwalk**, **unblob**, `7z`, `unsquashfs` | github.com/ReFirmLabs/binwalk, github.com/onekey-sec/unblob | Carve embedded filesystems and blobs. |
| WebAssembly | **WABT** (`wasm2wat`, `wasm-objdump`) | github.com/WebAssembly/wabt | Text form and section inventory; `wasm-decompile` only in WABT 1.0.41 and earlier. |
| Network captures | **Wireshark**/`tshark`, **mitmproxy** | wireshark.org, mitmproxy.org | Read saved pcap/HAR/flows; capture only in a controlled env. |
| SQLite | `sqlite3` | sqlite.org | Open a **copy** read-only (`sqlite3 -readonly copy.db`). |
| Model files | format header readers (GGUF/safetensors), `strings` | per-format | Read metadata; do not load weights to "inspect". |

## Keeping it safe for the whole organisation

- Every tool above is read-only on the sample by default. The ones that can act
  on a live target (debuggers, mitmproxy in intercept mode, a driven browser)
  are used only under SKILL.md section 6, in an isolated
  environment.
- Parsers are attack surface too: an unpacker or decompiler can have its own bugs
  (path traversal in an extractor has happened). That is why analysis runs in the
  network-less environment of SKILL.md section 1, never on the credentialed host.
- Do not assume a tool is offline: check its docs for update checks or telemetry,
  turn them off, and let the environment's denied network enforce it.
- A sample is untrusted input. Install tools from their own trusted source, and
  never from a link that came with the sample.
