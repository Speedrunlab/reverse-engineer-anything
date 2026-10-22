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
4. **Reduce install-time code.** `npm ci --ignore-scripts` stops npm lifecycle
   scripts. For Python prefer wheels (`pip install --require-hashes
   --only-binary=:all:`); an sdist still runs its build backend. `cargo install
   --locked` pins versions but `build.rs` and proc-macros still run, so build Rust
   tools in a sandbox. A dry run (`brew install --dry-run`, `apt-get -s install`)
   shows what would change but does not stop scripts; use it to catch an install
   that would upgrade shared system libraries, and stop if it would.
5. **Install into the analysis image or VM, not the credentialed host.** These are
   developer tools; build them once into the pinned image the analysis runs in
   (SKILL.md section 1). The skill assumes they are present and says so when one is
   missing; it never installs on the fly mid-task.
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
| Rust (built with cargo-auditable) | `rust-audit-info` | github.com/rust-secure-code/rust-audit | List the `.dep-v0` dependency tree offline. |
| .NET IL dump | `monodis` | Mono | Dump IL and metadata without a GUI. |
| ELF notes / cores (macOS host) | `llvm-readelf`, `eu-readelf`/`eu-stack` (elfutils) | LLVM, sourceware.org/elfutils | Apple `nm` can't read ELF; use these or `$(brew --prefix binutils)/bin/readelf`. |
| Pickle inspection | `python3 -m pickletools` (stdlib) | Python | Disassemble a pickle without loading it. |
| Java / JVM | `javap` (JDK), **CFR** or **Vineflower**, `jarsigner` | jdk; github.com/leibnitz27/cfr, github.com/Vineflower/vineflower | Disassemble and decompile `.class`/`.jar`. |
| macOS bundles / packages | `plutil`, `codesign`, `lipo`, `pkgutil` | built into macOS | Read Info.plist, entitlements, architectures, package signatures. |
| Windows / Linux installers | `msitools` (`msiinfo`, `msiextract`), `innoextract`, `dpkg-deb`, `rpm2cpio`, `cabextract` | distro packages | Unpack installers and OS packages without running them. |
| SBOM / component scan | **syft** (+ `grype` or `osv-scanner`, DB staged) | github.com/anchore/syft | Inventory components in a tree or image; disable DB auto-update. |
| Android | **apktool**, **JADX**, `aapt2` | github.com/iBotPeaches/Apktool, github.com/skylot/jadx | apktool for resources/manifest, JADX for Java/Kotlin. |
| JavaScript / Electron | `@electron/asar`, `prettier` (formatting), the `source-map` package | npm (pinned, `--ignore-scripts`) | Extract ASAR, then format and map back. |
| Android extras | `bundletool`, `apksigner` | github.com/google/bundletool; Android SDK build-tools | AAB to APK; signing certificates. |
| PE signatures | `osslsigncode` | github.com/mtrojnar/osslsigncode | Read Authenticode signatures. |
| JSON (HAR, metadata) | `jq` | jqlang.org | Query HAR files and JSON output. |
| Firmware / packed | **binwalk**, **unblob**, `7zz`, `unsquashfs` | github.com/ReFirmLabs/binwalk, github.com/onekey-sec/unblob, 7-zip.org | Carve embedded filesystems and blobs. `7zz` is official 7-Zip; `7z` is p7zip. |
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
