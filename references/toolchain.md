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
| Rust (built with cargo-auditable) | `rust-audit-info` | github.com/rust-secure-code/cargo-auditable (the `rust-audit-info` crate) | List the `.dep-v0` dependency tree offline. |
| .NET IL dump | `monodis` | Mono | Dump IL and metadata without a GUI. |
| ELF notes / cores | `llvm-readelf`; `eu-readelf`/`eu-stack`/`eu-unstrip` (elfutils, Linux only) | LLVM; sourceware.org/elfutils | Apple `nm` can't read ELF. On macOS use `llvm-readelf` or `$(brew --prefix binutils)/bin/readelf`; run the `eu-*` tools in the Linux VM. |
| Pickle inspection | `pickletools` (stdlib), through the skill's `pickle-dis.py` helper | Python | Disassemble every pickle in a file without loading it (plain `python3 -m pickletools` stops at the first). |
| ZIP | `unzip` (Info-ZIP), or `bsdtar` | distro packages | List (`unzip -l`) and stream single members (`unzip -p`) of jars and other ZIPs. |
| Java / JVM | `javap` (JDK), **CFR** or **Vineflower**, `jarsigner` | jdk; github.com/leibnitz27/cfr, github.com/Vineflower/vineflower | Disassemble and decompile `.class`/`.jar`. |
| PyInstaller / pyc | `pyinstxtractor`, `pyi-archive_viewer` (PyInstaller), **pycdc**/`pycdas`; the skill's `pyc-header.py` | github.com/extremecoders-re/pyinstxtractor, github.com/zrax/pycdc | Unpack a PyInstaller exe and disassemble/decompile `.pyc`; read the header first. |
| macOS bundles / packages | `plutil`, `codesign`, `lipo`, `pkgutil` | built into macOS | Read Info.plist, entitlements, architectures, package signatures. |
| Windows / Linux installers | `msitools` (`msiinfo`, `msiextract`), `innoextract`, `unshield`, `cabextract`, `dpkg-deb`, `rpm`, `bsdtar` (libarchive) | distro packages | Unpack installers and OS packages without running them. |
| macOS packages / signing | `xar`, `xcrun stapler`; `rcodesign` on Linux | Xcode command-line tools; github.com/indygreg/apple-platform-rs | Expand `.pkg`; check stapled notarisation; read Apple signatures off-Mac. |
| Crash and core dumps | `gdb`, Breakpad `minidump_stackwalk`, `atos` (macOS) or `llvm-symbolizer`; `jq` for `.ips` | distro packages; chromium.googlesource.com/breakpad; LLVM | Post-mortem backtraces and symbolication; never `run`; gdb with `set print frame-arguments none`. |
| SBOM / component scan | **syft** (+ `grype` or `osv-scanner` for vulns, DB staged) | github.com/anchore/syft | Inventory components. syft has no DB; `SYFT_CHECK_FOR_APP_UPDATE=false` stops its only network call. |
| Android | **apktool**, **JADX**, `aapt2` | github.com/iBotPeaches/Apktool, github.com/skylot/jadx; `aapt2` from Android SDK build-tools | apktool for resources/manifest, JADX for Java/Kotlin. |
| JavaScript / Electron | `@electron/asar`, `prettier` (formatting), the `source-map` package | npm (pinned, `--ignore-scripts`) | Extract ASAR, then format and map back. |
| Android extras | `bundletool`, `apksigner` | github.com/google/bundletool; Android SDK build-tools | AAB to APK; signing certificates. |
| PE signatures | `osslsigncode` | github.com/mtrojnar/osslsigncode | Verify Authenticode against a staged CA bundle (`-ignore-cdp` offline); `extract-signature -pem` plus `openssl pkcs7` names the signer. |
| JSON (HAR, metadata) | `jq` | jqlang.org | Query HAR files and JSON output. |
| Firmware / packed | **binwalk**, **unblob**, `7zz`, `unsquashfs`; the skill's `entropy.py` | github.com/ReFirmLabs/binwalk, github.com/onekey-sec/unblob, 7-zip.org | Carve embedded filesystems and blobs; an entropy map per block. `7zz` is official 7-Zip; `7z` is p7zip. |
| WebAssembly | **WABT** (`wasm2wat`, `wasm-objdump`) | github.com/WebAssembly/wabt | Text form and section inventory; `wasm-decompile` only in WABT 1.0.41 and earlier. |
| Network captures | **Wireshark**/`tshark`, **mitmproxy** | wireshark.org, mitmproxy.org | Read saved pcap/HAR/flows; capture only in a controlled env. |
| SQLite | `sqlite3` | sqlite.org | Open a **copy** read-only, as the firmware and archives guide shows (`-readonly -init /dev/null`, `trusted_schema=OFF`). |
| Model files | format header readers (GGUF/safetensors), `strings` | per-format | Read metadata; do not load weights to "inspect". |
| Unity IL2CPP | **Il2CppDumper** | github.com/Perfare/Il2CppDumper | Needs a .NET runtime; parses `global-metadata.dat` plus the code binary, runs nothing. |
| Flutter | `strings`, `readelf -n`; a snapshot-hash table (reFlutter's `enginehash.csv`); **Blutter** optional | github.com/Impact-I/reFlutter, github.com/worawit/blutter | Blutter builds a Dart runtime for the exact SDK: prepare it when the image is built. |
| Godot | **GDRE Tools** (`gdre_tools`) | github.com/GDRETools/gdsdecomp | Headless `--list-files`, `--extract`, `--recover`. |
| EVM bytecode | Foundry `cast` (`selectors`, `disassemble`) | getfoundry.sh (github.com/foundry-rs/foundry) | Offline; never `--resolve`, which calls a public service. |
| GPU code objects | `cuobjdump`, `nvdisasm` (CUDA toolkit); `roc-obj-ls`, `roc-obj-extract` (ROCm); `clang-offload-bundler` (LLVM) | developer.nvidia.com; rocm.docs.amd.com | Vendor toolkits, free but not open source; install into the image. |
| Erlang / Elixir | `erl` (OTP) for `beam_lib` | erlang.org | Reads chunks without loading the module. |
| Logic-analyser recordings | **sigrok-cli** with libsigrokdecode | sigrok.org | Reads `.sr`, `.vcd`, CSV; decodes only. |
| ELF hardening | `checksec` | github.com/slimm609/checksec | RELRO, canary, NX, PIE, RPATH, Fortify. |
| PE resources | `wrestool` (icoutils) | nongnu.org/icoutils | Lists and extracts resources; no version-info decoding. |
| Apple resources | `assetutil`, `plutil`, `openssl smime` | built into macOS | Asset catalogs, nibs, keyed archives, provisioning profiles. |
| Objective-C / Swift names | `otool -ov`, `swift demangle`; `dsdump` optional | Xcode command-line tools; github.com/DerekSelander/dsdump | Class, method and protocol names. |
| Two builds, function pairing | **BinDiff** + BinExport | github.com/google/bindiff | Apache 2.0; exports from Ghidra, IDA or Binary Ninja. |
| Electron fuses | `@electron/fuses` (`electron-fuses read`) | npm (pinned, `--ignore-scripts`) | Reads the fuse wire in the Electron binary. |
| JavaScript unminifying | `wakaru` (`@wakaru/cli`) | npm (pinned, `--ignore-scripts`) | Rewrites a bundle into modules; output is not source. |
| HarmonyOS | `ark_disasm` | OpenHarmony SDK toolchains | Disassembles `modules.abc`. |
| React Native (Hermes) | `hermes-dec` | github.com/P1sec/hermes-dec | Disassembles and decompiles Hermes bytecode. |
| PE tables | `llvm-readobj` (`--coff-imports`, `--coff-exports`, `--coff-tls-directory`, `--coff-load-config`); `llvm-objdump` (`--disassemble-symbols`) | LLVM releases (github.com/llvm/llvm-project); Apple's command-line tools ship `llvm-objdump` with four target families and no `llvm-readobj` | Imports, delay-loads, exports, TLS callbacks, load configuration; one function by name. |
| PE in Python | `pefile` | github.com/erocarrera/pefile (pip, `--require-hashes`) | The same directories as objects; `get_imphash()`; the TLS callback array. |
| Linux kernel modules | `kmod` (`modinfo`, `modprobe --show-modversions`); the kernel tree's `scripts/extract-module-sig.pl`; the skill's `modsig.py` | distro packages; kernel.org | `.modinfo`, symbol CRCs, the signature trailer; `readelf -p .modinfo` works on any host. |
| Devicetrees | `dtc`, `fdtdump`, `fdtget` (device-tree-compiler); `dumpimage` (u-boot-tools) for FIT images, optional | distro packages; git.kernel.org/pub/scm/utils/dtc/dtc.git | Decompile and query `.dtb`/`.itb`; read only. |
| Node.js single executables | `segedit` (Xcode command-line tools), `wrestool` (icoutils), the skill's `elf-note.py` | Xcode command-line tools; nongnu.org/icoutils | Extract the `NODE_SEA_BLOB` resource (the Mach-O section is `__NODE_SEA_BLOB`) from a Mach-O, PE or ELF carrier. |
| Protobuf and gRPC bodies | `protoc` (`--decode_raw`, `--decode`) | github.com/protocolbuffers/protobuf releases | Decode a captured message with or without its schema; nothing is fetched. |
| GGUF and safetensors | `gguf-dump` (the `gguf` package from llama.cpp's `gguf-py`); the skill's `gguf-header.py` and `safetensors-header.py` | pip (`--require-hashes`); github.com/ggml-org/llama.cpp | Metadata and the tensor directory only; weights are never loaded. |
| GameCube / Wii DOL | Ghidra GameCube Loader extension | github.com/Cuyler36/Ghidra-GameCube-Loader (Apache 2.0) | Loads DOL and REL, adds the Gekko/Broadway language; the skill's `dol-header.py` reads the header without it. |
| Firmware peripheral registers | SVD-Loader-Ghidra (`SVD-Loader.py`) with a CMSIS-SVD file | github.com/leveldown-security/SVD-Loader-Ghidra (GPL 3.0); github.com/cmsis-svd/cmsis-svd-data | Labels memory-mapped registers in Ghidra from the chip's SVD. |
| Live only (SKILL.md section 6) | `adb` (platform-tools), Frida, `strace`, `ltrace` | Android SDK; frida.re; distro packages | Inside the isolated VM, under a session envelope. |

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
