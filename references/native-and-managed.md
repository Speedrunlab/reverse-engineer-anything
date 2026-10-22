# Native, managed and bytecode artifacts

Covers compiled code: native executables and libraries (ELF, Mach-O, PE), .NET
managed assemblies, Go and Rust binaries, and WebAssembly. Static and read-only;
work on a copy, cite the sample's SHA-256 on every finding.

## Start with the cheap passes

For any compiled file, the inventory often answers the question before you
decompile anything:

- `file <bin>`: format, architecture, stripped or not, static or dynamic.
- `strings -a -n 6 -- <bin> > "$W/out/strings-<name>.txt"`: embedded text (URLs, paths,
  format strings, version stamps, error messages, bundled library names) goes to a
  file, never the screen, because it can hold keys; name it in the ledger as
  secret-bearing (SKILL.md section 1). Query it with `grep -c` and
  targeted `grep -o ... | cut -c1-120 | sort -u | cat -v` (SKILL.md section 4). Bound your
  conclusions to what you searched.
- Imports / exports, what it calls out to, and what it offers:
  - ELF: `readelf -d`, `objdump -T`, `nm -D` (the dynamic table only). For a
    statically linked binary use `nm <bin>` or `readelf -s <bin>` (the full symbol
    table; empty output means stripped).
  - Mach-O: `otool -L` (linked libs), `otool -l`, `nm`.
  - PE: `objdump -x`, or a PE reader for the import/export tables.
- Sections and layout: `readelf -S` / `objdump -h`. An unexpected section, an
  executable-and-writable segment, or an oversized blob is worth a note.
- Build identity: `readelf -n` (ELF notes: the GNU build-id and ABI tag),
  `dwarfdump --uuid` for a Mach-O (tested). It pairs a binary with its symbols,
  a crash or a vendor advisory; a missing note is absence of that record, not a
  statement about the build.
- Hardening: `checksec file <bin>` (the Go rewrite; older shell releases take
  `--file=<bin>`), or `readelf -l`/`-d` for `GNU_RELRO`, the `GNU_STACK` flags
  and `BIND_NOW`: RELRO, stack canary, NX, PIE, RPATH/RUNPATH and Fortify, each a
  static declaration.

Record the architecture and bitness: a decompiler needs the right language/
calling-convention, and a wrong guess produces confident nonsense.

On macOS, `readelf` and `nm -D` are not installed by default: use `llvm-readelf`
(from LLVM) or `$(brew --prefix binutils)/bin/readelf` (Homebrew `binutils`, keg-only); for Mach-O files use `otool` and
`nm`.

## Common questions

- **Which crypto (or other) library and version does it use?** First separate
  *linked* from *bundled*:
  - Linked: `readelf -d <bin> | grep NEEDED` (ELF), `otool -L` (Mach-O), the
    import table (PE). The library's own version is not in this file;
    `readelf -V` shows the symbol versions it requires (for example
    `OPENSSL_3.0.0`), which bounds it.
  - Bundled (statically linked): look for the library's version string in the
    file itself, printing only the name and version, never the whole line:
    `"$W/scripts/run.sh" bash -c 'strings -a -n 6 -- "$1" | grep -Eio "(openssl|libressl|boringssl|mbed ?tls|wolfssl|gnutls|libgcrypt|libsodium)[ /_-]?v?[0-9][0-9a-z.]*" | sort -u | cat -v' _ <bin>`.
  - Confidence: a version string inside the file plus calls into its routines is
    high; a string alone is medium (it may be vendored but unused, or stale). To
    show calls in a static binary, find the library's own functions (its symbols,
    or when stripped its error and function-name strings) and follow their
    cross-references to callers in Ghidra; a reference to the version string only
    reaches the library's version function.
- **What does it export or import?** The symbol and import tables above; record
  them to `$W/out/` and answer from the file.
- **Is it signed, and by whom?** `codesign -dvvv` (Mach-O); for PE, a signature
  reader such as `osslsigncode verify`. Revocation needs the network, which the
  section 1 environment denies, so any revocation lookup fails: record revocation
  as "not checked".
- **Version, icons and other Windows resources?** `wrestool -l <exe> > "$W/out/pe-res-<name>.txt"`
  (icoutils) lists resource types and names; `wrestool -x -t14 -o "$W/out/icons-<name>" <exe>`
  extracts the icon groups (a tree write, so an extraction). It does not decode
  version info (type 16): read `FileVersion` and `ProductVersion` as UTF-16
  strings with `strings -a -e l`, as the SBOM section of the archives guide does.

## Decompilation (when a function's logic is the question)

- **Ghidra** (headless) is the default for serious decompilation. Import the
  binary, run auto-analysis, then pull pseudocode for the specific functions the
  question needs, not the whole program.
  - Drive it through its headless analyzer so no GUI is required; script the
    export of the functions you care about.
  - Pseudocode is a reconstruction, not source. Say so. Names, types and control
    flow are inferences unless symbols are present.
- **rizin / radare2** for quick disassembly, cross-references and scripting when
  you do not need full decompilation. Run `aaa` (analysis) first; then `izz`
  (strings), `afl` (functions), `axt` (xrefs to an address), `pdf` (disassemble a
  function). Send large listings to a file in `$W/out/`.
- A licensed IDA, Binary Ninja or Hopper works under the same rules (never on
  the credentialed host; version recorded with each finding). Opening a file in
  any decompiler is static; only running the target is live.
- Work from a seed: an exported symbol, a string's cross-reference, an import
  call site. Follow it outward only as far as the question needs.

## Headerless code (raw blobs, bootloaders, DOS)

A blob carved from firmware with no ELF, PE or Mach-O header loads only with an
architecture and a base address you supply:
`analyzeHeadless <project-dir> <project> -import <blob> -processor <language id, e.g. ARM:LE:32:Cortex> -loader BinaryLoader -loader-baseAddr 0x08000000 -postScript <export script>`
(headless loader arguments take the `-loader-<name>` form). Both values are
inferences from the firmware map (the vector table, strings referenced by
absolute address, the chip named by the board or datasheet): record them with
every finding and check them against cross-references that resolve, because a
wrong base produces plausible nonsense. A DOS MZ executable imports with
Ghidra's own loader; a headerless `.com` is a raw 16-bit image loaded at `0x100`.

## Managed (.NET / CLI)

- A PE whose imports are dominated by `mscoree`/CLR is managed. Decompile with
  **ILSpy** / `ilspycmd <assembly> -o "$W/out/ilspy-<name>"` to recover C# (an
  extraction: SKILL.md section 1 checks apply, with that directory as `$ROOT`).
  String literals in .NET are UTF-16 in the `#US` heap, which plain `strings`
  misses: search the decompile, or use GNU `strings -a -e l` (binutils).
- Managed metadata usually preserves names and types, so the decompile is close
  to source. Still separate what the IL shows from what you infer about intent.
- Obfuscated assemblies (renamed symbols, control-flow flattening) are common;
  note obfuscation as an observation and keep conclusions bounded.
- A .NET **NativeAOT** image has no CIL: `ilspycmd` finds no managed metadata and
  `strings` shows .NET type names in a native binary. Treat it as native
  (Ghidra); the pseudocode is a reconstruction of compiled code, not C#, and the
  type names and frozen string literals it keeps are the useful map. A
  **single-file** bundle (one large exe, no `*.dll` beside it) still holds CIL:
  ILSpy opens it.
- **What config does it read, and what does it do with the values?** Grep the
  decompiled tree for `ConfigurationManager`, `AppSettings`, `GetSection`,
  `GetConnectionString`, `ConnectionStrings`, `IConfiguration`, `GetValue<`,
  `.Bind(`, `.Get<`, `services.Configure<`, `IOptions<`, `IOptionsSnapshot<`,
  `IOptionsMonitor<`, `Environment.GetEnvironmentVariable`, and file reads
  (`File.ReadAllText`, `XmlDocument.Load`, `JsonSerializer`). Keys bound through an
  options class are the class's property names, not string literals, so read the
  bound type. For
  each key, trace its default and where the value flows (a connection, a branch,
  a path). Check embedded resources, and any `*.config`/`appsettings*.json`
  that is part of the approved target; a file merely sitting next to a lone DLL is
  a separate artifact (SKILL.md section 0): ask before reading it.
- **Which external services does it call?** Run `endpoints.sh` (Java and JVM,
  below) on the decompiled tree for candidate URLs and connection strings, then
  find the call sites: `HttpClient`, `WebRequest`, `SqlConnection`, gRPC and
  WCF clients. Answer as "the code can contact", each with its call site.

## Go

- `go version -m <bin> > "$W/out/go-version-<name>.txt"` records the Go version, main
  module, dependency modules and build settings straight from the binary (build
  settings can carry `-ldflags -X` values, so name the file secret-bearing and query
  it), often the fastest answer to
  "what is this built from".
- Go binaries are large and statically linked; `strings` surfaces package paths.
  For logic, use a current Ghidra release: it recovers Go function names and
  types itself. Older releases needed a separate plugin and mislabelled Go's
  calling convention, so record the Ghidra version with the finding.

## Rust

- If built with `cargo auditable`, the `.dep-v0` section lists the dependency
  tree as zlib-compressed JSON: read it with `rust-audit-info <bin>`, which works
  offline. (`cargo audit` fetches an advisory DB over the network and reports
  vulnerabilities, not an inventory, so it is not used here.) A missing section is
  absence of that metadata, not proof of no dependencies.
- Otherwise treat it as a native binary (Ghidra/rizin); Rust's monomorphised,
  inlined code is dense, so stay seed-driven.

## WebAssembly

- `wasm2wat <file>.wasm -o "$W/out/<name>.wat"` for the text form; `wasm-objdump -x` for
  the import/export/section inventory. `wasm-decompile` (a C-like view) shipped
  in WABT 1.0.41 and earlier and was removed after; pin that version if you want it.
- Note the imports (what the host must provide) and exports (the module's API).
  WAT is a faithful text of the bytecode, not original source.
- A `.wasm` referenced by JavaScript glue: keep the glue and the module together,
  and record which paths or URLs were ambiguous rather than resolving them by
  guess.

## Pitfalls

- A stripped binary has no symbol names; everything is positional. Do not invent
  function names as if they were recovered.
- Decompiler output varies by version and settings, record both, so a finding
  is reproducible.
- "Uses library X" from a string or an import is linkage, not proof a code path
  runs. Show the call site before claiming behaviour.

## Java and JVM

`.jar`, `.war` and `.ear` are zip archives; `.class` is bytecode. Never `java -jar`
a sample.

- `unzip -l <jar> | cat -v` to inventory; read `META-INF/MANIFEST.MF` (Main-Class,
  versions) and any `META-INF/maven/**/pom.properties` for component versions.
- `javap -c -p -v <Class> > "$W/out/javap-<name>.txt"` disassembles bytecode and
  the constant pool, where string constants (keys included) appear in full: name
  the file secret-bearing and query it with `grep -c` and `grep -o ... | cut -c1-120`.
  Decompile with **CFR** (`java -jar cfr.jar --outputdir $W/out/cfr-<name> <jar>`, which
  writes files instead of flooding stdout) or **Vineflower**; JADX also reads
  `.jar`. Treat decompiler output as a reconstruction.
- A Spring Boot fat jar nests dependencies under `BOOT-INF/lib/*.jar`; those are
  payloads of the same artifact (no new authority entry): unzip each into its own
  new extraction root (an extraction, SKILL.md section 1), or stream one member
  out with `unzip -p` as a single named file.
- `jarsigner -verify -verbose -certs <jar>` reports signing; an unsigned or
  mismatched jar is a provenance finding.
- **Logging framework and version:** list `BOOT-INF/lib/*` (or the flat jar's
  entries) matching `log4j|logback|slf4j`. The implementation is `logback-classic`
  (Logback) or `log4j-core` (Log4j 2). `slf4j-api` is the facade, and `log4j-api`,
  `log4j-to-slf4j`, `jul-to-slf4j`, `log4j-slf4j*-impl` and `logback-core` are
  APIs, bridges or bindings: list them separately, and never report Log4j 2 as the
  framework unless `log4j-core` is present (a default Spring Boot jar ships
  `log4j-api` and `log4j-to-slf4j` with Logback as the implementation). Take the version from
  the nested jar's `MANIFEST.MF` `Implementation-Version` or its `pom.properties`,
  not the filename alone.
- **Hard-coded endpoints and credentials:** one helper, saved and locked as
  `$W/scripts/endpoints.sh` (SKILL.md section 1), writing straight to a mode-0600
  file so no raw value reaches the screen:

  ```sh
  #!/usr/bin/env bash
  # endpoints.sh <tree> <out-file>: endpoint URLs with credentials masked.
  # Needs GNU sed for the I flag: the Linux VM's sed, or SED=gsed on macOS.
  set -o pipefail; umask 077
  SED="${SED:-sed}"
  "$SED" --version >/dev/null 2>&1 || { echo "endpoints.sh: needs GNU sed" >&2; exit 2; }
  LC_ALL=C grep -rEaoh -- "((https?|wss?|amqps?|rediss?|ldaps?|mongodb(\+srv)?|jdbc:[a-z0-9:]+)://[^ \"'<>[:cntrl:]]+|jdbc:oracle:thin:[^ \"'<>[:cntrl:]]+)" "$1" \
  | "$SED" -E "s#//[^/?# \"']*@#//<cred>@#g; s#(thin:)[^@ \"']*@#\1<cred>@#g; s/((pass(word|wd)?|pwd|secret|token|api_?key|access_?key|access_token|client_secret|key|sig(nature)?|auth)=)[^&; \"']*/\1<redacted>/Ig" \
  | sort -u > "$2"
  ```

  Run it as `"$W/scripts/run.sh" "$W/scripts/endpoints.sh" "$ROOT" "$W/out/endpoints-<name>.txt"`,
  with `$ROOT` set to the tree searched: an extraction root, or a decompiler's
  output tree under `$W/out/`, which gets the same SKILL.md section 1 link step
  first. It masks URL user-info (including a password
  containing `@`), the Oracle `user/pass@` form and common secret query parameters.
  Exit 1 with an empty file means nothing matched; exit 2 is an error (a missing
  tree, or no GNU sed), never "no endpoints". For a credential's location, list
  the files with `grep -rEl` and the same pattern. A token embedded in a
  URL path (a webhook) cannot be detected generically, so treat `endpoints-<name>.txt`
  as secret-bearing (mode 0600, never handed over) and report hosts from the
  host-only list rather than full URLs (review it first: a user-info holding a raw
  `/`, invalid in a URL but seen, is not masked and would show as `user:digits`)
  (`LC_ALL=C grep -aoE '(//|<cred>@)(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?(,(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?)*' "$W/out/endpoints-<name>.txt" | sed -E 's#^(//|<cred>@)##' | tr ',' '\n' | LC_ALL=C sort -u > "$W/out/host-list-<name>.txt"`), and report
  a credential as file, key, type and length only (SKILL.md section 1).
- Dependencies for an SBOM: the `pom.properties` groupId/artifactId/version, or
  hashes of bundled jars matched against the operator's known-set.

## macOS bundles

A `.app` is a directory; a `.pkg`/`.dmg` wraps one. Read, never launch.

- `plutil -p <App>.app/Contents/Info.plist > "$W/out/info-plist-<name>.txt"`, then grep
  it for identifiers, versions and the executable name (`CFBundle`) rather than
  reading it whole, since custom keys can hold API keys (name the file
  secret-bearing); the Mach-O is at
  `Contents/MacOS/<name>` (route it above).
- `codesign -dvvv --entitlements :- <App>.app` for the signing identity and the
  entitlements (pipe to `plutil -p -` to read them); `lipo -info <binary>` and
  `lipo -thin <arch> <binary> -output "$W/out/<name>-<arch>"` to pick an architecture.
- **Signed and notarised?** `codesign -dvvv <App>.app > "$W/out/codesign-<name>.txt" 2>&1`,
  then `grep -E 'Authority|TeamIdentifier|flags|Timestamp|not signed' "$W/out/codesign-<name>.txt"`
  shows the Developer ID chain and the hardened-runtime flag, or "code object is
  not signed at all" for an unsigned bundle (a real answer, not a tool failure;
  reproduced on an unsigned test bundle). `<App>.app` is the bundle at
  `$W/original/target` (codesign and plutil only read it; batch reads use the
  extracted copy, SKILL.md section 1). Notarisation that has been stapled: `xcrun stapler
  validate <App>.app`. `spctl -a -vv` needs Apple's online service, which the
  section 1 environment denies, so report "notarisation not determinable offline
  unless stapled". Also check the container's own signature: `codesign -dvvv
  <f>.dmg`. Do not trust `codesign --verify` on a `7zz` extract (it loses symlinks
  and xattrs); record that as a limit rather than mounting the image. A macOS host
  is needed for `codesign`/`spctl`; on Linux use `rcodesign print-signature-info`.
- `.pkg`: `pkgutil --check-signature` and `pkgutil --expand-full` (or `xar -xf`).
  `.dmg`: unpack with `7zz x` into `$W/extracted/`, do not `hdiutil attach`
  (that mounts it).
- ASAR, embedded frameworks and XPC services under `Contents/` are payloads of the
  same app (no new approval, SKILL.md section 5): route each separately.
- **Classes and methods (Objective-C and Swift):** `otool -ov <bin> > "$W/out/objc-<name>.txt"`
  dumps the Objective-C runtime metadata (class, method and protocol names;
  tested, 1,121 named entries in a system app); `nm <bin> | swift demangle > "$W/out/swift-syms-<name>.txt"`
  restores Swift names when the binary is not stripped. Names map the code; they
  are not evidence that a path runs. A header generator (`dsdump`, `class-dump`)
  writes a tree, an extraction.
- **What it loads:** `otool -L <bin>` lists the libraries each executable links and
  `otool -l <bin> | grep -A2 LC_RPATH` the `@rpath` search paths (tested); resolve
  `@executable_path` and `@loader_path` against the bundle layout. A library that
  resolves nowhere in the bundle comes from the system (the dyld shared cache) or
  is missing: a finding either way. `dwarfdump --uuid <bin>` is the build UUID.
- **Interface files and asset catalogs:** compiled `.nib`/`.storyboardc` and
  `NSKeyedArchiver` files are binary plists, so `plutil -p <file>` reads them
  (class names and outlets, not source); `assetutil --info <Assets.car> > "$W/out/assets-<name>.json"`
  (built into macOS; tested) lists each asset's name, size and appearance without
  decoding images.
- **iOS `.ipa`:** a ZIP: `7zz x` into a new extraction root; `Payload/<App>.app/`
  holds `Info.plist`, the Mach-O, `Frameworks/`, `PlugIns/` (extensions) and
  `embedded.mobileprovision` (the signing profile, a plist inside a CMS wrapper:
  `openssl smime -inform der -verify -noverify -in embedded.mobileprovision 2>/dev/null | plutil -p -`,
  which names the team, the entitlements and the provisioned devices, the last a
  list of personal data to count, not quote). An App Store binary is
  FairPlay-encrypted: `otool -l <bin> | grep -A4 LC_ENCRYPTION_INFO` showing
  `cryptid 1` means the code is not readable statically, and decrypting it is out
  of scope; a developer or enterprise build (`cryptid 0`) reads like any Mach-O.

## Crash and core dumps

Read statically; a core holds process memory, so the secret rules (SKILL.md
section 1) apply in full.

- ELF core: `readelf -n core > "$W/out/core-notes-<name>.txt"` lists the core notes
  (signal in `NT_PRSTATUS`, mapped files in `NT_FILE`, and the process command
  line, which can hold a secret, so query the file); `eu-unstrip -n --core core` pairs each mapping with
  its build-id; `eu-stack --core core -e <bin>` gives a backtrace;
  `gdb -nx -iex "set auto-load off" -iex "set print frame-arguments none" --batch -ex bt -c core <bin> > "$W/out/bt-<name>.txt"`
  (both `-nx` and `auto-load off`, never `run`/`start`/`call`, and never `bt full`:
  frame arguments and locals can hold passwords). The file is secret-bearing
  (its "Core was generated by" line repeats the process's arguments): name it in
  the ledger, and read it with
  `grep -v '^Core was generated' "$W/out/bt-<name>.txt" | cut -c1-200 | cat -v`. Match the build-id to symbols
  before trusting frame names. `eu-*` are elfutils (Linux); run them in the Linux
  analysis VM.
- Windows minidump: Breakpad `minidump_stackwalk <dmp> <symbols>`, or the Python
  `minidump` library.
- macOS `.ips`/`.crash` are text (JSON for `.ips`): select fields with `jq` or
  `grep`, and read the result with `cut -c1-200 | cat -v` (the "Application
  Specific Information" is sample-controlled);
  symbolicate with `atos` or `llvm-symbolizer`.

## Unity IL2CPP

Unity ships either Mono (`<Game>_Data/Managed/Assembly-CSharp.dll`, the managed
route above) or IL2CPP: the C# compiled to native code in `GameAssembly.dll`,
`GameAssembly.so`, `libil2cpp.so` (Android) or `UnityFramework` (iOS), with the
names, types and string literals kept in `global-metadata.dat`
(`<Game>_Data/il2cpp_data/Metadata/` on desktop, `assets/bin/Data/Managed/Metadata/`
in an APK). The two files together are one target set (SKILL.md section 0).

- **Il2CppDumper** (open source, .NET) parses both in memory and runs nothing:
  `Il2CppDumper <code binary> <global-metadata.dat> "$W/out/il2cpp-<name>"` (on
  Linux or macOS, `dotnet Il2CppDumper.dll ...`). It writes `dump.cs` (every class,
  method and field with its code offset), `stringliteral.json` (secret-bearing:
  query it), `script.json` and `il2cpp.h` (for its Ghidra and IDA scripts, which
  apply the names) and `DummyDll/` (name-only stub assemblies ILSpy can open; no
  method bodies). A tree write, so an extraction under SKILL.md section 1.
- Names come from the metadata, bodies are native: decompile a chosen method in
  Ghidra at the offset `dump.cs` gives, after running the script that applies the
  names. A metadata file the tool rejects as invalid is encrypted or obfuscated:
  record that and stop there; decrypting it is out of scope.

## Flutter (Dart AOT)

`libapp.so` (per ABI in an APK; `App.framework/App` on iOS; `app.so` on desktop)
is the Dart ahead-of-time snapshot of the app's own code; `libflutter.so` or
`Flutter.framework` is the engine. The snapshot is not Java and not
decompilable to Dart source, so the triage facts matter:

- **Snapshot hash**, 32 hex characters 20 bytes after the magic `f5 f5 dc dc`,
  which identifies the exact Dart SDK build (tested on a fixture):

  ```sh
  python3 -I - <libapp.so> <<'EOF'
  import re, sys
  d = open(sys.argv[1], "rb").read()
  for m in re.finditer(b"\xf5\xf5\xdc\xdc", d):
      h = d[m.start()+24:m.start()+56]
      print(f"magic at {m.start()}: snapshot_hash", h.decode() if re.fullmatch(rb"[0-9a-f]{32}", h) else "<not hex>")
  EOF
  ```

  Map the hash to a Dart or Flutter release with a table the operator staged (the
  reFlutter project publishes one); no lookup happens here. The VM and isolate
  snapshots in one file carry the same hash.
- **Engine identity:** `readelf -n libflutter.so` for the build-id, and any
  `Dart VM version` string (release engines often strip it).
- **Dependency inventory:** the snapshot's string pool names every Dart file:
  `strings -a -n 8 -- <libapp.so> | grep -oE 'package:[A-Za-z0-9_]+' | sort | uniq -c | sort -rn | head -50`
  lists the packages, and `dart:` URIs the SDK libraries used.
- **Names and more:** Blutter (open source) recovers class and function names
  and the object pool, but it builds a Dart runtime at the exact SDK version
  first, fetching that source: do that when the analysis image is built, never in
  the analysis environment. `flutter_assets/` (asset and font manifests, bundled
  JSON) is readable data; a `kernel_blob.bin` means a debug build whose Dart
  kernel is far richer than an AOT snapshot.

## Erlang and Elixir (BEAM)

A `.beam` file (a release ships them under `lib/<app>-<version>/ebin/`; Elixir
modules are `Elixir.<Module>.beam`) is an IFF container (`FOR1` magic, `BEAM`
form) whose chunks hold the atom table (`AtU8`), exports, imports, lambdas, the
code, literals, and `CInf` compile info (source path, compiler version). `Dbgi`
or `Abst`, when the build kept debug info, holds the abstract code, which prints
back as readable source.

- Read the chunks with OTP's `beam_lib`, which parses the file without loading
  the module: `erl -noshell -eval 'io:format("~p~n", [beam_lib:chunks("<abs>.beam", [exports, imports, attributes, compile_info])]), halt().' > "$W/out/beam-<name>.txt"`;
  `[abstract_code]` returns the AST when debug info exists, and `erl_pp:form/1`
  prints it. The Erlang runtime runs; nothing from the sample does.
- Without a runtime, `strings -a -n 3` on the file still lists the atoms, which
  are the module, function and record names.

## GPU code objects (CUDA, HIP)

A host binary or library can carry GPU code: a CUDA fatbin (one cubin ELF per
`sm_XX` plus PTX text) or a Clang offload bundle for HIP (AMDGPU code objects
per `gfx9xx`). The tools are the vendors' own toolkits (free, not open source;
install them into the analysis image like any other tool).

- **Inventory first:** `cuobjdump --list-elf --list-ptx <file> > "$W/out/cuobjdump-<name>.txt"`
  on an executable, `.so`, `.a`, `.o` or standalone fatbin. `cuobjdump -xptx all <file>`
  and `-xelf all <file>` write every PTX and cubin into the current directory, so
  run them from the run directory as an extraction; `cuobjdump -ptx <file>` and
  `cuobjdump -sass <file>` print PTX and SASS to stdout (one named file in
  `out/`); `nvdisasm <cubin>` disassembles a single cubin.
- **HIP:** `roc-obj-ls -v <exe>` lists the code objects as URIs, `roc-obj-extract '<uri>'`
  writes one (quote it: the URI contains `&`), and
  `clang-offload-bundler --list --input=<bundle> --type=o` lists a bundle's entries.
- The facts are kernel names (`.entry` in PTX, the symbols of a cubin), parameter
  counts and shared-memory declarations, and the targets present. A target in the
  binary says what it can run on, not what ran.

## EVM bytecode

A deployed contract's runtime bytecode, as hex text or raw bytes the operator
supplies (nothing is fetched from a chain, an explorer or IPFS).

- `cast selectors <bytecode> > "$W/out/selectors-<name>.txt"` (Foundry; offline)
  lists the 4-byte function selectors with inferred argument types and
  mutability, and `cast disassemble <bytecode>` prints the opcodes. Its `--resolve`
  flag looks names up on a public service: never use it here. Record the
  selectors; the operator can resolve them outside.
- Selectors and types are inferences from the dispatcher, not a verified ABI. The
  trailing CBOR metadata (`ipfs`, `solc` fields) is a declaration, not a verified
  compiler or source identity, and the Keccak code hash is not the file's SHA-256.
  Init code and runtime code are different artifacts: say which you have.

## What is this app built with

For an installed application directory whose runtime is unknown, the files
beside the main executable usually say (path conventions: low confidence until
`file` and the executable's imports confirm them):

| Marker | Runtime | Route |
|---|---|---|
| `resources/app.asar` or `resources/app/`, `*.pak`, `libffmpeg` | Electron | [JavaScript and Electron](javascript-and-electron.md) |
| `*.deps.json`, `*.runtimeconfig.json`, `System.*.dll` | .NET | Managed, above |
| `jre/`, `runtime/lib/modules`, `lib/*.jar` beside a launcher | Java (jpackage) | Java and JVM, above |
| `Qt6Core.dll`/`Qt5Core.dll`/`libQt*`, `qt.conf`, `qml/` | Qt (C++) | native, above |
| `<Game>_Data/`, `UnityPlayer.dll`/`libunity.so`, `GameAssembly.*` or `Managed/` | Unity | Unity IL2CPP or Managed, above |
| `Engine/`, `<Game>/Content/Paks/*.pak`, `UnrealEngine` in strings | Unreal (C++) | native; assets in `.pak` |
| `.pck`, or an executable with a PCK trailer | Godot | [archives guide](firmware-and-archives.md#installers-and-os-packages) |
| `libflutter.so`/`flutter_windows.dll`, `flutter_assets/`, `app.so` | Flutter | Flutter, above |
| `_internal/` with `base_library.zip`, `python3NN.dll` | PyInstaller | [archives guide](firmware-and-archives.md#installers-and-os-packages) |
| `WebView2Loader.dll` beside a small executable | Tauri or another WebView2 host (Rust or .NET, web assets embedded) | native or Managed, above |
| `node_modules/`, `package.json`, a Node binary | Node application | [JavaScript and Electron](javascript-and-electron.md) |
