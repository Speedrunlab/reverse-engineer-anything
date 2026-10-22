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
- Work from a seed: an exported symbol, a string's cross-reference, an import
  call site. Follow it outward only as far as the question needs.

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
  payloads of the same artifact (no new authority entry), unzipped and read in
  place.
- `jarsigner -verify -verbose -certs <jar>` reports signing; an unsigned or
  mismatched jar is a provenance finding.
- **Logging framework and version:** list `BOOT-INF/lib/*` (or the flat jar's
  entries) matching `log4j|logback|slf4j`; `slf4j` is only the facade, so report
  it separately from the implementation (log4j2, logback). Take the version from
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
  LC_ALL=C grep -rEaoh -- "((https?|wss?|amqps?|rediss?|ldaps?|mongodb(\+srv)?|jdbc:[a-z0-9:]+)://[^ \"'<>]+|jdbc:oracle:thin:[^ \"'<>]+)" "$1" \
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
  host-only list rather than full URLs
  (`grep -oE '(//|<cred>@)[A-Za-z0-9.-]+(:[0-9]+)?' "$W/out/endpoints-<name>.txt" | sed -E 's#^(//|<cred>@)##' | LC_ALL=C sort -u > "$W/out/host-list-<name>.txt"`), and report
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
- macOS `.ips`/`.crash` are text (JSON for `.ips`): read with `jq`/`cat`;
  symbolicate with `atos` or `llvm-symbolizer`.
