# Native, managed and bytecode artifacts

Covers compiled code: native executables and libraries (ELF, Mach-O, PE), .NET
managed assemblies, Go and Rust binaries, and WebAssembly. Static and read-only;
work on a copy, cite the sample's SHA-256 on every finding.

## Start with the cheap passes

For any compiled file, the inventory often answers the question before you
decompile anything:

- `file <bin>`: format, architecture, stripped or not, static or dynamic.
- `strings -a -n 6 -- <bin> > "$W/out/strings.txt"`: embedded text (URLs, paths,
  format strings, version stamps, error messages, bundled library names) goes to a
  file, never the screen, because it can hold keys. Query it with `grep -c` and
  targeted `grep -o ... | cut -c1-120 | sort -u` (SKILL.md section 4). Bound your
  conclusions to what you searched.
- Imports / exports, what it calls out to, and what it offers:
  - ELF: `readelf -d`, `objdump -T`, `nm -D`.
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
    file itself, e.g. `strings -a -n 6 <bin> | grep -Ei
    'openssl [0-9]|libressl|boringssl|mbed ?tls|wolfssl|gnutls|libgcrypt|libsodium'`.
  - Confidence: a version string inside the file plus calls into its routines is
    high; a string alone is medium (it may be vendored but unused, or stale).
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
  **ILSpy** / `ilspycmd <assembly> -o <outdir>` to recover C#.
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
  a path). Check embedded resources and any shipped `*.config`/`appsettings*.json`.

## Go

- `go version -m <bin>` prints the Go version, main module, dependency modules
  and build settings straight from the binary, often the fastest answer to
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

- `wasm2wat <file>.wasm -o <file>.wat` for the text form; `wasm-objdump -x` for
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

- `unzip -l <jar>` to inventory; read `META-INF/MANIFEST.MF` (Main-Class,
  versions) and any `META-INF/maven/**/pom.properties` for component versions.
- `javap -c -p -v <Class>` disassembles bytecode and shows the constant pool.
  Decompile with **CFR** (`java -jar cfr.jar --outputdir $W/out/cfr <jar>`, which
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
- **Hard-coded endpoints and credentials:** one pipeline, straight to a mode-0600
  file, so no raw value reaches the screen (`$ROOT` is the decompiled tree):

  ```sh
  set -o pipefail; umask 077
  grep -rEoh -- "((https?|wss?|amqps?|rediss?|ldaps?|mongodb(\+srv)?|jdbc:[a-z0-9:]+)://[^ \"'<>]+|jdbc:oracle:thin:[^ \"'<>]+)" "$ROOT" \
  | sed -E "s#//[^/ \"']*@#//<cred>@#g; s#(thin:)[^@ \"']*@#\1<cred>@#g; s/((pass(word|wd)?|pwd|secret|token|api_?key|access_?key|access_token|client_secret|key|sig(nature)?|auth)=)[^&; \"']*/\1<redacted>/Ig" \
  | sort -u > "$W/out/endpoints.txt"
  ```

  It masks URL user-info (including a password containing `@`), the Oracle
  `user/pass@` form and common secret query parameters; `pipefail` makes a failed
  stage an error rather than an empty "no endpoints" file. A token embedded in a
  URL path (a webhook) cannot be detected generically, so treat `endpoints.txt` as
  secret-bearing: keep it at mode 0600, report hosts
  (`cut -d/ -f3 "$W/out/endpoints.txt" | sort -u`) rather than full URLs, and report
  a credential as file, key, type and length only (SKILL.md section 1).
- Dependencies for an SBOM: the `pom.properties` groupId/artifactId/version, or
  hashes of bundled jars matched against the operator's known-set.

## macOS bundles

A `.app` is a directory; a `.pkg`/`.dmg` wraps one. Read, never launch.

- `plutil -p <App>.app/Contents/Info.plist` for identifiers, versions and the
  executable name; the Mach-O is at `Contents/MacOS/<name>` (route it above).
- `codesign -dvvv --entitlements :- <App>.app` for the signing identity and the
  entitlements (pipe to `plutil -p -` to read them); `lipo -info <binary>` and
  `lipo -thin` to pick an architecture.
- **Signed and notarised?** `codesign -dvvv <App>.app 2>&1 | grep -E
  'Authority|TeamIdentifier|flags|Timestamp'` shows the Developer ID chain and the
  hardened-runtime flag. Notarisation that has been stapled: `xcrun stapler
  validate <App>.app`. `spctl -a -vv` needs Apple's online service, which the
  section 1 environment denies, so report "notarisation not determinable offline
  unless stapled". Also check the container's own signature: `codesign -dvvv
  <f>.dmg`. Do not trust `codesign --verify` on a `7zz` extract (it loses symlinks
  and xattrs); record that as a limit rather than mounting the image. A macOS host
  is needed for `codesign`/`spctl`; on Linux use `rcodesign print-signature-info`.
- `.pkg`: `pkgutil --check-signature` and `pkgutil --expand-full` (or `xar -xf`).
  `.dmg`: unpack with `7zz x` into `$W/extracted/`, do not `hdiutil attach`
  (that mounts it).
- ASAR, embedded frameworks and XPC services under `Contents/` are each their own
  target.

## Crash and core dumps

Read statically; a core holds process memory, so the secret rules (SKILL.md
section 1) apply in full.

- ELF core: `readelf -n core` lists the core notes (signal in `NT_PRSTATUS`,
  mapped files in `NT_FILE`); `eu-unstrip -n --core core` pairs each mapping with
  its build-id; `eu-stack --core core -e <bin>` gives a backtrace;
  `gdb -nx -iex "set auto-load off" --batch -ex bt -c core <bin>` (both `-nx` and
  `auto-load off`, and never `run`/`start`/`call`). Match the build-id to symbols
  before trusting frame names. `eu-*` are elfutils (Linux); run them in the Linux
  analysis VM.
- Windows minidump: Breakpad `minidump_stackwalk <dmp> <symbols>`, or the Python
  `minidump` library.
- macOS `.ips`/`.crash` are text (JSON for `.ips`): read with `jq`/`cat`;
  symbolicate with `atos` or `llvm-symbolizer`.
