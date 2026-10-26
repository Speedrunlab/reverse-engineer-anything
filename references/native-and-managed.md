# Native, managed and bytecode artifacts

Covers compiled code: native executables and libraries (ELF, Mach-O, PE), .NET
managed assemblies, Go and Rust binaries, WebAssembly, Java, Apple bundles,
crash reports, Unity, Flutter, BEAM, GPU code, EVM bytecode, Linux kernel
modules and DOL executables. Static and read-only; work on a copy, cite the
sample's SHA-256 on every finding.

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
  - PE: `llvm-readobj --coff-imports --coff-exports <pe> > "$W/out/pe-tables-<name>.txt"`
    (LLVM; not in Apple's command-line tools) prints the import table (`Import {`
    blocks: the DLL, its lookup and address table RVAs, each function by name or
    ordinal), the **delay-load** descriptors (`DelayImport {` blocks: a DLL bound
    only when first called, so it is absent from the plain import list and still
    used) and the export directory (`Export {`: ordinal, name, RVA, or
    `ForwardedTo` another DLL). GNU `objdump -x` shows the plain import and
    export tables. Python `pefile` (pinned, hashed) reads the same directories
    (`DIRECTORY_ENTRY_IMPORT`, `DIRECTORY_ENTRY_DELAY_IMPORT`,
    `DIRECTORY_ENTRY_EXPORT`) and its `get_imphash()` is the import hash, an
    MD5 over the plain import table's `dll.function` names that sample
    catalogues key on (delay-loads excluded): compare it with the operator's
    known-set; a match is a lead about the build, not an identity.
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
- Code before the entry point, and the linker's mitigation declarations (PE):
  `llvm-readobj --coff-tls-directory --coff-load-config <pe> > "$W/out/pe-config-<name>.txt"`.
  A TLS directory whose `AddressOfCallBacks` is not zero names an array of
  callbacks the loader runs before the entry point, a finding on its own (read
  the array with `pefile` from `DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks`,
  or let Ghidra label it). The load configuration's `SecurityCookie`,
  `SEHandlerTable` and `SEHandlerCount` (SafeSEH, 32-bit only),
  `GuardCFFunctionTable` and `GuardFlags` (Control Flow Guard) are declarations
  the linker wrote, read like the ELF flags above: not proof the loader
  enforced them. An absent directory is absence of the declaration.
- Any architecture: `readelf -h` reads the class, byte order and machine of any
  ELF on any host, but `objdump -d` disassembles only targets its build knows
  (`binutils-multiarch`, or an `llvm-objdump` built with the targets you need:
  `llvm-objdump --version` lists them; Apple's build, reached as `xcrun llvm-objdump`
  since it is not on the PATH, has only AArch64, Arm, WebAssembly and x86).
  A section flagged `C` in `readelf -S` is compressed (zlib, or zstd with
  binutils 2.40+) and reads with `readelf -z -p <section>` or
  `llvm-readelf --decompress -p <section>`. Record machine, class and byte order
  with the finding.
- An entropy map (`binwalk -E`, or `entropy.py` from the archives guide, which
  needs no binwalk) places packed or encrypted regions in any file: a `.text`
  near 8 bits per byte is packed or encrypted, which bounds what `strings` and
  a disassembler can see until it is unpacked (statically, or not at all).

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
- **Is it signed, and by whom?** `codesign -dvvv` (Mach-O). PE, MSI, CAB and
  APPX: `osslsigncode verify -in <file> -CAfile <bundle> -TSA-CAfile <bundle> -ignore-cdp > "$W/out/sig-<name>.txt"`
  checks the Authenticode signature against a CA bundle the operator staged
  (`-ignore-cdp`, osslsigncode 2.8 or later, skips the CRL fetch the environment
  would block anyway; a timestamped signature needs `-TSA-CAfile`, or
  `-ignore-timestamp` to check the signer chain alone). The
  signer chain is readable offline without trusting any bundle:
  `osslsigncode extract-signature -pem -in <file> -out "$W/out/sig-<name>.pem"`,
  then `openssl pkcs7 -in "$W/out/sig-<name>.pem" -print_certs -noout -text | grep -E 'Subject:|Issuer:|Not (Before|After)'`
  (the timestamp countersignature is in the same PKCS#7). Revocation needs the
  network, which the section 1 environment denies: record revocation as "not
  checked". "Signed" says the bytes match a signature the file carries; who
  the signer is needs the operator's expected identity to compare against.
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
- **One function by name, no project:** `llvm-objdump -d --disassemble-symbols=<symbol> <bin> > "$W/out/dis-<name>-<symbol>.txt"`
  (tested; on macOS it is `xcrun llvm-objdump`, and `/usr/bin/objdump` there is the
  same LLVM binary, which rejects the GNU spelling; GNU binutils 2.32+ spells it
  `objdump -d --disassemble=<symbol>`)
  prints one function's disassembly, the cheapest seed-driven read before a
  Ghidra project. Mach-O symbols carry a leading underscore (`_main`), and a
  symbol that is not there is only a warning with exit 0 and an output file
  holding nothing but the header, so check the file has a body (tested). On a
  stripped binary give `--start-address=0x<hex>` and `--stop-address=0x<hex>` a range
  from the inventory (the `=` form with the `0x` prefix: the spaced form is
  rejected, and a value without `0x` is not read as hex).
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

**Peripheral registers.** In microcontroller firmware an absolute address in the
peripheral range (Cortex-M: `0x40000000` to `0x5FFFFFFF`, and the private
peripheral bus `0xE0000000` to `0xE00FFFFF`, whose System Control Space starts
at `0xE000E000`) is a register access. Name them with the chip's
CMSIS-SVD file (the vendor's, or the `cmsis-svd-data` collection) through
SVD-Loader-Ghidra (`SVD-Loader.py`, run from the Script Manager), which creates
the peripheral memory blocks and labels so the decompiler shows the register
instead of a bare constant. The chip is the operator's input (the board, the
datasheet, a part number in `strings`): an SVD for the wrong chip labels every
access plausibly and wrongly, so record the SVD file and its hash with each
finding that rests on it.

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
- **Who calls a method, who reads a field?** Dump the IL to one named file
  (`ilspycmd -il <assembly> > "$W/out/il-<name>.il"`) and grep it for the
  member's full name after `call`, `callvirt`, `newobj`, `ldftn`, `ldvirtftn`
  (a method taken as a delegate), `ldfld`, `stfld`, `ldsfld`, `stsfld`, `ldflda`
  and `ldsflda`: each hit is a static edge at an IL offset inside a
  named method, not a call that ran. A **ReadyToRun** image keeps that IL
  beside precompiled native code, so ILSpy reads it like any assembly; the
  native code is a start-up cache, never the only copy of the logic (unlike
  NativeAOT above).
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
- A universal Mach-O holds one Go build per slice and `go version -m` reads one
  file: `lipo -info <bin>` names the slices (`arm64e` is its own name, not
  matched by `arm64`) and `lipo -thin <arch> -output "$W/out/<name>-<arch>" <bin>`
  gives the slice to read; the same for `rust-audit-info` below.

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
- **Apple `.ips`** (macOS and iOS crash reports; `.crash` is the older text form)
  is two JSON documents: line 1 is the header, the rest is the body. Read the
  header with `head -n1 <f> | jq '{bug_type, app_name, app_version, os_version, timestamp}'`:
  `bug_type` `"309"` is a crash; other types (`"288"` is a stackshot) are not
  and have no crash body. The body (tested on a system report):
  `tail -n +2 <f> | jq '{procName, procPath, exception, termination, faultingThread, threads: (.threads | length), usedImages: (.usedImages | length)}'`
  gives the process, the exception (`type`, `codes`, and `signal` when the report
  has one), the termination
  (`namespace`, `indicator`, `code`, `flags`) and the faulting thread's index;
  `tail -n +2 <f> | jq -c '.threads[.faultingThread].frames[] | [.imageIndex, .imageOffset, .symbol]'`
  lists that thread's frames. A frame's address is
  `usedImages[imageIndex].base + imageOffset`, and `usedImages[]` carries each
  image's `base`, `size`, `uuid`, `arch`, `name` and `path` (one placeholder entry
  with `source` `"A"` and no name or path is normal; no frame points at it). Symbolicate
  offline with the binary or dSYM whose `dwarfdump --uuid` matches the image's
  `uuid`: `atos -o <binary or dSYM DWARF> -arch <arch> -l <base> <address>`
  (tested). `atos` reads `-l` and the addresses as hex with or without `0x`,
  and the report's `base` and `imageOffset` are decimal: convert the base and the
  sum `base + imageOffset` first (`printf '0x%x' <decimal>`), or a decimal value
  is read as a different address and names the wrong symbol (tested). An older
  text `.crash` report carries the same frames and image list; an address inside
  an ELF binary symbolicates with `llvm-symbolizer --obj=<bin> $(printf '0x%x' <addr>)`
  (Homebrew or a release LLVM; Apple's tools do not ship it), where `<addr>` is
  the first `LOAD` address from `readelf -l` plus the offset: that address is 0
  for most shared objects and PIEs, so the offset itself for those, and link base
  plus offset for a non-PIE executable; the runtime `base + imageOffset` names
  nothing for a PIE or
  shared object (the base is randomised) and equals link base plus offset for a
  non-PIE executable (tested on ET_DYN files linked at 0 and at 0x10000 and on an
  ET_EXEC). Symbol names printed inside the report are recorded claims, not
  verified; `asi` ("Application Specific Information"), `procLaunch` and every
  path are sample text (`cut -c1-200 | cat -v`), and paths carry user names:
  personal data to count.

## Unity IL2CPP

Unity ships either Mono (`<Game>_Data/Managed/Assembly-CSharp.dll`, the managed
route above) or IL2CPP: the C# compiled to native code in `GameAssembly.dll`,
`GameAssembly.so`, `libil2cpp.so` (Android) or `UnityFramework` (iOS), with the
names, types and string literals kept in `global-metadata.dat`
(`<Game>_Data/il2cpp_data/Metadata/` on desktop, `assets/bin/Data/Managed/Metadata/`
in an APK). The two files together are one target set (SKILL.md section 0).

- The metadata file starts with the magic `AF 1B B1 FA`, then its version as a
  32-bit integer at offset 4 (`od -An -t u4 -j 4 -N 4 global-metadata.dat`,
  tested on a fixture): 24 and its 24.x points are 2017.1 to 2020.1 builds, 27
  is 2020.2 to 2021.1, 29 is 2021.2 to 2022.3.32, 31 is 2022.3.33 to Unity 6.2,
  and 35 and up are Unity 6.3 onward (the Il2CppInspector version table maps
  each point release). The number picks the tool release to use and dates the
  build; a file without the
  magic is encrypted, obfuscated or not metadata at all.
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

## Linux kernel modules

A `.ko` is a relocatable ELF (`readelf -h`: `Type: REL`) whose `.modinfo`
section carries the module's declarations and whose tail may carry a signature.
Read, never `insmod`: a module is kernel code.

- **Declarations:** `readelf -p .modinfo <ko> > "$W/out/modinfo-<name>.txt"`
  prints the `key=value` strings on any host: `license`, `vermagic` (the kernel
  version and configuration it was built for), `depends`, `alias` (the devices
  it claims), `parm` and `parmtype` (its parameters), `srcversion`, `intree`,
  `name`. On Linux, `modinfo <ko>` (kmod) prints the same fields by name, plus
  `signer`, `sig_key` and `sig_hashalgo` when the file is signed, and
  `modinfo -F <field> <ko>` one of them; both take a file path and never load
  the module.
- **Symbol versions:** `readelf -SW <ko> | grep -E '__versions|__ksymtab|\.gnu\.linkonce\.this_module'`
  shows which tables exist (`-W` keeps long names whole; GNU `readelf` otherwise
  cuts them to 17 characters); `__versions` is 64-byte records (a CRC, then the
  symbol name) that `readelf -x __versions <ko>` dumps and, on Linux,
  `modprobe --show-modversions <ko>` lists one per line. The CRCs must match
  the target kernel's: a mismatch is a "built for another kernel" finding, not
  corruption.
- **Signature:** a signed module ends with the 28 bytes
  `~Module signature appended~\n`, preceded by a 12-byte descriptor (algorithm,
  hash, key-identifier type, signer and key-id lengths, big-endian signature
  length) and, before that, the PKCS#7 signature over the module bytes. Read it
  with this helper, saved and locked as `$W/scripts/modsig.py` (tested on a
  fixture):

  ```python
  # modsig.py <module.ko> [out.p7s]: read the appended Linux module signature trailer; optionally write the PKCS#7 bytes. Nothing is loaded.
  import struct, sys
  MAGIC = b"~Module signature appended~\n"
  data = open(sys.argv[1], "rb").read()
  if not data.endswith(MAGIC):
      print("no signature trailer (not proof the module is unsigned elsewhere)"); sys.exit(1)
  if len(data) < len(MAGIC) + 12:
      print("trailer magic present but the file is shorter than the 12-byte descriptor: truncated or not a module"); sys.exit(1)
  algo, hsh, id_type, signer_len, key_id_len, sig_len = struct.unpack(">BBBBB3xI", data[-len(MAGIC)-12:-len(MAGIC)])
  body_end = len(data) - len(MAGIC) - 12 - sig_len
  if sig_len == 0:
      print("descriptor says sig_len 0: no signature bytes, corrupt trailer, nothing written"); sys.exit(1)
  if body_end <= 0:
      print(f"descriptor says sig_len {sig_len} and {len(data) - len(MAGIC) - 12} byte(s) precede it: no module would remain (the kernel refuses this too), corrupt trailer, nothing written"); sys.exit(1)
  print(f"algo {algo} hash {hsh} id_type {id_type} ({'PKCS#7' if id_type == 2 else 'other'}) signer_len {signer_len} key_id_len {key_id_len} sig_len {sig_len}; signed module bytes 0..{body_end}")
  if len(sys.argv) > 2:
      if id_type == 2: open(sys.argv[2], "wb").write(data[body_end:body_end + sig_len]); print("PKCS#7 written to", sys.argv[2])
      else: print(f"id_type {id_type} is not PKCS#7 (2): nothing written")
  ```

  Run it as `"$W/scripts/run.sh" python3 -I "$W/scripts/modsig.py" <ko> "$W/out/sig-<name>.p7s"`,
  then the signer line,
  `"$W/scripts/run.sh" env LC_ALL=C bash -c 'set -o pipefail; openssl cms -cmsout -inform der -in "$1" -noout -print | sed -n "2p;/^ *signerInfos:/,/^ *digestAlgorithm:/p" | cat -v | cut -c1-200' _ "$W/out/sig-<name>.p7s"`,
  prints the content type and the first signer: by issuer and serial number, or
  by key identifier when the module was signed with `sign-file -k` (hex rows of
  15 bytes, so a `grep -A1` had shown 15 of its 20). Read its shape before its
  words, because every string in it is the sample's. Line 1 must read
  `contentType: pkcs7-signedData`; any other type (`undefined`, enveloped,
  digested) with signer-looking lines under it is a string field carrying fake
  print lines, which LibreSSL prints with their newlines, so report the shape and
  read no signer from it. Then exactly one `signerInfos:` line, and a
  `serialNumber:` or a hex row before `digestAlgorithm:`; two `signerInfos:`
  lines, or none of those rows, is forged or cut; `signerInfos:` followed by
  `<EMPTY>` is a SignedData with no signer; an empty result with exit 0 is a CMS
  with no `signerInfos` at all. `sign-file` writes exactly one signer; for a CMS
  with more signers, save the whole print,
  `"$W/scripts/run.sh" env LC_ALL=C bash -c 'openssl cms -cmsout -inform der -in "$1" -noout -print > "$2"' _ "$W/out/sig-<name>.p7s" "$W/out/cms-<name>.txt"`,
  count its `digestAlgorithm:` lines for the signer count and read it with
  targeted searches through `cat -v`. The `^ *` anchors keep a one-line issuer
  name that contains the words from ending the range early; `LC_ALL=C` around
  the whole shell keeps BSD `sed` from failing on a lone high byte LibreSSL
  prints, and makes `cat -v` show every byte OpenSSL 3.2 and later pass raw,
  such as a right-to-left override (3.0, 3.1 and LibreSSL escape them); `cut`
  bounds a line a megabyte-long issuer would stretch. OpenSSL 3.2.0 to 3.2.4,
  3.3.0 to 3.3.3 and 3.4.0 to 3.4.1 print a newline inside a name raw by their
  defaults, which lets a forged issuer hide the real serial inside the range, so
  on OpenSSL add `-nameopt esc_ctrl,esc_msb,utf8,sep_comma_plus_space` before
  `-print` (LibreSSL does not take the option; the windows come from
  `apps/lib/apps.c` at each tag and the 3.4.2 change note, the behaviour from
  3.0.17 and 3.4.1 built from the release tarballs); `pipefail` keeps `openssl`'s
  failure as the exit status, where a bare pipe reported the last stage's 0 for an
  unreadable file. The
  kernel's `sign-file` writes a detached CMS signature with no certificate
  inside, so `openssl pkcs7 -print_certs` prints nothing for a real module, and
  `openssl pkcs7` cannot load the key-identifier form at all (tested on both
  signature forms, a two-signer CMS, hostile issuers, forged string fields in a
  signed, an unsigned-type and an enveloped CMS, a lone high byte, and unreadable
  files, OpenSSL 3.6 and LibreSSL 3.3).
  does the same (`-d` prints the descriptor, `-0` writes the unsigned module).
  The signature is checked only by a kernel holding the signing key: here it is
  "present, signer X", never "valid". No trailer is absence of a trailer, not
  proof the module is unsigned in another package.
- **Compressed modules** (`.ko.xz`, `.ko.zst`, `.ko.gz`, as distributions ship
  them): decompress to a new file in `out/` first (`xz -dc -- <f> > "$W/out/<name>.ko"`,
  `gunzip -c <f> > "$W/out/<name>.ko"`, `zstd -d <f> -o "$W/out/<name>.ko"`; `xz -dk`
  and `gunzip -k` write beside the input, which is read-only here), hash both,
  and read the decompressed one; `modinfo` reads a
  compressed module itself when its kmod was built with that codec.
- `.text`, `.init.text` and `.exit.text` hold the code, and the `__ksymtab*`
  tables are data naming what it exports to other modules: route the file to
  the native sections above for the code.

## GameCube and Wii DOL

A `.dol` is the executable format of the GameCube and Wii: a 256-byte header of
up to 7 text and 11 data sections (file offset, load address, size, all
big-endian), one BSS range and the entry point, then the sections' bytes. It has
no magic: identify it by a header that makes sense (offsets inside the file,
load addresses inside the console's main memory, `0x80000000` to `0x81800000`,
the entry inside a text section), never by the extension alone. `file` has no
DOL entry and, for the usual layout whose first section starts at 0x100, prints
"Apple HFS/HFS+ resource fork" (tested): on a `.dol` that label is noise. Read the header
with this helper, saved and locked as `$W/scripts/dol-header.py` (tested on a
fixture):

```python
# dol-header.py <file.dol>: the 256-byte DOL header: 7 text + 11 data sections (file offset, load address, size), bss, entry
import struct, sys
h = open(sys.argv[1], "rb").read(0x100)
if len(h) < 0x100:
    print(f"{len(h)} bytes: shorter than the 256-byte DOL header, not a DOL"); sys.exit(1)
off = struct.unpack(">18I", h[0x00:0x48]); addr = struct.unpack(">18I", h[0x48:0x90]); size = struct.unpack(">18I", h[0x90:0xD8])
bss_addr, bss_size, entry = struct.unpack(">3I", h[0xD8:0xE4])
for i in range(18):
    if size[i]:
        print(f"{'text' if i < 7 else 'data'}{i if i < 7 else i-7}\tfile 0x{off[i]:x}\tload 0x{addr[i]:08x}\tsize 0x{size[i]:x}")
print(f"bss 0x{bss_addr:08x} size 0x{bss_size:x}\nentry 0x{entry:08x}")
```

For the code, Ghidra with the GameCube loader extension (Cuyler36's
`Ghidra-GameCube-Loader`, Apache 2.0; it loads DOL and REL files and
apploaders, maps each section at its address, and adds the
`PowerPC:BE:32:Gekko_Broadway` language) imports the file directly. Stock
Ghidra needs the sections placed by hand from the header above (`BinaryLoader`
loads one blob at one base), with the `PowerPC:BE:32:default` language, which
does not decode the paired-single instructions Gekko and Broadway add: those
show as bad or undefined. Record the language and the extension version with
every finding. A disc image is a container: extract the DOL from it first.

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
| one `node` binary whose strings hold `NODE_SEA_FUSE_...:1`, no `node_modules/` beside it | Node.js single executable | [JavaScript and Electron](javascript-and-electron.md#nodejs-single-executable-applications) |
