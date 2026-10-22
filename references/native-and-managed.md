# Native, managed and bytecode artifacts

Covers compiled code: native executables and libraries (ELF, Mach-O, PE), .NET
managed assemblies, Go and Rust binaries, and WebAssembly. Static and read-only;
work on a copy, cite the sample's SHA-256 on every finding.

## Start with the cheap passes

For any compiled file, the inventory often answers the question before you
decompile anything:

- `file <bin>`: format, architecture, stripped or not, static or dynamic.
- `strings -a -n 6 <bin>`: embedded text: URLs, paths, format strings, version
  stamps, error messages, bundled library names. Bound your conclusions to what
  you searched.
- Imports / exports, what it calls out to, and what it offers:
  - ELF: `readelf -d`, `objdump -T`, `nm -D`.
  - Mach-O: `otool -L` (linked libs), `otool -l`, `nm`.
  - PE: `objdump -x`, or a PE reader for the import/export tables.
- Sections and layout: `readelf -S` / `objdump -h`. An unexpected section, an
  executable-and-writable segment, or an oversized blob is worth a note.

Record the architecture and bitness: a decompiler needs the right language/
calling-convention, and a wrong guess produces confident nonsense.

## Decompilation (when a function's logic is the question)

- **Ghidra** (headless) is the default for serious decompilation. Import the
  binary, run auto-analysis, then pull pseudocode for the specific functions the
  question needs, not the whole program.
  - Drive it through its headless analyzer so no GUI is required; script the
    export of the functions you care about.
  - Pseudocode is a reconstruction, not source. Say so. Names, types and control
    flow are inferences unless symbols are present.
- **rizin / radare2** for quick disassembly, cross-references and scripting when
  you do not need full decompilation. `izz` (strings), `afl` (functions), `axt`
  (xrefs to an address), `pdf` (disassemble a function).
- Work from a seed: an exported symbol, a string's cross-reference, an import
  call site. Follow it outward only as far as the question needs.

## Managed (.NET / CLI)

- A PE whose imports are dominated by `mscoree`/CLR is managed. Decompile with
  **ILSpy** / `ilspycmd <assembly> -o <outdir>` to recover C#.
- Managed metadata usually preserves names and types, so the decompile is close
  to source. Still separate what the IL shows from what you infer about intent.
- Obfuscated assemblies (renamed symbols, control-flow flattening) are common;
  note obfuscation as an observation and keep conclusions bounded.

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
  tree as zlib-compressed JSON: read it with `rust-audit-info <bin>` or
  `cargo audit bin <bin>` (a raw section dump is just compressed bytes). A
  missing section is absence of that metadata, not proof of no dependencies.
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
