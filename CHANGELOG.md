# Changelog

Reverse Engineer Anything. Newest first.

## v1.15.0 (25 Oct 2026)

Coverage pass against release 6.8.0 (25 Oct 2026) of REA by @morluto, the
project this skill was inspired by (not affiliated): its new target types and
inspections were lined up against the routes here and the gaps filled, each as
the same static, read-only, evidence-first recipe on standard tools.

- New routes: Linux kernel modules (`.modinfo`, `__versions`, the appended
  signature trailer, compressed `.ko`), Node.js single-executable applications
  (the fuse string; the blob in a Mach-O section, an ELF note or a PE resource;
  then the JavaScript route), flattened devicetrees (`fdtdump`, `dtc`, `fdtget`,
  FIT images), GameCube and Wii DOL executables (a header reader, Ghidra with
  the GameCube loader), and Apple `.ips` crash reports read with `jq` and
  symbolicated offline with `atos`.
- PE: import, delay-load and export tables and the import hash; TLS callbacks
  and the load configuration (SafeSEH, CFG, the security cookie) as linker
  declarations; the signer chain offline from an extracted Authenticode
  signature; any-architecture ELF reading; compressed sections; one function
  by name with `objdump`.
- Firmware: peripheral registers named from a CMSIS-SVD file (SVD-Loader); an
  entropy map for any file.
- Managed, Go, Rust, Unity: IL call and field-access edges; ReadyToRun images;
  a universal Mach-O thinned before `go version -m` and `rust-audit-info`; the
  IL2CPP metadata magic and version.
- Android: compile-time constants (`static final` values) and their inlining.
- Captures: protobuf and gRPC bodies decoded with `protoc --decode_raw`, the
  gRPC frame and the gRPC-web forms.
- Model files and bytecode: header readers for safetensors and GGUF (and
  `gguf-dump`), the ambiguity of early GGUF type numbers, the `.pyc` header
  (magic, hash-based or timestamp).
- Evidence: each reconstruction claim gets one outcome (passed, failed, not
  applicable, could not be tested).
- Toolchain: nine rows added, three amended.

Tested here on fixtures built for the purpose or on a system file: the `.ips`
reads and `atos`, `segedit` extraction of a Mach-O section, the ELF note
extractor, the module-signature trailer reader, the DOL header reader, the
safetensors and GGUF header readers, the `.pyc` header reader, the entropy
helper, `llvm-objdump --disassemble-symbols`, the gRPC frame strip and the
IL2CPP version read. Not run here (tool absent on this host; command forms
checked against each tool's own documentation or source): `llvm-readobj`,
`pefile`, `osslsigncode extract-signature`, `modinfo`,
`modprobe --show-modversions`, `fdtdump`, `dtc`, `fdtget`, `protoc`,
`gguf-dump`, `wrestool --raw`, SVD-Loader, the GameCube loader.

Deliberately not replicated, as before (the toolkit, not the analysis): agent
environments served from a capture, retained summaries and evidence paging,
recovery settings and the JSON Lines output.

## v1.14.0 (23 Oct 2026)

Coverage pass: the target types a general reverse-engineering toolkit is
expected to handle were listed against the routes here, and the missing ones
added, each as the same static, read-only, evidence-first recipe.

- New routes: Unity IL2CPP (`global-metadata.dat` + `GameAssembly`), Flutter
  (Dart AOT snapshot hash, engine build-id, package inventory), Erlang/Elixir
  BEAM, GPU code objects (CUDA fatbin, HIP bundles), EVM contract bytecode
  (selectors, offline), Godot PCK, HarmonyOS packages, and logic-analyser
  recordings (sigrok-cli).
- Apple: iOS `.ipa` (provisioning profile, FairPlay encryption as a stated
  limit), Objective-C and Swift names, `@rpath` resolution, compiled nibs, asset
  catalogs and keyed archives.
- Electron: fuses read from the binary (pinned `@electron/fuses`, or the raw
  wire), the renderer isolation surface (BrowserWindow preferences, preload and
  contextBridge, IPC channel pairing, `.node` modules), an unminifier, and
  scripts extracted from a HAR for static analysis.
- Android: scheme-by-scheme signing output and key-rotation lineage; markers for
  Flutter, Unity, .NET for Android and React Native inside an APK.
- Native: build identity (`readelf -n`, `dwarfdump --uuid`), hardening checks,
  Windows resources (`wrestool`), .NET NativeAOT and single-file bundles,
  headerless blobs in Ghidra (`BinaryLoader` with an explicit base), licensed
  decompilers under the same rules, and a table of runtime markers for an
  installed app.
- Captures: `tshark -G fields` and decode-as, Fiddler SAZ as a ZIP, QUIC qlog
  event summaries; an owned Android device and instrumentation named as live
  steps.
- Evidence: pairing functions across two builds (BinDiff, Version Tracking),
  call paths bounded by indirect calls, and verifying a reconstruction against a
  finite claim list.
- Toolchain: seventeen rows added, each with its source and what it does and
  does not do.

Tested here on fixtures or a system binary: the snapshot-hash reader, the fuse
wire check, the HAR script extraction, the qlog summary, `otool -ov`,
`dwarfdump --uuid`, `LC_RPATH`, `assetutil --info` and `swift demangle`. Not run
here (tool absent on this host; command forms checked against each tool's own
documentation): Il2CppDumper, gdre_tools, cast, cuobjdump, roc-obj-ls, erl,
sigrok-cli, checksec, wrestool, bindiff, wakaru, electron-fuses, ark_disasm,
hermes-dec, apksigner.

## v1.13.0 (23 Oct 2026)

Hardening round 13: Linux packages, HAR exports, AppImage and Java jars walked end
to end, proven findings only (7 medium reproduced or shown by quoting both
passages). Every route the skill covers has now been walked at least once.

- Three v1.12.0 commands were wrong (each reproduced, each fixed and re-tested):
  the core-dump mask stopped at an apostrophe inside the arguments (it now masks
  to the end of the line); the host-list `grep` lacked `-a`, so one NUL byte
  turned it into "Binary file ... matches" (now `LC_ALL=C grep -a`); and the
  `hosts.sh` user-info class could swallow a real host after a NUL or a comma
  (now restricted to user-info characters, `@` kept for passwords). `endpoints.sh`
  stops a capture at control bytes.
- AppImage has its own route row (`file` reports only ELF).
- Logging frameworks: `logback-classic` or `log4j-core` is the implementation;
  `log4j-api`, `log4j-to-slf4j` and the other bridges are listed separately, so
  a default Spring Boot jar is not reported as Log4j 2.
- HAR credentials are counted per host with case-insensitive header names (an
  exact `Authorization` match missed a lower-case `cookie`; reproduced).
- A credential only counted, its value never read, is reported in the answer; a
  recovered value that may be live remains a stop.

Also: `.deb` files and control scripts unpack into two new roots; nested jars are
an extraction or one streamed member; a pickle member is streamed to a fixed
output name with the member as a quoted argument; a database in a target set
keeps matched names; the lock line hashes every helper, `.py` included; the
escape check runs before the link step; `unzip` is in the toolchain.

## v1.12.0 (23 Oct 2026)

Hardening round 12: WebAssembly, Rust, model files and crash dumps walked end to
end, proven findings only (5 medium reproduced).

- Pickles: `pickletools` stops at the first pickle in a file, so a later
  `GLOBAL` went unseen (reproduced with a harmless two-pickle file). A locked
  helper, `pickle-dis.py`, disassembles every pickle and says when the whole
  file was read; every `*.pkl` in a zip-format `.pt` is inspected, streamed out as
  one named file.
- `file` on a core dump prints the process's arguments (reproduced on a synthetic
  core): its output goes to a file and the arguments are masked before reading.
- The escape scan exempted any file named `commands.log`, so a truncated or
  forged log went unseen (reproduced). Only the lead's log is exempt, and it is
  checked instead: a regular file whose earlier bytes are unchanged.
- Host lists dropped multi-host connection strings, names with `_` and IPv6
  literals (reproduced): one host pattern now keeps all of them (tested).
- A target can be a set of files named together (a core and its binary, a
  database with its `-wal`/`-shm`, a module with its glue), each with its own
  digest.

Also: `unset DEBUGINFOD_URLS` in `env.sh`; a "this sample is malicious" finding
is reported as the answer; macOS crash reports are read field by field.

## v1.11.0 (23 Oct 2026)

Hardening round 11, proven findings only (4 medium findings reproduced, plus
low ones fixed alongside). One finding was left
unproven and unchanged: that Ghidra headless writes its log and settings under
the sandboxed HOME on every run and so trips the escape scan (Ghidra is not
installed on the build host).

- The host-only list dropped real hosts followed by `;`, `)` or a backtick (CSP
  strings, template literals; reproduced). `hosts.sh` now captures only
  scheme, masked user-info, host and port, and both host lists are built with one
  host pattern that also reads the endpoint file (tested: every host kept, no
  npm-scope or credential fragments).
- `codesign` filtering hid "code object is not signed at all", the answer for an
  unsigned bundle (reproduced): output goes to a file and the pattern includes it.
- The repository check never ended when `W` was unset or relative (reproduced):
  it now requires `W` and stops at `.`; step 2 sets `W` inline.
- One hand-over set (ledger, every `commands.log`, `report.md` if written, each
  non-secret deliverable, the original), used at close and at live teardown.
- "Extraction" means a tool creating files named from the sample; one named
  output file (`pycdc`, `wasm2wat`, `lipo -thin`, `bundletool`) is not one.
- A directory target locks `original/` after its copy; the macOS recipe's
  `<App>.app` is `$W/original/target`; Go build settings and Info.plist output are
  secret-bearing; the query example ends with `cat -v`.

## v1.10.0 (23 Oct 2026)

Hardening round 10, proven findings only (7 reproduced: 3 by running the
command on a neutral test folder, 4 by quoting the conflicting passages).

- SQLite: a WAL-mode database in the read-only `original/` cannot be opened
  ("unable to open database file", reproduced with sqlite3 3.54). Open a working
  copy, with its `-wal`/`-shm`, in a fresh scratch directory, SQL passed as
  arguments so `run.sh` logs it; `immutable=1` when the `-wal` is missing. The
  database and its `-wal`/`-shm` are one artifact.
- A decompiler that prints to stdout (pycdc) gets its own output directory as
  `$ROOT`; its output in `out/` was tripping the escape scan (reproduced). The
  PyInstaller recipe follows the escape-check order.
- Subagents run no extraction: the lead runs every extraction, one at a time,
  and hands over finished roots.
- Secrets kept off screen: `bundletool dump manifest`, `javap -v` and
  `rpm --scripts` go to files; any guide command that prints sample text is run
  with its output redirected, shown or not.
- Every `out/` file carries the target name; the raw host and endpoint lists are
  secret-bearing and never handed over, and a host-only list (well-formed names
  only, tested) is the deliverable.
- `manifest.sh` exits non-zero when a file cannot be hashed (it exited 0;
  reproduced); the file count runs after `chmod -R u+rwX` (a mode-000 directory
  hid files; reproduced); close-out and live teardown record everything, hash
  outside `run.sh`, then hand over exactly the hashed files; the report template
  no longer holds the ledger's closing hash; intake asks only what the request
  does not state.

## v1.9.0 (23 Oct 2026)

Hardening round 9, the first under the rule that a finding counts only once it
is reproduced (a command run on a neutral test folder, or both conflicting
passages quoted). Proven and fixed:

- Escape-check timing. Writing T0 into the ledger made the scan flag the ledger
  under GNU `find` (sub-second compare), and BSD `find` (whole-second compare)
  missed a write made in T0's own second. Both reproduced. Now: ledger entry
  first, wait, take T0 and keep it in the conversation, wait, run, then append
  T0 and the result. Any failed section 1 check is a 6A stop.
- The preflight's variable-name check printed a continuation line of a
  multi-line value; it now reads only `NAME=` lines.
- `hosts.sh` and `endpoints.sh` skipped files with NUL bytes (BSD grep printed
  "Binary file ... matches" instead of the URL); they now use `LC_ALL=C grep -a`.
- A statically linked ELF had no symbol command (`readelf -d`, `objdump -T` and
  `nm -D` read only the dynamic table): `nm` / `readelf -s`, and how to show the
  library's routines are called.

Also: `chmod -R u+rwX` before the link step (a mode-000 directory gave a false
"0"; reproduced) and the link check requires empty stderr; every `out/` file
names its target; live teardown records deletions before hashing; a directory
target is copied into an extraction root for batch reads; the 600-second cap is
for unpackers, analysers run under an operator time budget; close-out records the
data-handling confirmation before the final hash; Windows DLL versions come from
the version resource.

## v1.8.0 (23 Oct 2026)

Hardening round 8 (adversarial, fresh-reader), scope frozen. New commands were run
against a test tree before shipping; `find -newerct` was checked on BSD `find`
(GNU `find` accepts the same time format); the `tshark` forms are unchanged
filters, now logged and failing loudly.

- The escape check compares change times against a time recorded in the ledger,
  not a marker file a hostile archive could rewrite; `! -type d` also catches a
  planted symlink; the temp folder is emptied after each run; run directories are
  made with `mkdir` (no `-p`). Decompilers count as extractions, with their output
  directory as `$ROOT`.
- The link step refuses to run without a root and removes nothing it could not
  record.
- Secrets: the gdb backtrace's "Core was generated by" line is filtered and the
  file is secret-bearing; `hosts.txt` is named secret-bearing; per-target output
  files carry the target's name, so a second sample never overwrites the first.
- .NET: ILSpy output location, a step for the services it calls, UTF-16 string
  literals, and config files read only when they are part of the approved target.
- Captures: "external" excludes broadcast, carrier NAT and IPv6 local ranges;
  "contacted" needs the device as initiator; cleartext is also read from the
  protocol hierarchy, with the claim bounded; credential counts are per host;
  `tshark` runs through `run.sh` with `pipefail`.
- Close-out order: cleanup (including the secret-bearing `out/` files) is recorded
  before the ledger hash is posted; extraction roots are made writable before
  deletion. Link records pair and sort before a version diff.

## v1.7.0 (23 Oct 2026)

Hardening round 7 (adversarial, fresh-reader), scope frozen. New commands were run
against a test tree before shipping. One finding was rejected after checking the
source: GNU sed reads a `#` inside a bracket expression as part of the class, not
as the delimiter (`match_slash` hands brackets to `snarf_char_class`), so
`endpoints.sh` is unchanged.

- The escape check now scans the whole working directory by change time, skipping
  only the new root, `scratch/`, the temp and cache folders and the command logs.
  A backdated ledger edit, a planted `.pth` under the sandboxed HOME and a write
  into another root are all caught; a missing path is a failure, never a pass.
- Link neutralisation first makes the root writable (extractors keep read-only
  directories, where `rm` failed silently) and is then confirmed by a re-check
  that must print 0. Version comparisons also diff the two link records.
- A directory target's manifest (`manifest.sh`) uses relative paths and lists link
  targets, so its SHA-256 is reproducible on any machine; source and copy match
  with `cmp`.
- More secret-safe reads: `aapt2 dump badging`, `go version -m`, `msiinfo export`
  and `readelf -n` on a core go to files; the manifest search keeps whole tags
  (the `<application>` flags were being cut).
- Consistency: same root names across versions, `diff` exit codes, each version's
  `original/` locked, a pre-ledger stop is ledger entry 1 itself, location checks
  rerun through `run.sh`, approval wording matches section 0, scratch is always a
  fresh `<task>/` directory, output paths for `wasm2wat` and `lipo -thin`,
  extractions kept after an abort until the operator answers.

## v1.6.0 (23 Oct 2026)

Hardening round 6 (adversarial, fresh-reader), scope frozen. New commands were run
against a test tree before shipping (the GNU sed path of `endpoints.sh` was
checked by its guard only, as the build host has BSD sed).

- The scripts are locked (read-only, with `SHA256SUMS`) and `original/` is
  read-only. After every extraction the sums are rechecked and a change-time
  (`-cnewer`) scan of `scripts/`, `original/` and the sandboxed HOME's config must
  come back empty, so an extractor that writes outside its root is caught even
  when it backdates the file. binwalk 2.3.3 and earlier are refused
  (CVE-2022-4510).
- A directory target (an installed `.app`) has a defined identity: a `cp -a`
  copy and a sorted per-file SHA-256 manifest.
- Payloads carved from the approved artifact (an `app.asar`, a rootfs, a nested
  jar) need no new approval; the routing rule says container first, then the
  question's row on the extraction root; the SBOM guide runs inside `$ROOT`;
  `$ROOT` is defined.
- The host and endpoint pipelines are locked helper scripts run through
  `run.sh`, with `pipefail` and meaningful exit codes; `endpoints.sh` refuses to
  run without GNU sed rather than returning an empty file.
- Secret exposure closed: gdb backtraces use `set print frame-arguments none` and
  go to a file; library-version, DNS, SNI, manifest and plist reads go to files or
  print only the match; HAR masking drops a query or fragment with no path;
  `umask 077` in `env.sh`; secret-bearing `out/` files are named in the ledger and
  never exported.
- Consistency: one confidence scale (the SBOM guide no longer has its own),
  comparison layout matches the evidence guide, the setup order creates `$W`
  before checking it, a pre-ledger stop writes nothing in a failed location, the
  link rule's prose matches its command, README wording matches the body.

## v1.5.0 (23 Oct 2026)

Hardening round 5 (adversarial, fresh-reader), scope frozen. Every changed
command below was run against a test tree before shipping, except the tshark
filters (tshark not installed on the build host; checked against the Wireshark
display-filter documentation).

- Link neutralisation is one NUL-safe command that acts only on paths `find`
  produced; tested with a newline-named link aimed at the ledger (ledger intact).
  Out-of-root symlinks in a filesystem image are now expected, recorded and
  neutralised, not a stop.
- Preflight judges the network by `curl`'s specific exit codes (6, 7, 28), so a
  missing or broken tool can no longer pass for "offline"; repository detection
  walks parent folders for `.git`; a size-bounded filesystem is required at intake
  and checked with `df`.
- Sample-derived listings (`strings`, decompiles, captures) go to files and are
  queried with counts and targeted searches, never read whole; `cat -v` ends any
  command that displays sample text. Pipelines are logged whole via
  `run.sh bash -c '...' _ <file>`.
- One confidence scale everywhere; the ledger's first entry uses `prev: genesis`
  and its contents are listed in one place; per-item results (permission map,
  SBOM) have a home in `$W/out/` whether or not a report is filed; extraction
  always targets a new root, decompiler output lives in `$W/out/`.
- Masking: the JavaScript host list masks user-info keys (a Sentry DSN key no
  longer reads as a host); the endpoint pipeline gains `pipefail` and more secret
  parameter names and is treated as secret-bearing; the HAR projection keeps only
  method and host; cleartext reporting keys on client SYNs and is honest about
  which protocols the credential count covers; the template no longer asks for
  secret prefixes. `JAVA_TOOL_OPTIONS` also pins `java.io.tmpdir`.

## v1.4.0 (23 Oct 2026)

Hardening round 4 (fresh-reader, adversarial, accuracy). Scope frozen: fixes only.

- The round 3 command-logging one-liner was broken (a pipe on the function
  definition meant nothing was logged). Replaced by `env.sh` and `run.sh` files,
  tested: the tool's exit status passes through, redirected output stays clean,
  hostile file names are logged quoted, and tool output never enters the log.
- One intake message and an explicit order of operations (intake, layout, preflight,
  copy and hash, first ledger entry). The preflight checks the operator's real home
  (not the sandboxed one, where it passed trivially) and fails by design on an
  ordinary desktop, so the agent asks for an analysis environment instead of
  improvising one.
- Link neutralisation is a tested procedure that records each link's target and
  never writes through a link. Extraction roots are defined, including per-version
  roots for comparisons.
- The Java endpoint scan is one tested pipeline straight to a 0600 file (no raw
  credential is printed); the pcap cleartext query projects fields only and covers
  IPv6; `JAVA_TOOL_OPTIONS` and `TMPDIR` keep JVM tools and syft inside the sandbox;
  PyInstaller extraction runs in a fresh capped directory; teardown appends its
  ledger entry before hashing and exporting.

## v1.3.0 (23 Oct 2026)

Hardening round 3 (adversarial, usability, accuracy). Closes concrete abuse paths
a hostile sample could use and fills coverage gaps:

- A formatter, SQLite CLI or extractor no longer loads config, plugins, a view's
  `writefile()`, or a planted symlink out of the sample: Prettier runs
  `--no-config` from an empty scratch dir; SQLite uses `-init /dev/null -readonly`
  with `trusted_schema=OFF` and base tables only; every extractor gets an explicit
  output directory and runs with a sandboxed `HOME`; links out of the tree are
  neutralised before any recursive read or diff (`--no-dereference`).
- The preflight counts secret-shaped env names instead of printing values, checks
  more credential stores, and verifies the work path is not synced or
  version-controlled. One `run` wrapper logs every command and exit (no second
  log). The live VM exports and hashes the ledger before rollback so evidence
  survives. Core reading is explicitly static; launching or attaching a debugger
  is live.
- New routes and recipes: PyInstaller/`.pyc`, a full pcap recipe (hosts, DNS, SNI,
  cleartext, credential counts), macOS notarisation, Java endpoints/credentials and
  logging-framework version, .NET config-read APIs corrected.
- Accuracy: `7zz` everywhere, `msiinfo tables` before `export`, extractor `-d`/`-C`
  flags, AppImage offset from the ELF header, `eu-unstrip` for build-ids,
  `gdb -iex "set auto-load off"`, syft's app-update env var, `python3 -I -m pickletools`,
  elfutils is Linux-only.

---

## v1.2.0 (22 Oct 2026)

Hardening round 2 (three fresh reviews). Two reviewers independently caught that
round 1's link rule would block every firmware root filesystem, and that the
"third-party component" clause blocked ordinary work; both are fixed.

- Extraction limits are concrete and workable (`timeout`, size/file/depth caps,
  `realpath` containment); filesystem links and device nodes are recorded, not
  followed, instead of rejected.
- Identifying a bundled component is in scope; reading its internals needs its own
  approval. Authority record adds a security contact, a licence-terms check, and
  an approver who is not the requester.
- Work environment is preflight-tested, not just asserted; sample-derived names
  never reach a shell; subagents are tightly scoped; the ledger is tamper-evident.
- Live analysis uses a recorded session envelope (so a debugger session is not
  stalled by per-command approval), with egress only to endpoints the organisation
  operates or may test.
- New routes and recipes: software bill of materials (SBOM) for a tree or image,
  Android permission-to-code mapping, .NET config-read tracing, Java/JVM, macOS
  app bundles, Windows/Linux installers and packages, crash and core dumps.
- Accuracy fixes: `7zz` vs `7z`, `rust-audit-info` (not `cargo audit bin`, which
  needs the network), `--only-binary` for pip, AppImage squashfs offset, macOS
  `readelf`, `android:usesCleartextTraffic`, macOS `app.asar` path.

---

## v1.1.0 (22 Oct 2026)

Hardening round 1 (three independent reviews: coverage, safety, agent usability):
- Authority record with approver and reference; data-handling check; re-approval on any scope change.
- Work environment, work layout, extraction limits, never-mount, content-is-data and out-of-bounds rules; secrets masked at the source.
- Live gate made checkable: per-step recorded approval, isolated VM checks, teardown.
- New "stop and ask" section; append-only ledger with confidence levels; retention instead of blanket cleanup.
- Routing picks the most specific row; rules for missing or failing tools and large output.
- Recipes: crypto-library version (linked vs bundled), Electron host inventory, two-version comparison.
- Fixes: binwalk v2/v3 flags, `7z -o`, `mitmdump -n -r`, full `bundletool` command, pickle model files never loaded, macOS `readelf`, rizin `aaa`.
