# Changelog

Reverse Engineer Anything. Newest first.

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
