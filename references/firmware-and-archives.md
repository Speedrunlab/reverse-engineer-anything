# Firmware, packed archives, model files and databases

Covers artifacts that carry other artifacts (firmware images, installers, packed
executables, archives) and self-contained data files (model files, SQLite). All
static and read-only; cite the sample's SHA-256; carve into `$W/extracted/`
only.

## Firmware images and packed blobs

Firmware and installers are containers. The job is to map and carve the layers,
then route each payload.

- **Map first, carve second.** `binwalk <image>` shows what is embedded (file
  systems, compressed blobs, certificates, bootloaders) and where. Read the map
  before extracting.
- **Check the binwalk version first** (`binwalk --help`): v3 takes the output
  directory as `-d`, v2 as `-C` (in v2, `-d` means depth). Never use v2 at 2.3.3
  or earlier (CVE-2022-4510: a crafted image writes outside the output directory).
  Run the SKILL.md section 1 escape check after every carve.
- **Carve** with `binwalk -e -d <outdir> <image>` (v3) or `binwalk -e -C <outdir> <image>` (v2) or, for broader format coverage
  and recursive extraction, **unblob** (`unblob -e <outdir> <image>`). Both write into a
  directory you choose: point it at a new extraction root `$W/extracted/<name>/`.
- **Re-identify every carved payload** (`file`, magic bytes) and route it:
  a squashfs or ext filesystem unpacked with `unsquashfs` or `7zz` (never mounted);
  a native blob to
  [native and managed](native-and-managed.md); a bundled app to its guide.
- **Record the chain.** For each payload, note what it was and its offset in the
  image, so the path from the original bytes to the analysed payload is
  auditable.
- A self-extracting or auto-running unpacker is **live mode**: stop and get
  approval (SKILL.md section 6). Carving extracts bytes; it must not execute the
  target.

## Installers and OS packages

Unpack, never run. (`7zz` is official 7-Zip; `7z` is p7zip, either works for ZIP.)

Every tool below gets an explicit output directory under `$W/extracted/<name>/`
(their default is the current directory) and runs from a fresh `$W/scratch/<task>/`,
under the SKILL.md section 1 escape-check order. pyinstxtractor, which cannot
take an output directory, is the one exception, handled below.

- **General archive:** `7zz l -slt <archive>` to inventory and check paths, then
  `7zz x <archive> -o<$W/extracted/name>`.
- **Windows MSI:** `msiinfo tables <f>.msi` then `msiinfo export <f>.msi <table> > "$W/out/msi-<name>-<table>.txt"`
  per table (tables can hold property values; query the files, never print them whole), and `msiextract -C <dir> <f>.msi` (msitools), or `lessmsi` on Windows;
  `7zz` sees MSI streams only by cryptic names, so prefer msitools. **Inno Setup:**
  `innoextract -d <dir>`. **NSIS:** `7zz x`. **InstallShield:** `unshield -d <dir>`.
  **CAB:** `cabextract -d <dir>`. **MSIX/AppX:** unzip and read `AppxManifest.xml`.
  Never `msiexec /a`.
- **Linux packages:** `dpkg-deb -c <f>.deb | cat -v` (list), `-x <f>.deb "$W/extracted/<name>-files"` (files) and
  `-e <f>.deb "$W/extracted/<name>-control"` (the maintainer scripts; read, never
  run), two new roots, each an extraction under SKILL.md section 1; `rpm -qp --scripts
  <f>.rpm > "$W/out/rpm-scripts-<name>.txt"` (scriptlets can embed secrets: query
  the file, read it with `cut -c1-200 | cat -v`) then `bsdtar -xf <f>.rpm -C <dir>` (bsdtar reads rpm directly, so no
  `cd` into the output is needed). The maintainer scripts are part of the review.
- **macOS `.pkg`/`.dmg`:** `pkgutil --expand-full <f>.pkg <dir>` or `xar -xf <f>.pkg
  -C <dir>` for a pkg; `7zz x` for a dmg. Do not `hdiutil attach` (that mounts it).
- **PyInstaller executable:** confirm it
  (`strings -a -n 6 <exe> | grep -c -e MEIPASS -e PyInstaller`) and read the Python
  version from the embedded `python3NN.dll`/`libpython3.NN`. List members with
  `pyi-archive_viewer -l <exe>`. pyinstxtractor writes into the current directory,
  so its run directory is also its `$ROOT`: follow the section 1 escape-check order
  (ledger entry, `mkdir "$W/scratch/pyi-1"`, wait, take T0, wait), then
  `cd "$W/scratch/pyi-1" && "$W/scripts/run.sh" timeout 600 python3 -I <path>/pyinstxtractor.py <abs exe>`
  (through `run.sh`, so it is logged like every other tool). Run the section 1
  checks with `ROOT="$W/scratch/pyi-1"`, then move the output to a new extraction
  root (`mv` into `$W/extracted/pyi-1/`) and apply the link step there. It parses the archive's table
  of contents with `marshal` (hostile data parsed in memory, not code run), one
  more reason it runs only in the section 1 environment. The entry script is the
  member that is not `pyiboot*` or `pyi_rth_*`. A bare `.pyc` may need its header
  prepended: 16 bytes for Python 3.7+, 12 for 3.3 to 3.6, 8 before that.
  Disassemble with `pycdas`; decompile with `pycdc`, both of which print to
  stdout: redirect each to one file (`> "$W/out/pycdc-<name>-<member>.py"`; a
  single named file is not an extraction, SKILL.md section 1). If `pycdc` fails (common on
  3.11+) report the disassembly and mark behaviour inferred. Never
  `marshal.load`/`import` an untrusted `.pyc` yourself.
- **AppImage:** an ELF (type 2) with a squashfs appended. Its own
  `--appimage-extract` runs the file (live mode); instead compute the offset from
  the ELF header (`e_shoff + e_shentsize * e_shnum`, read with `readelf -h`) and
  `unsquashfs -d <dir> -o <offset> <file>`, or `7zz x`.
- After any unpack, re-identify each payload (SKILL.md section 2) and route it.

## Model files

- **Pickle-based model files** (`.pt`, `.pth`, `.pkl`, `.ckpt`, `.bin` saved with
  pickle) run code when loaded. Never load them. A file can hold several pickles
  one after another (older `torch.save` files do), and `python3 -I -m pickletools`
  stops at the first, so a later `GLOBAL` goes unseen (reproduced). Disassemble
  every pickle with this helper, saved and locked as `$W/scripts/pickle-dis.py`:

  ```python
  # pickle-dis.py <file>: disassemble every pickle in the file in turn; nothing is loaded
  import io, pickletools, sys
  data = open(sys.argv[1], "rb").read()
  f = io.BytesIO(data)
  n = 0
  while f.tell() < len(data):
      n += 1
      print(f"--- pickle {n} at offset {f.tell()}")
      pickletools.dis(f)
  print(f"--- {n} pickle(s), {len(data)} bytes, all read")
  ```

  Run `"$W/scripts/run.sh" python3 -I "$W/scripts/pickle-dis.py" <file> > "$W/out/pickle-<name>.txt"`
  and search the file for `GLOBAL`, `STACK_GLOBAL`, `REDUCE`, `BUILD` and `INST`.
  An exit with an error and no `all read` line means bytes that are not a pickle:
  record it, never treat the file as fully read. A zip-format `.pt` holds several
  members: list them all (`7zz l -slt`), stream each `*.pkl` out with
  `7zz e -so <file> "<member>" > "$W/out/<name>-pkl<N>.pkl"` (the member name
  is a quoted argument, never part of the output path; one named file, not an
  extraction), and inspect every one; a TorchScript `code/` folder is source to
  read, not run.
- **GGUF / safetensors** carry a metadata header plus weights. Read the
  **header** for architecture, tensor names/types, and embedded metadata with a
  format-specific reader; `strings` surfaces text metadata quickly.
- Do not load the weights "to inspect", that is running the model. Header and
  metadata answer identity and structure questions; behaviour is not inferable
  from declared architecture alone.
- Record full-file identity separately from header identity (hashing only the
  header leaves the weights unverified, say which you did).

## SQLite databases

- Open a **working copy**, never `original/` (it is read-only, and SQLite cannot
  open a WAL-mode file there): `cp` the database and any `-wal`/`-shm` that came
  with it, names kept matched (`sample.db`, `sample.db-wal`), into a fresh
  `$W/scratch/<task>/`, then
  `"$W/scripts/run.sh" sqlite3 -readonly -init /dev/null <copy> 'PRAGMA trusted_schema=OFF;' '<query>'`,
  each statement an argument so `run.sh` logs it. A WAL-mode database that came
  without its `-wal` opens only as `'file:<abs copy>?immutable=1'`; say that
  uncheckpointed transactions, if any, are not visible. These are defence in depth:
  `-init /dev/null` stops the CLI reading `~/.sqliterc`, and `trusted_schema=OFF`
  stops a view or trigger calling functions that are not marked safe (current CLIs
  already block their own `writefile()` there; older or custom builds may not).
  Never open the operator's live database.
- **Schema first:** `.schema` (or `SELECT sql FROM sqlite_master`) before any row
  read. Read only **base tables** (`SELECT ... FROM "t"`), never a view or a
  virtual table (both can run functions). Select only the non-sensitive columns
  the question needs, with a `LIMIT`; never `SELECT *` a table that holds secrets.
- A database in WAL mode has a `-wal` file holding committed transactions not yet
  written back to the main file (`-shm` is only its index). They are one artifact
  with the database: name them together at intake, hash each, copy them together,
  and note whether you have a quiescent snapshot or a torn copy.
- Redact: app databases hold tokens, messages and personal data. Report shape
  and the answer, not raw rows of personal content.

## Component inventory (SBOM)

"Which open-source components and versions are inside this image?" for a bill of
materials. Carve the image first (the firmware section above, SKILL.md section 5)
and run every step on its extraction root, `$ROOT`, after the section 1 link
step: the paths below are inside that root, so `/var/lib/dpkg/status` means
`"$ROOT/var/lib/dpkg/status"`, never the host's own file. Work from strongest
evidence to weakest, one ledger entry per method:

1. **Package databases** (the strongest single signal): `/var/lib/dpkg/status`,
   `/var/lib/opkg/status`, `/var/lib/pacman/local/`, an RPM database, and
   `/etc/os-release`. These give name and version directly.
2. **Shared libraries:** the `*.so*` file names and `readelf -d <lib> | grep SONAME`.
3. **Banners in binaries:** `strings -a -n 6` for BusyBox (`BusyBox v1.x`), the
   kernel (`Linux version ...`), the bootloader, OpenSSL (`OpenSSL 3.x`), zlib and
   libc. A banner inside the file is good evidence; a version from a path or
   filename alone is weak.
4. **Licence files** under `/usr/share/doc`, `LICENSE`, `NOTICE`.

For a Windows tree (an unpacked installer), methods 1 and 2 do not apply: take
each DLL's version from its version resource (the `FileVersion` and
`ProductVersion` strings, stored as UTF-16, so GNU `strings -a -e l`), one signal
(medium). The PE header's image and linker versions are not file versions.

Write the result to `$W/out/sbom-<name>.cdx.json` in CycloneDX form (name, version,
path, detection method, confidence). If the operator has staged **syft**,
`"$W/scripts/run.sh" syft dir:"$ROOT" -o cyclonedx-json="$W/out/syft-<name>.cdx.json"`
cross-checks the manual pass, after the section 1 link step on that root (syft has
no vulnerability DB; `SYFT_CHECK_FOR_APP_UPDATE=false`, set in `env.sh`, stops its
only network call, and `TMPDIR` in `env.sh` keeps its temporary unpacking inside
`$W`). Vulnerability matching, if asked, is a
separate tool (grype/osv-scanner) with its DB staged and updates disabled. Grade
confidence on the one scale in SKILL.md section 7: a package DB entry or a banner
alone is one signal (medium); two that agree, such as a package DB and a banner,
or a SONAME and a banner, are high; a path or filename alone is low. State
coverage: a clean extraction inventoried, or carving that may have missed regions.

## Pitfalls

- `binwalk`'s signature matches have false positives; a "detected" blob at an
  offset is a candidate until you carve and identify it.
- Encryption and compression look alike as high-entropy regions; entropy is a
  hint, not a verdict.
- Carving can produce thousands of files; inventory and route by type rather
  than reading everything. The answer is usually in one or two payloads.
