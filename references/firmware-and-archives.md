# Firmware, packed archives, model files and databases

Covers artifacts that carry other artifacts (firmware images, installers, packed
executables, archives) and self-contained data files (model files, SQLite). All
static and read-only; cite the sample's SHA-256; carve into `work/extracted/`
only.

## Firmware images and packed blobs

Firmware and installers are containers. The job is to map and carve the layers,
then route each payload.

- **Map first, carve second.** `binwalk <image>` shows what is embedded (file
  systems, compressed blobs, certificates, bootloaders) and where. Read the map
  before extracting.
- **Check the binwalk version first** (`binwalk --help`): v3 takes the output
  directory as `-d`, v2 as `-C` (in v2, `-d` means depth).
- **Carve** with `binwalk -e -d <outdir> <image>` (v3) or `binwalk -e -C <outdir> <image>` (v2) or, for broader format coverage
  and recursive extraction, **unblob** (`unblob -e <outdir> <image>`). Both write into a
  directory you choose: point it at `work/extracted/`.
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

Every tool below gets an explicit output directory under `work/extracted/<name>/`
(their default is the current directory) and runs from `work/scratch/`.

- **General archive:** `7zz l -slt <archive>` to inventory and check paths, then
  `7zz x <archive> -o<work/extracted/name>`.
- **Windows MSI:** `msiinfo tables <f>.msi` then `msiinfo export <f>.msi <table>`
  per table, and `msiextract -C <dir> <f>.msi` (msitools), or `lessmsi` on Windows;
  `7zz` sees MSI streams only by cryptic names, so prefer msitools. **Inno Setup:**
  `innoextract -d <dir>`. **NSIS:** `7zz x`. **InstallShield:** `unshield -d <dir>`.
  **CAB:** `cabextract -d <dir>`. **MSIX/AppX:** unzip and read `AppxManifest.xml`.
  Never `msiexec /a`.
- **Linux packages:** `dpkg-deb -c <f>.deb` (list), `-x <f>.deb <dir>` (files) and
  `-e <f>.deb <dir>` (the maintainer scripts; read, never run); `rpm -qp --scripts
  <f>.rpm` then `bsdtar -xf <f>.rpm -C <dir>` (or `rpm2cpio <f>.rpm | (cd <dir> &&
  cpio -idmv)`). The maintainer scripts are part of the review.
- **macOS `.pkg`/`.dmg`:** `pkgutil --expand-full <f>.pkg <dir>` or `xar -xf <f>.pkg
  -C <dir>` for a pkg; `7zz x` for a dmg. Do not `hdiutil attach` (that mounts it).
- **PyInstaller executable:** confirm it
  (`strings -a -n 6 <exe> | grep -c -e MEIPASS -e PyInstaller`) and read the Python
  version from the embedded `python3NN.dll`/`libpython3.NN`. List members with
  `pyi-archive_viewer -l <exe>`. Extract with pyinstxtractor **from a fresh empty
  subfolder** (`cd work/scratch && python3 -I <path>/pyinstxtractor.py <abs exe>`,
  the one permitted run-from-cwd case, because the tool writes beside itself); move
  the output under `work/extracted/`. The entry script is the member that is not
  `pyiboot*` or `pyi_rth_*`; a `.pyc` may need its 16-byte header for that Python
  version prepended. Disassemble with `pycdas`; decompile with `pycdc`, and if it
  fails (common on 3.11+) report the disassembly and mark behaviour inferred.
  Never `marshal.load`/`import` an untrusted `.pyc`.
- **AppImage:** an ELF (type 2) with a squashfs appended. Its own
  `--appimage-extract` runs the file (live mode); instead compute the offset from
  the ELF header (`e_shoff + e_shentsize * e_shnum`, read with `readelf -h`) and
  `unsquashfs -d <dir> -o <offset> <file>`, or `7zz x`.
- After any unpack, re-identify each payload (SKILL.md section 2) and route it.

## Model files

- **Pickle-based model files** (`.pt`, `.pth`, `.pkl`, `.ckpt`, `.bin` saved with
  pickle) run code when loaded. Never load them; inspect the opcodes with
  `python3 -I -m pickletools <file>` (a zip-format `.pt` holds `data.pkl` inside:
  list it with `7zz l`, extract only that member, inspect it) or stop and ask.
- **GGUF / safetensors** carry a metadata header plus weights. Read the
  **header** for architecture, tensor names/types, and embedded metadata with a
  format-specific reader; `strings` surfaces text metadata quickly.
- Do not load the weights "to inspect", that is running the model. Header and
  metadata answer identity and structure questions; behaviour is not inferable
  from declared architecture alone.
- Record full-file identity separately from header identity (hashing only the
  header leaves the weights unverified, say which you did).

## SQLite databases

- Open a **copy** safely: `sqlite3 -readonly -init /dev/null copy.db`, then
  `PRAGMA trusted_schema=OFF;` as the first statement. `-readonly` stops database
  writes but not a `writefile()` planted in a view, and the CLI otherwise reads
  `~/.sqliterc`; `-init /dev/null` and `trusted_schema=OFF` close those. Never open
  the operator's live database.
- **Schema first:** `.schema` (or `SELECT sql FROM sqlite_master`) before any row
  read. Read only **base tables** (`SELECT ... FROM "t"`), never a view or a
  virtual table (both can run functions). Select only the non-sensitive columns
  the question needs, with a `LIMIT`; never `SELECT *` a table that holds secrets.
- A database in WAL mode has a `-wal` file holding committed transactions not yet
  written back to the main file (`-shm` is only its index). Copy all of them
  together, note whether you have a quiescent snapshot or a torn copy, and record
  the identity of each file.
- Redact: app databases hold tokens, messages and personal data. Report shape
  and the answer, not raw rows of personal content.

## Component inventory (SBOM)

"Which open-source components and versions are inside this image?" for a bill of
materials. Work from strongest evidence to weakest, one ledger entry per method:

1. **Package databases** (highest confidence): `/var/lib/dpkg/status`,
   `/var/lib/opkg/status`, `/var/lib/pacman/local/`, an RPM database, and
   `/etc/os-release`. These give name and version directly.
2. **Shared libraries:** the `*.so*` file names and `readelf -d <lib> | grep SONAME`.
3. **Banners in binaries:** `strings -a -n 6` for BusyBox (`BusyBox v1.x`), the
   kernel (`Linux version ...`), the bootloader, OpenSSL (`OpenSSL 3.x`), zlib and
   libc. A banner inside the file is good evidence; a version from a path or
   filename alone is weak.
4. **Licence files** under `/usr/share/doc`, `LICENSE`, `NOTICE`.

Write the result to `work/out/sbom.cdx.json` in CycloneDX form (name, version,
path, detection method, confidence). If the operator has staged **syft**,
`SYFT_CHECK_FOR_APP_UPDATE=false syft dir:work/extracted -o cyclonedx-json`
cross-checks the manual pass (syft has no vulnerability DB; the env var stops its
only network call, the app-update check). Vulnerability matching, if asked, is a
separate tool (grype/osv-scanner) with its DB staged and updates disabled. Confidence is high when a package
DB or a SONAME plus a banner agree; medium for a single banner; low for a path or
filename. State coverage: a clean extraction inventoried, or carving that may have
missed regions.

## Pitfalls

- `binwalk`'s signature matches have false positives; a "detected" blob at an
  offset is a candidate until you carve and identify it.
- Encryption and compression look alike as high-entropy regions; entropy is a
  hint, not a verdict.
- Carving can produce thousands of files; inventory and route by type rather
  than reading everything. The answer is usually in one or two payloads.
