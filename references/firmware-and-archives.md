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
  a squashfs or ext filesystem unpacked with `unsquashfs` or `7z` (never mounted);
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

- **General archive:** `7zz l -slt <archive>` to inventory and check paths, then
  `7zz x <archive> -o<work/extracted/name>`.
- **Windows MSI:** `msiinfo export <f>.msi` and `msiextract` (msitools), or
  `lessmsi` on Windows; `7zz` sees MSI streams only by cryptic names, so prefer
  msitools. **Inno Setup:** `innoextract`. **NSIS:** `7zz x`. **InstallShield:**
  `unshield`. **CAB:** `cabextract`. **MSIX/AppX:** unzip and read `AppxManifest.xml`.
  Never `msiexec /a`.
- **Linux packages:** `dpkg-deb -c <f>.deb` (list) and `-x` (extract);
  `rpm -qp --scripts <f>.rpm` (read maintainer scripts, never run them) and
  `rpm2cpio <f>.rpm | cpio -idmv`. The maintainer scripts are part of the review.
- **macOS `.pkg`/`.dmg`:** `pkgutil --expand-full` or `xar -xf` for a pkg; `7zz x`
  for a dmg. Do not `hdiutil attach` (that mounts it).
- **PyInstaller executable:** the application is the archive layer, not the
  bootloader stub; `pyi-archive_viewer` or pyinstxtractor lists members, then
  decompile the `.pyc` (`pycdc`). Do not `marshal.load` untrusted `.pyc`.
- **AppImage:** it is an ELF with a squashfs appended. Its own
  `--appimage-extract` runs the file (live mode); instead read the squashfs offset
  from the ELF section headers and `unsquashfs -o <offset>`, or `7zz x`.
- After any unpack, re-identify each payload (section 2) and route it.

## Model files

- **Pickle-based model files** (`.pt`, `.pth`, `.pkl`, `.ckpt`, `.bin` saved with
  pickle) run code when loaded. Never load them; inspect the opcodes with
  `python3 -m pickletools <file>` (a zip-format `.pt` holds `data.pkl` inside:
  list it with `7z l`, extract only that member, inspect it) or stop and ask.
- **GGUF / safetensors** carry a metadata header plus weights. Read the
  **header** for architecture, tensor names/types, and embedded metadata with a
  format-specific reader; `strings` surfaces text metadata quickly.
- Do not load the weights "to inspect", that is running the model. Header and
  metadata answer identity and structure questions; behaviour is not inferable
  from declared architecture alone.
- Record full-file identity separately from header identity (hashing only the
  header leaves the weights unverified, say which you did).

## SQLite databases

- Always open a **copy**, read-only: `sqlite3 -readonly copy.db`. Never open
  the operator's live database.
- **Schema first:** `.schema` (or `SELECT sql FROM sqlite_master`) before any
  row read. Then read only the tables/columns the question needs, with a `LIMIT`.
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
path, detection method, confidence). If the operator has staged **syft** and its
database, `syft dir:work/extracted -o cyclonedx-json` cross-checks the manual
pass; keep its DB auto-update off (no network). Confidence is high when a package
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
