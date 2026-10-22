# Firmware, packed archives, model files and databases

Covers artifacts that carry other artifacts (firmware images, installers, packed
executables, archives) and self-contained data files (model files, SQLite). All
static and read-only; cite the sample's SHA-256; carve into the sample subfolder
only.

## Firmware images and packed blobs

Firmware and installers are containers. The job is to map and carve the layers,
then route each payload.

- **Map first, carve second.** `binwalk <image>` shows what is embedded (file
  systems, compressed blobs, certificates, bootloaders) and where. Read the map
  before extracting.
- **Carve** with `binwalk -e -d <outdir> <image>` (binwalk v3; v2 uses `-C <outdir>`) or, for broader format coverage
  and recursive extraction, **unblob** (`unblob -e <outdir> <image>`). Both write into a
  directory you choose, point it at the sample subfolder.
- **Re-identify every carved payload** (`file`, magic bytes) and route it:
  a squashfs/ext filesystem to mount read-only and walk; a native blob to
  [native and managed](native-and-managed.md); a bundled app to its guide.
- **Record the chain.** For each payload, note what it was and its offset in the
  image, so the path from the original bytes to the analysed payload is
  auditable.
- A self-extracting or auto-running unpacker is **live mode**: stop and get
  approval (SKILL.md section 6). Carving extracts bytes; it must not execute the
  target.

## Archives and installers

- `7z l <archive>` to inventory, `7z x` to extract (into the subfolder). Handles
  ZIP, many installer formats, and more.
- A platform installer (DMG, MSI, MSIX, deb/rpm, PyInstaller executable) wraps a
  payload: inventory members, extract, re-identify, route. For a PyInstaller
  executable the application is the archive layer, not the bootloader stub.

## Model files

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

## Pitfalls

- `binwalk`'s signature matches have false positives; a "detected" blob at an
  offset is a candidate until you carve and identify it.
- Encryption and compression look alike as high-entropy regions; entropy is a
  hint, not a verdict.
- Carving can produce thousands of files; inventory and route by type rather
  than reading everything. The answer is usually in one or two payloads.
