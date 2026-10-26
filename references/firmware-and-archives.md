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
- **Entropy as a hint:** `binwalk -E <image> > "$W/out/entropy-<name>.txt"` scores
  each region; flat high entropy is compression or encryption, which look alike.
  Carve and identify before calling a region either. The same map for any file,
  with no binwalk, comes from this helper, saved and locked as
  `$W/scripts/entropy.py` (tested on a fixture; one line per block, and a short
  last block cannot reach 8.0, since n bytes carry at most log2(n) bits each):

  ```python
  # entropy.py <file> [block bytes, default 4096]: Shannon entropy (bits per byte) per block; flat values near 8.0 are compressed or encrypted
  import math, sys
  from collections import Counter
  data = open(sys.argv[1], "rb").read()
  try:
      n = int(sys.argv[2]) if len(sys.argv) > 2 else 4096
      if n < 1: raise ValueError
  except ValueError:
      print("block size must be a whole number of bytes, for example 4096"); sys.exit(1)
  if not data: print("0 bytes: nothing to measure"); sys.exit(1)
  for i in range(0, len(data), n):
      b = data[i:i+n]; c = Counter(b)
      e = abs(sum(v/len(b) * math.log2(v/len(b)) for v in c.values()))
      print(f"0x{i:08x}\t{e:.2f}")
  ```
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

## Flattened devicetrees

A devicetree blob describes the hardware a Linux or U-Boot image expects: the
SoC, memory, buses and peripherals, with the kernel command line in
`/chosen/bootargs`. It starts with the magic `d0 0d fe ed` (big-endian); a
standalone `.dtb`, a `.dtb` carved from firmware or appended to a kernel image
(`binwalk` reports it), and a U-Boot FIT image (`.itb`, a devicetree whose
`/images` nodes carry the kernel, ramdisk and their hashes or signatures) are
all the same format. The tools are the devicetree compiler's own
(`device-tree-compiler`), which read the blob and run nothing:

- `fdtdump <file>.dtb > "$W/out/dtb-<name>.txt"` prints the header (version,
  sizes, boot CPU) and the whole tree in source form; `dtc -I dtb -O dts -o "$W/out/<name>.dts" <file>.dtb`
  decompiles it to a `.dts` you can diff between two images.
- `fdtget <file>.dtb / compatible / model`, `fdtget -t s <file>.dtb /chosen bootargs`
  and `fdtget -t x <file>.dtb /memory reg` answer the usual questions one
  property at a time (`-t s` strings, `-t x` hex cells, `-t i` integers).
  `bootargs` is sample text (`cut -c1-200 | cat -v`) and can name a root
  device, a console or a password.
- `compatible` strings name the board and SoC; a node's `reg` is an address on
  its own bus (the parent's `#address-cells`/`#size-cells`), not a CPU address
  until each ancestor's `ranges` is applied; `phandle` references
  (`interrupt-parent`, `clocks`, `remote-endpoint`) are links `dtc` prints as
  labels. A FIT image's `hash` and `signature` nodes are declarations: whether
  the bootloader checks them is a question about the bootloader; `dumpimage -l <itb>`
  (u-boot-tools) lists its components without extracting any.
- A `.dtbo` overlay changes a base tree and reads the same way; the merged
  result is in neither file.

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
  Read the header first with this helper, saved and locked as
  `$W/scripts/pyc-header.py` (tested on a fixture): the 16-bit magic names the
  CPython format (3627 is 3.14; map a number with `importlib.util.MAGIC_NUMBER`
  of a staged interpreter, or the table in CPython's
  `Lib/importlib/_bootstrap_external.py` up to 3.13 and
  `Include/internal/pycore_magic_number.h` from 3.14) and the flags say whether
  the file is hash-based (PEP 552) or carries the source's mtime and size; a
  file whose bytes 2 and 3 are not `0d 0a`, whose magic is below 3392 (the 3.7a4
  value that brought this header; earlier 3.x files carry 8 or 12 bytes) or whose
  magic is 5000 or more (Python 1.3 to 2.7 run from 5892 to 62211 with an 8-byte
  header; Python 3 magics have not reached 4000) is not this layout, and the helper
  says so. The magic names
  the format, not the interpreter that ran the program.

  ```python
  # pyc-header.py <file>: the 16-byte header of a CPython 3.7+ .pyc, nothing loaded
  import struct, sys
  h = open(sys.argv[1], "rb").read(16)
  if len(h) < 16:
      print(f"only {len(h)} byte(s) read: a pyc header is 16 bytes (truncated, or not a pyc)"); sys.exit(1)
  if h[2:4] != b"\r\n":
      print("bytes 2 and 3 are not 0d 0a: not a pyc header (a headerless marshal dump needs its header prepended)"); sys.exit(1)
  magic, flags = h[:4], struct.unpack("<I", h[4:8])[0]
  m = struct.unpack("<H", magic[:2])[0]
  if m >= 5000:
      print(f"magic {m}: outside CPython 3's range (Python 1.3 to 2.7 run from 5892 to 62211 with an 8-byte header), not the 16-byte 3.7+ layout"); sys.exit(1)
  if m < 3392:
      print(f"magic {m}: a pyc older than CPython 3.7a4 (8- or 12-byte header, no flags), not the 16-byte 3.7+ layout"); sys.exit(1)
  print("magic", magic[:2].hex(), "(little-endian", m, ") trailer", magic[2:].hex())
  if flags & 1:
      print("hash-based pyc; check_source" if flags & 2 else "hash-based pyc; not checked against source", "; source hash", h[8:16].hex())
  else:
      mtime, size = struct.unpack("<II", h[8:16])
      print(f"timestamp-based pyc; source mtime {mtime} size {size}")
  ```

  Disassemble with `pycdas`; decompile with `pycdc`, both of which print to
  stdout: redirect each to one file (`> "$W/out/pycdc-<name>-<member>.py"`; a
  single named file is not an extraction, SKILL.md section 1). If `pycdc` fails (common on
  3.11+) report the disassembly and mark behaviour inferred. Never
  `marshal.load`/`import` an untrusted `.pyc` yourself.
- **AppImage:** an ELF (type 2) with a squashfs appended. Its own
  `--appimage-extract` runs the file (live mode); instead compute the offset from
  the ELF header (`e_shoff + e_shentsize * e_shnum`, read with `readelf -h`) and
  `unsquashfs -d <dir> -o <offset> <file>`, or `7zz x`.
- **HarmonyOS / OpenHarmony (`.hap`, `.hsp`, an `.app` pack of them):** ZIPs.
  `module.json` (Stage model) or `config.json` (FA model) declares the abilities
  and permissions; `ets/modules.abc` is Ark bytecode, disassembled with the SDK's
  `ark_disasm <file>.abc "$W/out/abc-<name>.txt"` (one named output file);
  `libs/<abi>/*.so` route to the native guide.
- **Godot (`.pck`, or a pack appended to the game executable, found by its
  12-byte trailer):** GDRE Tools, headless:
  `gdre_tools --headless --list-files=<pck> > "$W/out/pck-list-<name>.txt"` to
  inventory, `--extract=<pck> --output=<dir>` to unpack into a new extraction
  root, and `--recover=<pck> --output=<dir>` to also decompile the GDScript
  (`.gdc`) to text, a reconstruction. The engine version and each file's declared
  MD5 are header claims, separate from the SHA-256 you take of each extracted
  file. An encrypted pack needs its key (`--key=`); a key recovered from the
  executable is a secret under SKILL.md section 1.
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
- **safetensors:** 8 bytes little-endian (the header length N), then N bytes of
  JSON (each tensor's `dtype`, `shape` and `data_offsets`, and a `__metadata__`
  string map), then the weights. Read the header with this helper, saved and
  locked as `$W/scripts/safetensors-header.py` (tested on a fixture; a header
  length over the format's 100 MB cap, or longer than the file, stops it before
  anything is read):

  ```python
  # safetensors-header.py <file>: print the JSON header (tensor names, dtypes, shapes, __metadata__); the weights are never read
  import json, struct, sys
  if sys.stdout: sys.stdout.reconfigure(errors="backslashreplace")  # a hostile tensor name must not stop the print
  LIMIT = 100_000_000  # the format's own header cap
  def show(s, n=120):  # control characters escaped, a cut marked, so a hostile name cannot forge or hide a row
      t = "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(s)[:n]); return t + ("..." if len(str(s)) > n else "")
  with open(sys.argv[1], "rb") as f:
      raw = f.read(8)
      if len(raw) < 8: print("shorter than the 8-byte length field: not a safetensors file"); sys.exit(1)
      (n,) = struct.unpack("<Q", raw)
      if n == 0 or n > LIMIT: print(f"header length {n} is outside the format's limit (1 to {LIMIT} bytes): not a safetensors file worth reading"); sys.exit(1)
      buf = f.read(n)
      if len(buf) != n: print(f"header truncated: {len(buf)} of {n} bytes present"); sys.exit(1)
  try:
      hdr = json.loads(buf.decode("utf-8"))  # the format is UTF-8 JSON; the reference reader refuses other encodings
  except (ValueError, RecursionError) as e:
      print(f"header is not UTF-8 JSON ({str(e)[:80]}): not a safetensors file"); sys.exit(1)
  if not isinstance(hdr, dict): print(f"header is JSON but not an object ({type(hdr).__name__}): not a safetensors header"); sys.exit(1)
  meta = hdr.pop("__metadata__", None)
  if meta is not None and (not isinstance(meta, dict) or not all(isinstance(v, str) for v in meta.values())): print(f"__metadata__ is not an object of string values ({type(meta).__name__}): not a safetensors header"); sys.exit(1)
  def ok(t):
      o = t.get("data_offsets") if isinstance(t, dict) else None
      return isinstance(t, dict) and isinstance(t.get("dtype"), str) and t["dtype"] and isinstance(t.get("shape"), list) and all(type(x) is int and x >= 0 for x in t["shape"]) and isinstance(o, list) and len(o) == 2 and all(type(x) is int for x in o) and 0 <= o[0] <= o[1]
  bad = [k for k, t in hdr.items() if not ok(t)]
  if bad: print(f"{len(bad)} entries lack a non-empty string dtype, a shape list of whole numbers or an ascending two-integer data_offsets (first: {bad[0][:60]!r}): not a safetensors header"); sys.exit(1)
  print(f"header {n} bytes, {len(hdr)} tensors, metadata keys: {sorted(show(k) for k in meta) if meta else 'none'}")
  for name, t in sorted(hdr.items()):
      print(f"{show(name)}\t{show(t['dtype'], 40)}\t{show(t['shape'], 200)}\tbytes {t['data_offsets'][1]-t['data_offsets'][0]}")
  ```

- **GGUF:** `GGUF` magic, version (2 or 3), the tensor count, then typed
  key/value metadata (`general.architecture`, `general.name`, the tokenizer,
  `tokenizer.chat_template`) and the tensor directory (name, dimensions, type
  number, offset), then aligned weights. `gguf-dump --no-tensors <file>` (the
  `gguf` Python package from llama.cpp, pinned) prints the metadata; this
  helper, saved and locked as `$W/scripts/gguf-header.py` (tested on a
  fixture), prints the metadata and the tensor directory with the standard
  library only, and stops on a version other than 2 or 3, a big-endian file or
  an absurd length:

  ```python
  # gguf-header.py <file.gguf>: the GGUF header, metadata key/value pairs and tensor directory; tensor data is never read
  import struct, sys
  LIMIT = 100_000_000  # longest string or array accepted; a header field beyond it is corrupt or hostile
  def show(s, n=120):  # control characters escaped, a cut marked, so a hostile name cannot forge or hide a row
      t = "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(s)[:n]); return t + ("..." if len(str(s)) > n else "")
  f = open(sys.argv[1], "rb")
  def rd(n):
      b = f.read(n)
      if len(b) != n: print("truncated: the header runs past the end of the file"); sys.exit(1)
      return b
  def u32(): return struct.unpack("<I", rd(4))[0]
  def u64(): return struct.unpack("<Q", rd(8))[0]
  def s():
      n = u64()
      if n > LIMIT: print(f"string length {n} over the {LIMIT}-byte limit: corrupt header"); sys.exit(1)
      return rd(n).decode("utf-8", "replace")
  SCALAR = {0: ("u8", "<B", 1), 1: ("i8", "<b", 1), 2: ("u16", "<H", 2), 3: ("i16", "<h", 2), 4: ("u32", "<I", 4), 5: ("i32", "<i", 4),
            6: ("f32", "<f", 4), 7: ("bool", "<?", 1), 10: ("u64", "<Q", 8), 11: ("i64", "<q", 8), 12: ("f64", "<d", 8)}
  def value(t, depth=0):
      if t == 8: return "string", s()
      if t == 9:
          if depth >= 4: print("arrays nested more than 4 deep: corrupt header"); sys.exit(1)
          et, n = u32(), u64()
          if n > LIMIT: print(f"array length {n} over the limit: corrupt header"); sys.exit(1)
          items = [value(et, depth + 1)[1] for _ in range(n)]
          return f"array[{n}] of {SCALAR[et][0] if et in SCALAR else 'string' if et == 8 else et}", items
      if t not in SCALAR: print(f"unknown metadata value type {t}: corrupt header or a newer format"); sys.exit(1)
      name, fmt, size = SCALAR[t]
      return name, struct.unpack(fmt, rd(size))[0]
  magic = rd(4)
  if magic != b"GGUF": print(f"not GGUF: magic {magic!r}"); sys.exit(1)
  ver = u32()
  if ver not in (2, 3): print(f"GGUF version {ver}: only versions 2 and 3 (little-endian) are read here; 1, or a big-endian file, would make every count below nonsense"); sys.exit(1)
  n_tensors = u64(); n_kv = u64()
  if n_tensors > 10_000_000 or n_kv > 1_000_000: print(f"{n_tensors} tensors, {n_kv} metadata pairs: implausible counts, corrupt header"); sys.exit(1)
  print(f"GGUF version {ver}, {n_tensors} tensors, {n_kv} metadata pairs")
  for _ in range(n_kv):
      k = s(); t = u32(); tn, v = value(t)
      if isinstance(v, list): shown = f"{len(v)} items, first {show(v[:3], 80)}"
      else: shown = show(v)
      print(f"{show(k)}\t{tn}\t{shown}")
  for _ in range(n_tensors):
      name = s(); nd = u32(); dims = [u64() for _ in range(nd)]; ttype = u32(); off = u64()
      print(f"tensor\t{show(name)}\tdims {dims}\ttype {ttype}\toffset {off}")
  ```

  A tensor type **number** is read against the writer's release: the integer
  types `I8`, `I16` and `I32` moved up the list as IQ types were inserted ahead
  of them, until a March 2024 llama.cpp commit pinned them at 24 to 26, so quote
  the number with the name your reader gives it and the reader's version. `strings` still surfaces the text metadata quickly.
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
