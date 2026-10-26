# JavaScript and Electron applications

Covers shipped JavaScript: bundled/minified web apps, Node packages, Node.js
single-executable applications, and Electron desktop apps (where the
application layer is JavaScript inside an ASAR archive). Static and read-only; cite the sample's SHA-256.

## Electron: find and extract the app layer

An Electron app is a Chromium + Node shell wrapping your real target: the app's
JavaScript, in `resources/app.asar` (Windows/Linux) or
`<App>.app/Contents/Resources/app.asar` (macOS), or an unpacked `resources/app/`.

- Locate `app.asar` inside the installed app or the package you extracted (an
  installed `.app` is a directory target: SKILL.md section 1, Identity). It is a
  payload of the approved app, so it needs no new approval (SKILL.md section 5). From
  an installer, unpack without running it: a DMG or NSIS `.exe` with `7zz x`, an
  AppImage with `unsquashfs` or `7zz` (see the firmware and archives guide).
- Extract it into `$W/extracted/`: `asar extract app.asar <outdir>` (from
  the pinned `@electron/asar`). `asar list app.asar` first to see the tree
  cheaply.
- The entry point is in the extracted `package.json` (`main`). Start there.
- **Fuses and integrity:** Electron fuses are flags baked into the Electron
  binary itself (`Contents/Frameworks/Electron Framework.framework/Electron Framework`
  on macOS, the main executable on Windows and Linux), not into `app.asar`. Read
  them with the pinned `@electron/fuses` package, whose command is
  `electron-fuses read --app <App>.app > "$W/out/fuses-<name>.txt"`. Without it the
  raw wire is visible to `strings`: the 32-byte sentinel
  `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`, a version byte, a length byte, then one byte
  per fuse, `0` disabled, `1` enabled, `r` removed, in the order the package's
  source lists for that wire version (version 1 starts RunAsNode,
  EnableCookieEncryption, EnableNodeOptionsEnvironmentVariable,
  EnableNodeCliInspectArguments, EnableEmbeddedAsarIntegrityValidation,
  OnlyLoadAppFromAsar):
  `LC_ALL=C grep -aoE 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX.{2}[01r]{1,16}' <binary> | cut -c33- | od -An -c`
  (tested on a fixture). No sentinel means unknown, not disabled.
  `EnableNodeCliInspectArguments` disabled or removed means the app ignores
  `--inspect`, which bounds any approved live step; a fuse is off-limits to defeat.

## Node.js single-executable applications

A Node.js single executable (SEA) is a copy of the `node` binary with the
application's script, and optionally its assets, a V8 code cache or a heap
snapshot, injected as a resource named `NODE_SEA_BLOB`; at start-up `node` runs
that blob instead of reading a script. Nothing about it is Electron.

- **Identify:** `LC_ALL=C grep -aoE 'NODE_SEA_FUSE_[0-9a-f]{32}:[01]' <bin>`
  prints the fuse string: `:1` means a blob was injected, `:0` is a plain
  `node` binary, and no match means the fuse is not in this file: a `node` built
  against a shared `libnode` carries it in the library, and a string can be
  removed, so no match is not proof the file is not Node.
- **Extract the blob**, one named file in `out/` (not an extraction). macOS:
  `otool -l <bin> | grep -B1 -A4 'sectname __NODE_SEA_BLOB'` shows the section in
  the `NODE_SEA` segment (Node's documentation calls it `NODE_SEA_BLOB`; postject,
  and Node's own `--build-sea`, write it with two leading underscores, and that is
  the name the Mach-O tools need), and
  `segedit <bin> -extract NODE_SEA __NODE_SEA_BLOB "$W/out/sea-<name>.blob"`
  writes it (tested on a blob written by `node --experimental-sea-config`). Linux:
  the blob is an ELF note whose owner is `NODE_SEA_BLOB` (`readelf -n <bin> | grep NODE_SEA | cut -c1-120`; the note's whole payload prints
  as one hex line, so never let it through unbounded);
  write it out with the helper below, saved and locked as
  `$W/scripts/elf-note.py` (tested on a synthetic ELF). Windows: an `RT_RCDATA`
  resource named `NODE_SEA_BLOB`: `wrestool -l <exe> | grep -i NODE_SEA`, then
  `wrestool -x --raw -t 10 -n NODE_SEA_BLOB -o "$W/out/sea-<name>.blob" <exe>`.

  ```python
  # elf-note.py <elf> <owner> <out-file>: write the descriptor of the first note whose owner matches (PT_NOTE segments first, SHT_NOTE sections if there are no program headers). Nothing is loaded.
  import struct, sys
  path, want, out = sys.argv[1], sys.argv[2].encode(), sys.argv[3]
  d = open(path, "rb").read()
  if len(d) < 52 or d[:4] != b"\x7fELF":
      print("not an ELF file (or shorter than an ELF header)"); sys.exit(1)
  if d[4] not in (1, 2) or d[5] not in (1, 2):
      print(f"EI_CLASS {d[4]} EI_DATA {d[5]}: not a valid ELF header (each must be 1 or 2)"); sys.exit(1)
  cls, end = d[4], "<" if d[5] == 1 else ">"
  try:
      if cls == 2:
          phoff, shoff = struct.unpack(end + "QQ", d[32:48]); phentsize, phnum, shentsize, shnum = struct.unpack(end + "HHHH", d[54:62])
      else:
          phoff, shoff = struct.unpack(end + "II", d[28:36]); phentsize, phnum, shentsize, shnum = struct.unpack(end + "HHHH", d[42:50])
      ranges = []
      for i in range(phnum):
          ph = d[phoff + i * phentsize: phoff + (i + 1) * phentsize]
          if cls == 2:
              p_type, _, p_offset, _, _, p_filesz = struct.unpack(end + "IIQQQQ", ph[:40])
          else:
              p_type, p_offset, _, _, p_filesz = struct.unpack(end + "IIIII", ph[:20])
          if p_type == 4: ranges.append((p_offset, p_filesz))
      if not ranges:
          for i in range(shnum):
              sh = d[shoff + i * shentsize: shoff + (i + 1) * shentsize]
              sh_type = struct.unpack(end + "I", sh[4:8])[0]
              if sh_type == 7:
                  off, size = (struct.unpack(end + "QQ", sh[24:40]) if cls == 2 else struct.unpack(end + "II", sh[16:24]))
                  ranges.append((off, size))
      for off, size in ranges:
          p, stop = off, min(off + size, len(d))
          while p + 12 <= stop:
              namesz, descsz, ntype = struct.unpack(end + "III", d[p:p+12]); p += 12
              name = d[p:p+namesz].rstrip(b"\0"); p += (namesz + 3) & ~3
              desc = d[p:p+descsz]; p += (descsz + 3) & ~3
              print(f"note owner {name[:64]!r}{'...' if len(name) > 64 else ''} type {ntype} desc {descsz} bytes")
              if name == want:
                  if len(desc) < descsz: print("note is truncated by the end of the file"); sys.exit(1)
                  open(out, "wb").write(desc); print("written", out); sys.exit(0)
  except struct.error:
      print("truncated ELF: a header or table runs past the end of the file"); sys.exit(1)
  print("no note with that owner"); sys.exit(1)
  ```

- **Read the blob:** it begins with the magic bytes `20 da 43 01`, a flags word
  (bit 0: the experimental warning disabled; bit 1: a V8 heap snapshot instead
  of script source; bit 2: a code cache follows; bit 3: assets follow; bit 4:
  `execArgv` follows), then a header tail that grew by release and sits before the
  path: nothing in Node 24.0, one `execArgv` extension byte in later Node 24 and
  in Node 25, that byte plus a module-format byte in Node 26 (8, 9 or 10 bytes in
  all; `node_sea.h` at the writer's tag is the source). Then the script's path and
  its source as length-prefixed strings, each an 8-byte little-endian length
  followed by the bytes (checked on blobs from Node 25). With bit 1 clear the
  source is plain text:
  `strings -a -n 4 "$W/out/sea-<name>.blob" | head -3 | cut -c1-120 | cat -v`
  shows the path (a short name such as `main.js` needs the `-n 4`, and a printable
  length byte can trail it, as in `main.js;`) and the first lines; copy the script out and read it as a
  bundle (next section). With bit 1 set the blob holds a serialised heap, not
  source: record that limit. A code cache is V8 bytecode for the same script,
  not extra logic; assets follow as name and bytes pairs, each named in the
  inventory.
- The host is unchanged `node`: its imports and strings are the runtime's, not
  the app's. The app can still load files from disk (`createRequire`), so list
  the paths the script names as part of the surface.

## Minified and bundled JavaScript

Shipped web/Node code is usually minified and bundled. Make it readable, then
read only what the question needs.

- **Source maps are the shortcut.** If a `.map` file (or an inline
  `//# sourceMappingURL=` data URI) shipped, use it to map the bundle back to
  original file/line with a source-map consumer. A map that references original
  source paths tells you the project structure directly.
- **No map:** format the bundle to restore structure, then read it. Run the
  formatter with config and plugins off and on a copy in `$W/scratch/`, because
  a formatter searches upward for `.prettierrc.js`/`prettier.config.js` and a
  `package.json` `"prettier"` key and will load a plugin a hostile bundle planted:
  `prettier --no-config --no-editorconfig` run from a fresh empty `$W/scratch/<task>/`
  (Prettier 3 loads a plugin only when config names one, which `--no-config`
  blocks), or js-beautify with `--config` pointing at an empty `{}` file (its CLI
  otherwise reads a `.jsbeautifyrc` from parent directories).
  Bundlers leave module boundaries (webpack chunk ids, module wrappers) you can
  navigate.
- **Unminify when formatting is not enough.** An unminifier such as `wakaru`
  (`wakaru <bundle>.js --unpack -o <outdir>`, from a pinned `@wakaru/cli` install,
  run from a fresh `$W/scratch/<task>/` with `<outdir>` a new directory under
  `$W/out/`, an extraction under SKILL.md section 1) splits a bundle back into
  modules and rewrites some patterns into readable form. Its output is a rewrite
  of the bundle, never the original source: cite the bundle's digest, not the
  rewritten file.
- Search before you read whole files: grep the beautified tree for the API, the
  string, the config key or the route the question is about, and work out from
  the hit.

## What to read for common questions

- **"What does it call home to"**: collect candidate hosts with this helper,
  saved and locked as `$W/scripts/hosts.sh` (SKILL.md section 1):

  ```sh
  #!/usr/bin/env bash
  # hosts.sh <tree> <out-file>: candidate scheme://host[:port], user-info masked
  set -o pipefail; umask 077
  LC_ALL=C grep -rEaoh -- '(wss?|https?)://([A-Za-z0-9._~%!$&*+=:@-]*@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?' "$1" | sed -E 's#//[^/]*@#//<cred>@#' | sort -u > "$2"
  ```

  Run it as `"$W/scripts/run.sh" "$W/scripts/hosts.sh" "$ROOT" "$W/out/hosts-<name>.txt"`.
  Exit 0 is a result; exit 1 with an empty file means no URL matched; exit 2 is an
  error, never "no hosts". The user-info part, where keys such as a Sentry DSN key
  sit, is masked rather than mistaken for a host; a password containing `/`, `?`
  or `#` can still leave a fragment, so name `hosts-<name>.txt` in the ledger as
  secret-bearing and never hand it over. The deliverable is the host-only list,
  (tested on CSP strings, template literals and a binary file):
  `LC_ALL=C grep -aoE '(//|<cred>@)(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?(,(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?)*' "$W/out/hosts-<name>.txt" | sed -E 's#^(//|<cred>@)##' | tr ',' '\n' | LC_ALL=C sort -u > "$W/out/host-list-<name>.txt"`.
  Then find the call sites: `fetch(`, `XMLHttpRequest`,
  `WebSocket`, `net.request`, `https.request`, axios/got, the auto-updater feed
  (`autoUpdater.setFeedURL`, `resources/app-update.yml`, `build.publish` in
  `package.json`), crash reporting and analytics settings, and any
  Content-Security-Policy that lists allowed hosts. Separate the app's own code
  from library noise (most hosts in `node_modules` are documentation links). Answer
  as "the code **can** contact these hosts", each with its call site; it is not
  proof a request was made. Observing real traffic is a live step (SKILL.md
  section 6) that the operator can approve as a next step.
- **"What can the web content reach"** (Electron): read each `new BrowserWindow(`
  and its `webPreferences` (`nodeIntegration`, `contextIsolation`, `sandbox`,
  `webSecurity`, `preload`, `allowRunningInsecureContent`), each preload's
  `contextBridge.exposeInMainWorld` (the API the page is handed), and the IPC
  pairs: `ipcMain.handle`/`ipcMain.on` channel literals in the main process
  against `ipcRenderer.invoke`/`ipcRenderer.send` in preload and renderer code.
  Pair a channel only on an exact literal match; a channel built from a variable
  stays unresolved. Note `<webview>` tags, `setWindowOpenHandler`,
  `shell.openExternal` fed from page data, `utilityProcess`, and any `.node`
  native module (usually in `app.asar.unpacked`): a `require` of a `.node` file
  names a native binding, not a verified export, so route that file to the
  native guide. Each item is a static observation of a setting as written; a
  later call can change it, so none proves the posture at runtime.
- **A web app without a live browser**: when the operator supplies a HAR with
  response bodies or a saved page, write each JavaScript body to its own file in a
  new directory under `$W/out/` (the recipe is in the network guide; an
  extraction under SKILL.md section 1), then treat that directory as a bundle tree
  above. The ledger records the host each file came from, never the full URL,
  since a query string can carry a token.
- **"What config / secrets ship in it"**: look for embedded config objects,
  `.env`-style constants, API keys. Report their presence and shape; redact the
  values, do not paste them.
- **"Which libraries and versions"**: the bundle's module headers, a shipped
  `package.json`, or version strings. Cross-check against the lockfile if one
  shipped.
- **"What changed between versions"**: see
  [evidence and reporting](evidence-and-reporting.md) for diffing two extracted
  trees.

## Pitfalls

- A minified name is not the original name; after a beautify, identifiers are
  still mangled unless a source map restored them. Do not present a guessed name
  as recovered.
- Dead code is common in bundles, a code path present in the file is not a path
  that runs. Trace reachability before claiming behaviour.
- Dynamic `import()` and string-built requires mean the static call graph can be
  incomplete; bound negative claims ("no call to X found in the bundled modules
  searched").
- An ASAR can have an `app.asar.unpacked` sibling holding native modules:
  inventory both.
