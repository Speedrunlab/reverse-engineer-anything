# JavaScript and Electron applications

Covers shipped JavaScript: bundled/minified web apps, Node packages, and
Electron desktop apps (where the application layer is JavaScript inside an ASAR
archive). Static and read-only; cite the sample's SHA-256.

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
- **Fuses and integrity:** note whether the app ships with Electron fuses that
  disable Node inspection or enforce ASAR integrity, relevant later if a live
  question comes up, and off-limits to defeat.

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
  `prettier --no-config --no-editorconfig` run from the empty `$W/scratch/`
  (Prettier 3 loads a plugin only when config names one, which `--no-config`
  blocks), or js-beautify with `--config` pointing at an empty `{}` file (its CLI
  otherwise reads a `.jsbeautifyrc` from parent directories).
  Bundlers leave module boundaries (webpack chunk ids, module wrappers) you can
  navigate.
- Search before you read whole files: grep the beautified tree for the API, the
  string, the config key or the route the question is about, and work out from
  the hit.

## What to read for common questions

- **"What does it call home to"**: collect candidate hosts with this helper,
  saved and locked as `$W/scripts/hosts.sh` (SKILL.md section 1):

  ```sh
  #!/usr/bin/env bash
  # hosts.sh <tree> <out-file>: candidate hosts, user-info masked
  set -o pipefail; umask 077
  grep -rEoh -- "(wss?|https?)://[^/ \"'<>?#]+" "$1" | sed -E 's#//[^/]*@#//<cred>@#' | sort -u > "$2"
  ```

  Run it as `"$W/scripts/run.sh" "$W/scripts/hosts.sh" "$ROOT" "$W/out/hosts.txt"`.
  Exit 0 is a result; exit 1 with an empty file means no URL matched; exit 2 is an
  error, never "no hosts". The user-info part, where keys such as a Sentry DSN key
  sit, is masked rather than mistaken for a host. Then find the call sites: `fetch(`, `XMLHttpRequest`,
  `WebSocket`, `net.request`, `https.request`, axios/got, the auto-updater feed
  (`autoUpdater.setFeedURL`, `resources/app-update.yml`, `build.publish` in
  `package.json`), crash reporting and analytics settings, and any
  Content-Security-Policy that lists allowed hosts. Separate the app's own code
  from library noise (most hosts in `node_modules` are documentation links). Answer
  as "the code **can** contact these hosts", each with its call site; it is not
  proof a request was made. Observing real traffic is a live step (SKILL.md
  section 6) that the operator can approve as a next step.
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
