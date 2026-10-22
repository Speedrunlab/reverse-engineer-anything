# JavaScript and Electron applications

Covers shipped JavaScript: bundled/minified web apps, Node packages, and
Electron desktop apps (where the application layer is JavaScript inside an ASAR
archive). Static and read-only; cite the sample's SHA-256.

## Electron: find and extract the app layer

An Electron app is a Chromium + Node shell wrapping your real target: the app's
JavaScript, usually in `resources/app.asar` (or an unpacked `resources/app/`).

- Locate `app.asar` inside the installed app or the package you extracted.
- Extract it into the sample subfolder: `asar extract app.asar <outdir>` (from
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
- **No map:** beautify/format the bundle to restore structure, then read it.
  Bundlers leave module boundaries (webpack chunk ids, module wrappers) you can
  navigate.
- Search before you read whole files: grep the beautified tree for the API, the
  string, the config key or the route the question is about, and work out from
  the hit.

## What to read for common questions

- **"What does it call home to"**: grep for `fetch(`, `XMLHttpRequest`,
  `WebSocket`, axios/got, and hard-coded hosts. List every distinct host and the
  code path that reaches it. This is static evidence of *what the code can do*,
  not proof a request fired, say so.
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
- An ASAR can have an `app.asar.unpacked` sibling holding native modules -
  inventory both.
