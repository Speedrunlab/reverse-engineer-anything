# Android applications (APK, and AAB via bundletool)

Covers Android packages: the manifest, resources, and Dalvik/ART bytecode.
Static and read-only; cite the sample's SHA-256. An APK is a ZIP, so the archive
route applies to its container, but these tools understand its structure.

## Manifest and resources first

The manifest answers a lot before any code:

- `apktool d <app>.apk -o <outdir>` decodes the manifest and resources into
  readable form, with `<outdir>` a new extraction root `$W/extracted/apktool-<name>/`
  (never an existing directory: apktool refuses one, and `-f` would delete it).
- Search the decoded `AndroidManifest.xml` rather than reading it whole, because
  `<meta-data>` values can hold API keys:
  `grep -nE '<(manifest|uses-permission|permission|activity|activity-alias|service|receiver|provider|application|intent-filter|action)([ >/]|$)' <outdir>/AndroidManifest.xml > "$W/out/manifest-tags.txt"`.
  apktool writes one element per line, so each line is a whole tag (not cut,
  because the `<application>` line carries every flag) and `<meta-data>` is left
  out; read the file with `cat -v`. Count `<meta-data>` entries; report their
  names only. It gives the package name, declared permissions, exported
  components (activities, services, receivers, providers), intent filters, the
  SDK levels (`android:minSdkVersion`/`android:targetSdkVersion`; apktool moves
  them into `apktool.yml` under `sdkInfo`), and the `<application>` flags `android:debuggable` and `android:usesCleartextTraffic`.
  Exported components and broad permissions are where behaviour and attack
  surface concentrate.
- `aapt2 dump badging <app>.apk > "$W/out/badging.txt"` gives a quick summary
  (package, version, permissions, launchable activity) without a full decode. It
  also prints `meta-data` values, so read it with
  `grep -v '^meta-data' "$W/out/badging.txt" | cut -c1-200 | cat -v`.

## Code

- **JADX** decompiles Dalvik bytecode to readable Java/Kotlin:
  `jadx <app>.apk -d "$W/out/jadx-<name>"` (decompiler output lives in `$W/out/`; or
  the GUI for exploration). Start from the entry
  points the manifest named, not every class.
- `apktool` gives you **smali** (disassembled bytecode), lower level than JADX's
  Java, useful when the decompile is wrong or obfuscated.
- Obfuscation (R8/ProGuard renaming, string encryption) is normal. Note it; keep
  names you see as positional unless a mapping file shipped.

## Common questions

- **Permissions, and where each is used**: list `uses-permission` from the
  manifest, then map each to its guarded API in the JADX tree. For example
  `ACCESS_FINE_LOCATION` to `requestLocationUpdates`/`getLastLocation`, `CAMERA`
  to `android.hardware.camera2`/`androidx.camera`, `READ_CONTACTS` to
  `ContactsContract`, `RECORD_AUDIO` to `AudioRecord`/`MediaRecorder`. Grep for
  those APIs and for the runtime-permission calls `checkSelfPermission`,
  `requestPermissions`, and the literal `"android.permission.<NAME>"`. Cite the
  class and method (JADX line numbers are not stable across versions) and mark app
  code versus an SDK package prefix. A permission with no call in the code you
  searched is reported as exactly that, with the search boundary. One row per
  permission goes in an appendix table, not the main findings table.
- **Network endpoints**: grep the decompiled tree and resource strings
  (`res/values/strings.xml`, `assets/`) for hosts and URLs. List them; mark which
  are reached by code you can see.
- **Bundled native code**: `lib/<abi>/*.so` are native libraries; route each to
  [native and managed](native-and-managed.md).
- **Third-party SDKs**: package prefixes in the class tree and strings identify
  bundled SDKs and their rough versions.
- **Signing**: `apksigner verify --print-certs <app>.apk` reads the signing
  certificate(s); useful for provenance and version continuity.

## Pitfalls

- An AAB (`.aab`) is a publishing format, not an installable APK. apktool and
  `aapt2` take APKs: convert first with
  `bundletool build-apks --bundle=<app>.aab --output=<$W/out/app>.apks --mode=universal`,
  then `7zz x <app>.apks -o<$W/extracted/apks>` to get `universal.apk` (or read
  the manifest with `bundletool dump manifest --bundle=<app>.aab`). JADX opens an
  `.aab` directly. The converted APK is signed with a debug key if one exists, or
  left unsigned (with the sandboxed `HOME` there is none), so its signature says
  nothing about who published the app; read signing from the original.
- `assets/` and `res/raw/` can hold a second payload (a bundled JS app, a model,
  an encrypted blob), inventory them and route each.
- Reflection and dynamic class loading (`DexClassLoader`, loading a dex from
  assets or the network) make the static call graph incomplete; bound negative
  claims and flag the dynamic-load site as the boundary.
