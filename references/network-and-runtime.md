# Network captures and runtime observation

Two kinds of work live here. **Reading a recorded capture** is static and needs
no live-session envelope; the section 0 authorisation gate still applies (the
capture is a sample). **Live observation**, running the target, attaching a
debugger, driving a browser, or capturing fresh traffic, is gated (SKILL.md
section 6): approved, authorised (owned, vendor-consented, or sanctioned by the
security lead), and isolated.

## Recorded captures (static)

A saved capture is just a file. Read it; do not replay or fetch from it.

- **pcap / pcapng**: always pass `-n` (no name resolution, no lookups). Start with
  `capinfos <file>` (span, snaplen, counts) and `tshark -nr <file> -q -z io,phs`
  (the protocol hierarchy). Then answer the usual questions without printing
  payloads:
  - **Hosts and protocols:** `-q -z conv,ip -z conv,ipv6` and `-q -z conv,tcp -z conv,udp`
    (`conv,ip` alone misses IPv6 and would make a "no external host" claim wrong).
  - **DNS names queried:** `-nr <file> -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u > "$W/out/dns-<name>.txt"`.
  - **TLS SNI (where it connects even when encrypted):** `-Y 'tls.handshake.type==1' -T fields -e ip.dst -e ipv6.dst -e tls.handshake.extensions_server_name | sort -u > "$W/out/sni-<name>.txt"`.
  - Both go to files because a name label can carry encoded data; read them with
    `wc -l` and `cut -c1-120 <file> | cat -v`.
  - **External** = any address outside RFC1918, loopback, link-local, multicast,
    0.0.0.0/8, 255.255.255.255, 100.64.0.0/10 (carrier NAT) and, for IPv6, `::1`,
    `fe80::/10`, `fc00::/7` and `ff00::/8`. The `conv` tables count both
    directions: "the device contacted X" needs the device as the initiator (its SYN,
    or its first packet to X).
  - **Cleartext:** which hosts and ports carried application data in the clear,
    with the default output (which prints payload summaries) suppressed:
    `-Y '(tcp.flags.syn==1 && tcp.flags.ack==0) && (tcp.dstport in {21 23 25 80 110 143 1883 8080})' -T fields -e ip.dst -e ipv6.dst -e tcp.dstport | sort | uniq -c`
    (client SYNs only, so the destination is the server, not an ephemeral client
    port), plus `-Y 'udp.dstport==69' -T fields -e ip.dst -e ipv6.dst | sort -u` for TFTP.
    List unencrypted DNS, NTP and mDNS separately as metadata, not secrets. Also
    read the cleartext protocols (http, ftp, telnet, smtp, pop, imap, mqtt) from the
    `io,phs` hierarchy, which catches them on other ports. Neither filter sees a
    flow that began before the capture or an unknown protocol on an unlisted port:
    bound a "no cleartext" claim to that.
  - **Credentials in the clear:** count only, e.g.
    `-Y 'http.authorization || http.cookie || ftp.request.command=="PASS"' -T fields -e ip.dst -e ipv6.dst | sort | uniq -c`
    (a count per destination host); never print the field. Report that N requests
    carried credentials, with the hosts, not the values. This count covers HTTP and FTP only: for other
    cleartext protocols in the list above (POP, IMAP, SMTP, Telnet, MQTT), report
    "credentials may be present in clear" for each host rather than a count.
  - **Rule:** never run `tshark -Y` without `-q` or `-T fields` (the default output
    prints packet summaries, including credentials). Run it under `timeout`, and
    through `run.sh` with the filter passed as an argument and `pipefail` on, so a
    rejected filter is an error, not an empty file:
    `"$W/scripts/run.sh" bash -c 'set -o pipefail; timeout 600 tshark -nr "$1" -Y "$2" -T fields -e dns.qry.name | sort -u > "$3"' _ <file> 'dns.flags.response==0' "$W/out/dns-<name>.txt"`.
  - **Field names and odd ports:** `tshark -G fields | grep -i '<term>' | cut -f2,3`
    lists the display-filter fields before you write a filter (a mistyped field
    is an error, which `pipefail` surfaces). A known protocol on a non-standard
    port is decoded with `-d`, for example `-d tcp.port==8883,mqtt`.
  Report the flows and fields you observed; a page of packets does not prove
  network completeness, and a capture is one session, not the app's whole behaviour.
- **HAR** (browser export), JSON of requests/responses. Project only non-secret
  fields rather than reading raw headers into context:
  `jq -r '.log.entries[] | (.request.method+" "+(.request.url|sub("^[a-z]+://([^/?#]*@)?";"")|split("/")[0]|split("?")[0]|split("#")[0]))' <file> | sort -u | cat -v`
  (method and host only: user-info, path, query and fragment, where tokens sit,
  are dropped, including a query with no path before it)
  for the endpoints. Count credentials per host without printing them; header
  names are matched case-insensitively, because HTTP/2 exports write them in
  lower case (an exact `"Authorization"` match missed a lower-case `cookie`;
  reproduced):
  `jq -r '.log.entries[].request | select([.headers[]?.name | ascii_downcase] | any(. == "authorization" or . == "proxy-authorization" or . == "cookie")) | .url | sub("^[a-z]+://([^/?#]*@)?";"") | split("/")[0] | split("?")[0] | split("#")[0]' <file> | LC_ALL=C sort | uniq -c`.
  Also count URLs with user-info or a secret-named query key, and bound a zero to
  what the export kept (browsers can omit cookies and bodies). Do not fetch the
  recorded URLs.
  **Scripts out of a HAR**, for static analysis of a web app (the JavaScript
  guide): index the JavaScript entries, then write each body to a fixed name in a
  new directory `$ROOT` under `$W/out/` (an extraction, SKILL.md section 1; tested
  on a fixture):

  ```sh
  jq -r '.log.entries | to_entries[] | select((.value.response.content.mimeType // "") | test("javascript")) | "\(.key)\t\(.value.response.content.encoding // "text")\t\(.value.request.url)"' <file> > "$ROOT/index.tsv"
  while IFS=$'\t' read -r i enc url; do
    if [ "$enc" = base64 ]; then jq -r ".log.entries[$i].response.content.text" <file> | base64 -d > "$ROOT/script-$i.js"
    else jq -r ".log.entries[$i].response.content.text" <file> > "$ROOT/script-$i.js"; fi
  done < "$ROOT/index.tsv"
  ```

  `index.tsv` holds full URLs, so it is secret-bearing; the ledger cites hosts.
  To test a reimplementation against recorded behaviour, derive the endpoint and
  shape list from the capture and write a local stub with normal coding tools;
  recorded values are never replayed to the real host.
- **Protobuf and gRPC bodies.** A body with content type `application/x-protobuf`,
  `application/grpc` (`+proto`), `application/grpc-web+proto` or
  `application/grpc-web-text` is a binary message, not JSON. Get one body out
  as a file, never into context: from a HAR,
  `jq -r '.log.entries[<i>].response.content | select(.encoding == "base64") | .text' <file> | base64 -d > "$W/out/body-<name>-<i>.bin"`
  when the entry says `"encoding": "base64"` (an entry without it holds text,
  and this form writes an empty file for it: check the size). A `grpc-web-text`
  body is base64 on top, each frame usually encoded and padded on its own (the
  protocol does not promise the boundary; the loop below copes either way): save
  the text first,
  `jq -r '.log.entries[<i>].response.content | if .encoding == "base64" then (.text // empty | @base64d) else (.text // empty) end' <file> > "$W/out/body-<name>-<i>.b64"`
  (Chrome records this content type with `"encoding": "base64"`, one more layer
  over the body's own, and `@base64d` peels it; an entry without `text` leaves the
  file empty, where a bare `.text` would write `null` and the loop would decode it
  to three bytes: check the size, and that the file holds base64 text, not frames),
  then decode it chunk by chunk into a different file,
  `grep -oE '[A-Za-z0-9+/]+=*' "$W/out/body-<name>-<i>.b64" | while read -r c; do printf '%s' "$c" | base64 -d; done > "$W/out/body-<name>-<i>.bin"`
  (`base64 -d` on the whole body fails at the first mid-stream padding and, on
  macOS, writes nothing; a loop that reads and writes one name truncates its
  input first; both tested). From a
  pcap, only a
  cleartext stream or one the operator's own key log decrypts
  (`-o tls.keylog_file:<file>`, a secret staged in the environment):
  `"$W/scripts/run.sh" bash -c 'set -o pipefail; timeout 600 tshark -nr "$1" -Y grpc.message_data -T fields -e grpc.message_data | tr , "\n" | sed -n "$2p" | xxd -r -p > "$3"' _ <file> <n> "$W/out/body-<name>-<n>.bin"`
  (one line per message once `tr` splits the comma-joined occurrences a packet can
  carry, and a zero-length message adds no field, so `<n>` counts the lines, not
  the stream's messages; the field is the message with its frame head already
  removed, inflated when the frame is flagged compressed and `grpc-encoding` is
  gzip or deflate, left compressed for other encodings: Wireshark's dissector
  and the `tshark` man page). A gRPC body from a HAR is framed: one
  byte (0 plain, 1 compressed as `grpc-encoding` says), four bytes big-endian
  length, then the message, repeated. Take the first message by its declared
  length, `len=$((0x$(xxd -p -s 1 -l 4 <body>))); if [ "$len" -eq 0 ]; then : > <msg>; else tail -c +6 <body> | head -c "$len" > <msg>; fi`
  (tested; `tail -c +6` alone is right only for a single-frame body, and the
  branch is there because `head -c 0` is an error on macOS), decompress it if
  flagged, and take the rest with `tail -c +$((6 + len)) <body> > <rest>` for the
  next frame (`tail` counts from 1, so `5 + len` starts one byte early; tested).
  Decode an unframed message without a schema (`<msg>` from the cut, a `tshark`
  line's file, or the whole body when the content type is `application/x-protobuf`,
  which has no frame) with `protoc --decode_raw < <msg> > "$W/out/decode-<name>-<i>.txt"`:
  it prints field numbers and raw values, and a length-delimited field may be a
  string, bytes, a nested message or packed numbers, so names and types stay
  inferences until the operator supplies the `.proto`
  (`protoc --proto_path=<dir> --decode=<pkg.Message> <file>.proto < <msg>`;
  the schema is theirs, never fetched). gRPC-web's last frame (flag bit `0x80`)
  is the trailer block, `grpc-status` and `grpc-message` as header text.
- **Saved mitmproxy flows**: `mitmdump -n -r <flows> > "$W/out/flows-<name>.txt"`,
  read with targeted searches, since it prints full URLs; `-n` starts no proxy
  listener; never use replay options. Treat bodies as recorded evidence, not live
  attribution.
- **Fiddler `.saz`**: a ZIP. `7zz x` it into a new extraction root; `raw/NN_c.txt`
  and `raw/NN_s.txt` are the raw request and response of session NN, headers and
  cookies included, so query them as you would a HAR (hosts and counts, never
  printed) and name the root secret-bearing. `_index.htm` lists the sessions.
- **QUIC / HTTP/3 qlog** (JSON; aioquic and others write it): events only, no
  bodies. `jq -r '.traces[].events[] | if type == "array" then "\(.[1]):\(.[2])" else .name end' <file> | sort | uniq -c`
  gives the event mix for both the array and the object event forms (tested on a
  fixture); select one event type's fields with `.[3]` or `.data`. A qlog is one
  endpoint's own view of one connection: pair it with the pcap when both exist,
  and do not read a loss or timing claim from it alone.
- **Never read a credential into context.** Captures carry cookies, tokens and
  auth headers. Select non-sensitive fields only (the projections above); report
  the endpoints and behaviour, and credentials as counts with their type and host.
- Bound claims to the capture: "the recording shows requests to X", not "the
  app only talks to X", unless the capture is known-complete for that session.

## Logic-analyser and signal recordings (static)

A saved logic-analyser capture (`.sr` from PulseView, `.vcd`, a CSV of samples)
is a file: decoding it touches no hardware. The tool is `sigrok-cli` with
libsigrokdecode.

- `sigrok-cli -L | cat -v` lists the installed decoders; `sigrok-cli -i <file>.sr --show`
  prints the recording's sample rate and channel names (an `.sr` is a ZIP whose
  `metadata` member holds the same).
- Decode with the decoder, its wiring and its settings named explicitly, into a
  file: `sigrok-cli -i <file>.sr -P uart:rx=D0:baudrate=115200 -A uart=rx-data > "$W/out/decode-<name>.txt"`
  (`-I vcd` when the format is not detected; stack decoders with commas, for
  example `-P spi:clk=D0:mosi=D1,sdcard_spi`). Channel names must be the
  recording's own; baud rate, wiring and protocol are the operator's inputs,
  never guessed.
- Decoded bytes are sample data: read the file with counts and `cut -c1-120 | cat -v`.
  Empty output means that decoder saw nothing at those settings, not that the bus
  was silent; a decode error at a sample range is a finding about the settings
  before it is one about the device.

## Live observation (approval-gated, isolated)

Only when static evidence cannot answer the question, and section 6's conditions
are met: approved, authorised (owned, vendor-consented, or sanctioned by the
security lead), and it runs in a disposable VM (a
container is not enough for untrusted native code; SKILL.md section 6), never the
host with credentials, keys or signed-in sessions, and never a personal browser
profile.

- **Run under a debugger in a sandbox.** Launch the target inside the isolated
  environment under `gdb`/`lldb` (or the platform debugger) to observe values
  that are only known at runtime. Scope to the declared behaviour; do not pivot
  into unrelated processes.
- **Browser / Electron observation.** Inside the isolated environment only, with a
  throwaway profile: observe a session the operator drives there, or drive one you
  launched, through the browser's debug
  protocol. Read only the page under test. Do not attach to an existing,
  signed-in browser. Record what you observed; keep it inside the approved
  scenario.
- **Capture fresh traffic** only in the controlled environment, against the
  owned target, with an interception proxy you configured for that sandbox.
  Capturing traffic that is not yours, or on a shared network, is out of scope.
- **An owned Android device or emulator**, inside the isolated environment, with
  `adb` pointed at that device only (`adb devices` recorded first):
  `adb shell dumpsys package <pkg>`, `adb logcat -d`, `adb shell pm path <pkg>`
  then `adb pull` to retrieve an installed APK as a new sample (hash it, new
  ledger entry). Never `adb install` the sample on, or `adb root`, the operator's
  own phone. Instrumentation (Frida, `strace`, `ltrace`) is live too: inside the
  VM, within the envelope, against the declared process only.

## Reconciling static and runtime evidence

- Static tells you what the code *can* do; runtime tells you what it *did* in the
  observed session. Keep the two labelled distinctly in the ledger.
- A runtime observation is one session's behaviour, not a universal law, note
  the inputs and environment that produced it.
- When runtime contradicts static (a path you thought dead actually ran, or vice
  versa), that contradiction is a finding: record both and the reconciliation.

## Pitfalls

- "I ran it and it did X" requires the isolation and approval above; without
  them, stay static and say the question needs live analysis.
- Timing, TLS pinning and anti-debug checks can change behaviour under
  observation, note when the environment may have altered what you saw.
