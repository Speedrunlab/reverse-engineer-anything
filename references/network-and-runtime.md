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
  - **DNS names queried:** `-nr <file> -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u > "$W/out/dns.txt"`.
  - **TLS SNI (where it connects even when encrypted):** `-Y 'tls.handshake.type==1' -T fields -e ip.dst -e ipv6.dst -e tls.handshake.extensions_server_name | sort -u > "$W/out/sni.txt"`.
  - Both go to files because a name label can carry encoded data; read them with
    `wc -l` and `cut -c1-120 <file> | cat -v`.
  - **External** = any address outside RFC1918, loopback, link-local and multicast.
  - **Cleartext:** which hosts and ports carried application data in the clear,
    with the default output (which prints payload summaries) suppressed:
    `-Y '(tcp.flags.syn==1 && tcp.flags.ack==0) && (tcp.dstport in {21 23 25 80 110 143 1883 8080})' -T fields -e ip.dst -e ipv6.dst -e tcp.dstport | sort | uniq -c`
    (client SYNs only, so the destination is the server, not an ephemeral client
    port), plus `-Y 'udp.dstport==69' -T fields -e ip.dst -e ipv6.dst | sort -u` for TFTP.
    List unencrypted DNS, NTP and mDNS separately as metadata, not secrets.
  - **Credentials in the clear:** count only, e.g.
    `-Y 'http.authorization || http.cookie || ftp.request.command=="PASS"' -T fields -e frame.number | wc -l`;
    never print the field. Report that N requests carried credentials, with the
    hosts, not the values. This count covers HTTP and FTP only: for other
    cleartext protocols in the list above (POP, IMAP, SMTP, Telnet, MQTT), report
    "credentials may be present in clear" for each host rather than a count.
  - **Rule:** never run `tshark -Y` without `-q` or `-T fields` (the default output
    prints packet summaries, including credentials). Run it under `timeout`.
  Report the flows and fields you observed; a page of packets does not prove
  network completeness, and a capture is one session, not the app's whole behaviour.
- **HAR** (browser export), JSON of requests/responses. Project only non-secret
  fields rather than reading raw headers into context:
  `jq -r '.log.entries[] | (.request.method+" "+(.request.url|sub("^[a-z]+://([^/?#]*@)?";"")|split("/")[0]|split("?")[0]|split("#")[0]))' <file> | sort -u`
  (method and host only: user-info, path, query and fragment, where tokens sit,
  are dropped, including a query with no path before it)
  for the endpoints; count auth headers rather than printing them. Do not fetch
  the recorded URLs.
- **Saved mitmproxy flows / SAZ**: read with the matching reader
  (`mitmdump -n -r <flows> > "$W/out/flows.txt"`, read with targeted searches, since it prints full URLs; `-n` starts no proxy listener; never use replay options; a SAZ reader for Fiddler). Treat bodies
  as recorded evidence, not live attribution.
- **Never read a credential into context.** Captures carry cookies, tokens and
  auth headers. Select non-sensitive fields only (the projections above); report
  the endpoints and behaviour, and credentials as counts with their type and host.
- Bound claims to the capture: "the recording shows requests to X", not "the
  app only talks to X", unless the capture is known-complete for that session.

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
