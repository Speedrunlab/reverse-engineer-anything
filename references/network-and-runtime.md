# Network captures and runtime observation

Two kinds of work live here. **Reading a recorded capture** is static and needs
no special approval. **Live observation**, running the target, attaching a
debugger, driving a browser, or capturing fresh traffic, is gated (SKILL.md
section 6): approved, owned, and isolated.

## Recorded captures (static)

A saved capture is just a file. Read it; do not replay or fetch from it.

- **pcap / pcapng**: `tshark -r <file>` with a display filter for the protocol
  or host in question; `tshark -r <file> -q -z conv,tcp` for a conversation
  summary. Wireshark's GUI for exploration. Report the flows and fields you
  observed; selecting a page of packets does not prove network completeness.
- **HAR** (browser export), JSON of requests/responses. Read the entries for
  hosts, methods, headers and timing. Do not fetch the recorded URLs.
- **Saved mitmproxy flows / SAZ**: read with the matching reader
  (`mitmproxy -r <flows>` in read mode, a SAZ reader for Fiddler). Treat bodies
  as recorded evidence, not live attribution.
- **Redact.** Captures carry cookies, tokens and auth headers. Report the
  endpoints and behaviour; redact the credentials.
- Bound claims to the capture: "the recording shows requests to X", not "the
  app only talks to X", unless the capture is known-complete for that session.

## Live observation (approval-gated, isolated)

Only when static evidence cannot answer the question, and section 6's conditions
are met: approved, the artifact is owned, and it runs in a disposable VM or
container, never the host with credentials, keys or signed-in sessions, and
never a personal browser profile.

- **Run under a debugger in a sandbox.** Launch the target inside the isolated
  environment under `gdb`/`lldb` (or the platform debugger) to observe values
  that are only known at runtime. Scope to the declared behaviour; do not pivot
  into unrelated processes.
- **Browser / Electron observation.** Observe a session the operator drives, or
  drive one you launched in a throwaway profile, through the browser's debug
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
