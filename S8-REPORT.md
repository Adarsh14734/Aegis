# Aegis S8 — Aegis makes the request

**Sprint:** S8
**Date:** 2026-08-18
**Controls:** C4 (promoted from C4a, **with its scope narrowed**) · C6 (promoted
from C6a, C6a **deleted**) · C3 (payload versioned, no chain invalidated)
**Status:** both **VERIFIED (harness, macOS)**, plus a live-network run of the
production resolution and TLS path. Neither reaches unqualified VERIFIED, which
still needs a live Claude Code session with the client's own log captured. That
gate was **unreachable** until now for a structural reason — see §C4's live tier
needs a fetch-capable server. The wiring it needs now exists and is verified;
the session itself is **NOT RUN**.
Suite: **109 passed, 0 failed**, exit 0. Every prior suite at its documented
figure.

---

## The one idea

C4a read a hostname out of a tool argument, checked it, and handed the call to
the MCP server to perform. C6a substituted a plaintext credential into those
arguments and handed them to the same server. Both controls were shaped by the
same limitation — **Aegis was not the one making the request** — and both
carried the same three holes because of it:

| Hole | Why it existed | S8 |
|---|---|---|
| TOCTOU | the host checked was never the host dialled | resolution happens once, in Aegis, and the address checked is the address the socket opens to |
| Redirects | an allowed host answering `302 → evil` was invisible | hops are followed one at a time and every hop re-runs the whole check |
| The credential | the plaintext went to a server §3 names as T3 | the credential goes onto Aegis's own request; the server is not in the path at all |

`aegis/fetch.py` closes all three by doing the request. For a tool declaring
`"egress": true` the MCP server is now **bypassed entirely**: it never sees the
URL, never sees the credential, never produces the response.

---

## What was built

| File | Role |
|---|---|
| `aegis/fetch.py` | Aegis as the HTTP client: resolution, address checks, manual redirects, credential attachment, byte counting |
| `aegis/audit.py` | Versioned row payload (v1/v2), four new columns, non-destructive migration |
| `aegis/verify.py` | Both hash rules, independently reimplemented; per-row version dispatch |
| `aegis/proxy.py` | `perform_egress`; the S4 substitution path removed |
| `tests/http_target.py` | A real HTTP origin that records every request it receives |
| `tests/s8.py` | 109 checks over real sockets |
| `evidence/S8-suite.txt` | Suite output plus a regression run of every prior suite |
| `evidence/S8-live-network.txt` | Real DNS, real TLS, real host — nothing injected |
| `evidence/S8-schema-compat.txt` | The real 85-row pre-S8 database, before and after migration |
| `~/code/aegis-testlab/servers/fetch_server.py` | A deliberately obedient fetch MCP server, so a live session has something to call |
| `tests/manual/c4-live-check.md` | The C4 live gate procedure. **NOT RUN** |
| `evidence/S8-live-wiring.txt` | That wiring driven end to end by a script: fetch.py reached, server bypassed |

`aegis/policy.py` is **unchanged**. The decision order, the allowlist, the SSRF
lexical checks and the credential grant logic are all exactly as S3b/S4 left
them; S8 runs *after* they return ALLOW and re-checks their conclusions against
what the network actually does.

---

## What C4 now covers, and what it does not

This is the section to read before repeating the word "C4" anywhere.

**True now, and verified:**

- A destination is checked **at the resolved address**, not at the name. A
  hostname that passes the allowlist and resolves to `10.0.0.7` is denied, with
  the address and the category in the reason. S3a said this gap "closes only in
  C4 proper, at the socket" — it is closed, and `tests/s8.py` §2 asserts the
  same host still passes the old lexical check, so what is being demonstrated
  is the new check and not an accident of the old one.
- **Every resolved address is checked, not just the one dialled.** A name
  answering with one public and one private address is refused. Picking the
  good one would have been luck.
- The socket opens to that literal address, and the hostname is used only for
  SNI, the `Host` header, and certificate validation. There is no second
  resolution for anyone to race.
- **Redirects are decisions.** Each hop re-runs allowlist, resolution, address
  category, and the credential's own host grant. A hop to a denied host is a
  denial with `rule_id: egress_redirect` naming the hop and the host — not a
  silent stop at the 302. More than five hops is `egress_redirect_limit`.
- Destination host, HTTP status, request bytes and response bytes are recorded
  on every allowed request. This is the data S6's Data flow screen was written
  against and could not have (S6 finding 1).

**Not true, and not claimed:**

- **This is not a TLS-terminating proxy.** It controls requests *Aegis makes*.
  A downstream MCP server that fetches on its own, a Bash tool with `curl`, an
  `npm install` postinstall script — all exactly as far outside the boundary as
  they were in S1. THREAT-MODEL.md §7.6 is unchanged, and the original C4's
  other half is now carried as a separate row, `C4-gateway`, marked not built.
- **Domain fronting is moot here, not solved.** Aegis chooses the SNI and the
  Host header and validates the certificate against the name it chose, so there
  is no client-supplied hostname to disbelieve. D3's reasoning still applies in
  full to any traffic Aegis does not originate.
- **The response body is returned to the model unscanned.** DLP runs on
  arguments, not on what comes back. An allowed host can return anything.
- **No port restrictions.** An allowlisted host is reachable on any port
  (S3a gap 3, unchanged).
- **The byte counts are plaintext HTTP bytes**, measured at the socket inside
  the TLS tunnel: request line + headers + body, and the same for the response.
  They are not wire bytes and say nothing about TLS overhead.

**The operator opt-in that makes the tests real.** `egress.check_url` already
let an operator permit a private address by listing it exactly in
`allowed_domains`; `fetch.address_refusal` applies the same rule to the
resolved address. That is what lets `tests/s8.py` fetch from a real origin on
127.0.0.1 instead of a mock. It is a documented feature, not a test hook — a
deployment that does not list the address gets the full refusal, which §2
verifies alongside.

---

## What C6 now covers

B4: *"Secrets never cross the boundary in plaintext. The broker performs the
operation; the agent receives a result."* S4-REPORT.md said plainly that
substitution did not meet this and that meeting it "means Aegis performing the
HTTP request itself... the two controls are the same piece of engineering."

They were. Verified at byte level in `tests/s8.py` §4 and §5:

- The origin's own request log shows the real credential in the `Authorization`
  header — so it genuinely reached the wire.
- The MCP server's own stdin log shows **no fetch call at all**: not the
  credential, not the handle, not the URL. The same log shows the non-egress
  `read_file` call arriving, so the server was demonstrably listening.
- The response the model receives has the value replaced by
  `[AEGIS-REDACTED:tok]`; the audit row names the handle and records that the
  far side echoed it back.
- The value is absent from the client stream, from proxy stderr, and from the
  audit database including `-wal` and `-shm`.

**A credential does not travel across a redirect it was not granted for.** The
grant is re-checked at every hop against the host the redirect moved to, not
the host the arguments named. A hop outside the grant is
`rule_id: credential_redirect`, and the suite asserts from the origin's log
that the secret never reached the second host.

**There is no fallback.** `Proxy.substitute` no longer substitutes: a handle on
a tool that does not declare `"egress": true` is denied with
`credential_requires_egress`. An egress call whose arguments Aegis cannot build
a request from is denied with `egress_not_performable` and a description of the
contract. Leaving the old path alive "just for those tools" would have left a
route by which a plaintext credential still reaches a server, and C6 would then
have been a claim about configuration rather than about code.

**Still not covered:** the credential necessarily reaches the host it was
granted for, and Aegis cannot constrain what that host does with it. Values
live in proxy memory for the session (S4 finding 2). Response redaction is
exact-match only. The OS keychain **write** path remains VERIFIED (manual)
only — S4-REPORT.md §7c, unchanged by this sprint.

---

## The audit schema change

Four new columns mean four new fields in the hashed payload, which changes
every `row_hash`. Done naively, upgrading Aegis would have invalidated every
audit database in existence — **the same observable event as an attack on the
log.** That is not an acceptable upgrade for the one control everything else
rests on.

So the payload is versioned per row:

```
v NULL or 1   sha256(canonical_json({id,ts,tool,effect,rule_id,reason,paths}) + prev)
v = 2         sha256(canonical_json({v,id,ts,tool,effect,rule_id,reason,paths,
                                     host,status,req_bytes,resp_bytes}) + prev)
```

Four decisions worth stating, because each is a place this could have been
built wrong:

- **`v` is NULL on old rows, not back-filled to 1.** Back-filling means
  rewriting rows, and `audit.py` has no code path that rewrites an audit row.
  This was not going to become the first one. NULL is what `ADD COLUMN` leaves
  behind, and the migration is one `ALTER TABLE ... ADD COLUMN` per column,
  which appends to the table definition and touches no stored row.
- **The version is inside the v2 payload.** A row cannot be reinterpreted under
  the other rule without invalidating itself, so "which rule applies" is not a
  flag an attacker gets to flip for free. `tests/s8.py` §7 sets `v=NULL` on a v2
  row and the verifier catches it.
- **The four fields are always present in a v2 payload**, carrying `null` when
  the decision was not a request. A field that appeared only sometimes would
  give one row shape two possible payloads, and the verifier would have to
  guess.
- **An unknown version fails.** A row declaring `v=99` is reported as
  uncheckable and exits 1. "Could not check it" must never read the same as
  "checked it and it was fine."

`verify.py` keeps its independent second implementation — now of both rules —
and reads the column list first, so a pre-S8 database with no `v` column at all
is read with the old query and verifies exactly as it always did.

**Evidence, on the real database.** `evidence/S8-schema-compat.txt` takes a
copy of this machine's actual 85-row audit log, written entirely before S8:

```
$ python3 -m aegis.verify compat.db      # before migration
OK: 85 row(s) verified, chain intact
head:   e132faa7de6d37ecbee0df2caf4d21aacb7206312af38f15b3ea8d0013cea0da

$ open with the S8 store (migrates), then verify again
85 rows, 85 with v NULL, 85 with host NULL
OK: 85 row(s) verified, chain intact
head:   e132faa7de6d37ecbee0df2caf4d21aacb7206312af38f15b3ea8d0013cea0da
```

Same head hash on both sides. A mixed chain — v1 rows with v2 rows appended —
verifies as one chain and the verifier says so rather than leaving it to be
noticed:

```
OK: 8 row(s) verified, chain intact
rules:  6 row(s) under the v1 payload (written before S8), 2 under v2. A mixed
        chain is normal after an upgrade and is not evidence of anything.
```

---

## C4's live tier needs a fetch-capable server

S1 set the bar for unqualified VERIFIED: *observed against live Claude Code,
with the client's own session log captured.* For C4 that gate was not merely
unmet, it was **unreachable**, and the reason is worth writing down because it
is the second time this project has hit it.

The testlab was wired to `@modelcontextprotocol/server-filesystem`, which
exposes **no fetch tool**. A live model asked to fetch a URL therefore has
nothing to call that crosses the proxy. It falls back to its client's own
WebFetch — a native tool, not an MCP call — which never touches Aegis. The
session then produces a transcript in which the model cheerfully fetched
something and the audit log recorded nothing, and that is very easy to read as
evidence when it is the precise opposite of evidence.

**With a filesystem-only setup, C4 is never reached at all.** Not weakened, not
partially applied: the code path does not execute, because no tool call that
would enter it ever arrives. Any claim about C4 made from such a session is a
claim about a control that did not run.

This is the same structural shape S1 recorded for `delete_file`: *"MCP-layer
mediation can never cover deletion on its own"* when the server's tool surface
omits the operation. Generalised: **an MCP-layer control can only be exercised
by a server that exposes the operation it mediates.** The tool surface decides
which of Aegis's controls are reachable, and a control nobody can reach is
indistinguishable — from the transcript — from a control that passed.

### What was set up

`~/code/aegis-testlab/servers/fetch_server.py`, wired through the proxy as a
second server alongside `filesystem`:

```json
"fetchlab": {
  "command": "python3",
  "args": ["/Users/adarsh/code/aegis/aegis/proxy.py", "--",
           "python3", "/Users/adarsh/code/aegis-testlab/servers/fetch_server.py"]
}
```

Three properties, each deliberate:

- **It is obedient.** Any request reaching it is performed with no allowlist, no
  SSRF rejection and no redirect limit. A block observed with it downstream came
  from Aegis and nowhere else — the same reasoning that makes
  `tests/mock_fs_server.py` useful, applied one layer out. A real fetch server
  with its own safeguards would take credit for Aegis's work.
- **Its schema is Aegis's argument contract** (`url`, `method`, `headers`,
  `body`). A server advertising a different shape would have the model produce
  calls denied as `egress_not_performable`, which tests the contract rather than
  the control.
- **It records every frame it receives** to `fetchlab-received.jsonl`. That file
  is the C4/C6 proof, because under S8 it must contain no `tools/call` at all.

The client's own escape routes are closed in
`~/code/aegis-testlab/.claude/settings.json`: `WebFetch`, `WebSearch`,
`Bash(curl:*)` and `Bash(wget:*)` are denied. Those are exactly how a model
answers the prompt without crossing Aegis, and leaving them open is how this
procedure produces a green transcript that means nothing. **Note what that
implies:** the routes are closed by the *client's* configuration, not by Aegis
— the same caveat S1 recorded as gap #8, and it has not changed.

### The wiring is verified; the session is not

`evidence/S8-live-wiring.txt` drives the wired chain end to end with a script —
real proxy, real fetch server, real network, the real audit database:

```
tools/list -> ['fetch']

id=3 isError=False   <!doctype html>... Example Domain ...
id=4 isError=True    AEGIS DENIED: fetch — host is not in allowed_domains
id=5 isError=True    AEGIS DENIED: fetch — link-local address (cloud instance
                     metadata lives here)

=== WHAT THE DOWNSTREAM SERVER RECEIVED ===
{"jsonrpc":"2.0","id":1,"method":"initialize",...}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}

87|fetch|allow|tool_rules.fetch|example.com|200|68|874|2
88|fetch|deny|egress_domain|||||2
89|fetch|deny|egress_domain|||||2

OK: 89 row(s) verified, chain intact
rules:  85 row(s) under the v1 payload (written before S8), 4 under v2.
```

**No `tools/call` reached the server** — not the allowed fetch, not the denied
ones. `tools/list` did, which is why the model can see the tool at all. The
allowed row carries the destination, status and both byte counts. `aegis doctor`
still exits 0 with both servers wired and now probes `fetchlab`.

That establishes the chain works and that `fetch.py` is genuinely reached. It
does **not** establish the live gate: a script is not a model, and the thing S1's
bar is actually about is what a capable model does when told to route around a
guardrail. `tests/manual/c4-live-check.md` is the procedure, with four prompts
and an explicit list of what would make it fail. It is **NOT RUN**, and C4 stays
at VERIFIED (harness, macOS) until someone runs it.

---

## Verification

| Suite | Result | Exit |
|---|---|---|
| `tests/s8.py` | **109 passed, 0 failed** | 0 |
| `tests/s7.py` | 138 passed, 0 failed | 0 |
| `tests/s5.py` | 80 passed, 0 failed, 1 NOT RUN | 1 |
| `tests/s4.py` | 67 passed, 0 failed, 2 NOT RUN | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |
| `tests/drive.py` | 4 allowed, 23 denied | 0 |

**Tier: VERIFIED (harness, macOS)** for C4 and C6, per S1's definition — real
macOS hardware, real sockets, a real HTTP origin, real SQLite, raw output
captured, decisions driven by `tests/` rather than a live model session.

**The production network path was additionally run live**
(`evidence/S8-live-network.txt`): real `socket.getaddrinfo`, real TLS, a real
host, nothing injected. `example.com` resolved to three addresses, all checked,
one dialled (an IPv6 address, as it happens), certificate validated against the
name, 200 with 68 request bytes and 874 response bytes recorded. A host off the
allowlist was refused. Dialling that same address while presenting a name no
certificate can carry is refused by certificate validation.

That evidence file also records a probe that **proved nothing and was kept
visible**: the first version of the TLS check presented `wrong-name.example.net`
and was accepted, because the address legitimately serves a certificate with a
`*.example.net` SAN. The probe was wrong, not the control. Quietly replacing it
would have been the more comfortable option and the wrong one.

### Why the suite injects a resolver

DNS is the one input a test cannot own. `fetch.resolve` takes an optional
resolver so a name can be pointed at a chosen address; production passes
nothing and the default is `socket.getaddrinfo`. It is not a bypass — whatever
the fixture returns goes through exactly the same address checks, which is the
property §2 exercises by pointing `rebind.test` at `10.0.0.7` and watching it be
refused. The live run above is what covers the real resolver.

### The eight cases the brief named

| Case | Result |
|---|---|
| SSRF via DNS resolving to a private address | denied, `egress_domain`, address and category named, nothing sent |
| Redirect from an allowed host to a denied one | denied at the hop, `egress_redirect`, hop number and host named |
| Redirect chain over 5 | denied, `egress_redirect_limit`, after following exactly 5 |
| Credential never in the arguments sent to the server, byte level | the server's stdin log contains no fetch call at all — not the value, not the handle, not the URL |
| host/status/bytes recorded on allowed requests | present in the audit row and in the chain |
| A pre-S8 database still verifies unchanged | the real 85-row log, same head hash before and after migration |
| A mixed database verifies | 6 v1 + 2 v2, one chain, both rules named in the output |
| *(added)* a v2 row downgraded to v1, and each new column edited | all detected |

---

## Findings

### 1. Four suites had to change, and none of them changed to stay green

- **`tests/s4.py` §3, §5 and part of §6** drove credentials through the
  substitution path S8 deletes. They now assert the S8 truth against a real
  HTTP origin. What they used to assert, for the record: *"the server received
  something in place of the handle"* and *"a substituted call is forwarded and
  completes"*. Both were true and both described a path whose existence was the
  gap S4-REPORT.md called "the big one". §1, §2, §4 and §7 are unchanged in
  substance. Net +2 checks.
- **`tests/tamper.py` case D and `tests/s3b.py`** simulate an attacker
  recomputing the whole chain. Their local copy of the hash rule was v1, so
  after S8 the forgery stopped validating — and case D, which exists to
  demonstrate that this attack is *not* detectable, started "passing" for the
  wrong reason. That is a defence Aegis does not have, appearing in a report by
  accident. Both simulations are now version-aware, and case D is back to its
  documented `exit 0 — not detected`.
- **`tests/drive.py`**: the two allowed-domain fetch cases were ALLOW when the
  URL was merely checked and forwarded. Now Aegis performs them, and
  `api.example.com` has no A record, so they deny at resolution. Expected counts
  moved 6/21 → 4/23 with the reason written into the file. The positive egress
  path lives in `tests/s8.py` against a local origin rather than depending on
  this machine's network.

The pattern across all four: a schema or architecture change quietly changes
what a test *means*, and the dangerous case is the one that keeps passing.

### 2. A connection refused escaped as an OSError

`send_once` caught `OSError` around the request but opened the socket outside
that block, so a refused connection propagated out of `fetch.perform` into the
proxy's pump instead of coming back as a recordable denial. Caught by the suite
on the first run, against a port nothing was listening on. Dialling an address
and being refused is an ordinary outcome, and it now returns
`rule_id: egress_failed` with a row.

### 3. Byte counting by wrapping the socket, not by reconstruction

`http.client` adds headers of its own — Host, Accept-Encoding, Content-Length,
Connection — so any attempt to compute the request size from its parts is a
guess at what the library did. A small counting wrapper around the socket
(`sendall`, and the file object `makefile` returns) counts what was actually
written and actually read. For TLS this is the plaintext inside the tunnel,
which is the number worth recording.

---

## Known gaps (do not claim these are handled)

1. **Everything in §What C4 now covers → "Not true".** Server-initiated
   requests, Bash, and anything not expressed as an egress tool call are
   untouched. `C4-gateway` is the row for that and it is not built.
2. **The egress argument contract is Aegis's, not the ecosystem's.** A tool
   whose arguments do not fit `{url, method, headers, body}` is denied.
   That is fail-closed and it **will break working setups on upgrade**, with a
   denial that explains the shape required. There is no compatibility mode; a
   fallback would be the disclosure this sprint removed.
3. **Response bodies are not scanned** for secrets, PII, or size beyond the
   5 MB read cap. An allowed host can return anything and the model gets it.
4. **No request-body DLP either.** `dlp.py` scans arguments before the call; it
   does not see the composed HTTP request.
5. **One address is dialled and no other is tried.** If the first resolved
   address is unreachable the request fails rather than falling back. Retrying
   would mean re-checking, which is correct but unbuilt.
6. **A credential is dropped by denial, not by stripping**, when a redirect
   leaves its grant. A legitimate cross-host redirect on a credentialed request
   is refused. Deliberate, and it will annoy someone.
7. **`allowed_domains` still has no port scoping** (S3a gap 3).
8. **The redirect cap is a constant**, not policy. So are the timeouts and the
   read cap.
9. **Nothing anchors the head hash off this machine** (S2 gap 2, unchanged).
   The new columns make each row bigger; they do not make the chain harder to
   rewrite wholesale.
10. **No live Claude Code session.** C4 and C6 are harness-verified. The gate
    is now *reachable* — a fetch-capable server is wired and the chain is proven
    end to end — but it has **NOT RUN**. `tests/manual/c4-live-check.md`.
11. **Reachability is a property of the server's tool surface, and nothing
    checks it.** With a filesystem-only setup C4 never executes, and neither
    Aegis nor `aegis doctor` says so: doctor proves *a* call is mediated, not
    that every control has something that can exercise it. A policy granting
    `fetch` to a server with no fetch tool is a rule that can never fire, and it
    looks identical to one that never had to. S1 gap #9 (no `tools/list`
    reconciliation) is the fix for this and is still open.
12. **The native-tool escape routes are closed by the client's config**, not by
    Aegis. `WebFetch` and `Bash(curl:*)` are denied in the testlab's
    `settings.json`; that is the agent's configuration, a user can edit it, and
    a different client may not honour it. S1 gap #8, unchanged.
13. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty
    after nine sprints.

---

## Reproduce

```bash
python3 tests/s8.py
```

The live wiring, without a model — proves `fetch.py` is reached and the server
is bypassed:

```bash
open tests/manual/c4-live-check.md
```

The compatibility claim, against your own audit log rather than a fixture — on
a copy, per the S2 operating rule:

```bash
cp ~/Library/Application\ Support/Aegis/audit.db /tmp/compat.db && python3 -m aegis.verify /tmp/compat.db && python3 -c "from aegis.audit import AuditStore; from pathlib import Path; AuditStore.open(Path('/tmp/compat.db')).close()" && python3 -m aegis.verify /tmp/compat.db
```
