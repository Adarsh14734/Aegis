# Aegis S4 — credential broker

**Sprint:** S4
**Date:** 2026-08-15
**Control:** C6 — credential broker, secret never enters agent context
**Status:** **C6a VERIFIED (harness, macOS) against a fake keychain only.** The
real OS keychain path is **UNVERIFIED**. C6 as written in THREAT-MODEL.md is
not met and is not claimed. See §What this is not and §Control status.

> **Correction, 2026-08-15.** An earlier revision of this report headlined
> "63/63 with the real keyring library". That figure was real but was presented
> in a way that overstated it, in two ways that matter. It came from a
> throwaway venv rather than this machine's interpreter, so it was not
> reproducible by the reader. And decisively, the backend under that run was
> `keyrings.alt.file.PlaintextKeyring` — a plaintext **file** — so the OS
> keychain was never exercised, while the report's summary sat next to the
> claim that "secrets live in the OS keychain". The keychain integration was
> never verified by any run, and the table below now says so. The true counts
> are in §Verification.

---

## What was built

| File | Role |
|---|---|
| `aegis/broker.py` | Handle detection, keychain access, substitution, redaction, `aegis-secret` CLI |
| `bin/aegis-secret` | The documented CLI entry point |
| `aegis/policy.py` | `credentials` grants; authorization at evaluation time, no secret access |
| `aegis/proxy.py` | Substitution after ALLOW; response redaction on the way back |
| `aegis/egress.py` | `url_host()` helper, so credential host scoping reuses the egress matcher |
| `tests/s4.py` | 63 cases |
| `tests/fixtures/keyring.py` | Fake keyring so the suite never touches a real keychain |
| `tests/echo_server.py` | A server that reflects its arguments — the case redaction exists for |
| `tests/manual/keychain-check.md` | By-hand procedure for the one path that cannot be automated |
| `evidence/S4-suite.txt` | Raw output on this machine's interpreter: 65 passed, 0 failed, **2 NOT RUN**, exit 1 |
| `evidence/S4-suite-alt-backend.txt` | Same suite where §7b can also run: 68 passed, 0 failed, **1 NOT RUN**, exit 1 |

The model writes `${aegis:github_token}`. Aegis substitutes the real value
after the policy chain returns ALLOW and immediately before the frame reaches
the server. The value does not appear in the audit database, stderr, denial
frames, or any response the model sees.

---

## What this is NOT

THREAT-MODEL.md **B4** states the goal: *"Secrets never cross the boundary in
plaintext. The broker performs the operation; the agent receives a result."*

**This does not do that.** It hands the plaintext credential to the MCP server.
THREAT-MODEL.md §3 names that server as adversary **T3** — "a tool the user
installed is hostile, or was updated to become hostile." A hostile server
receives a working credential and can keep it, forward it, or use it directly.
Nothing in S4 constrains that, and response redaction does not help: a server
that wants the value simply keeps it rather than echoing it.

What S4 does achieve is narrower and still worth having:

- **The model never sees the value.** That defeats T2 — an injected instruction
  cannot exfiltrate a secret the model was never shown, and the secret cannot
  leak through the model's context into a provider's logs or a later response.
- **The value is not on disk in Aegis's own artifacts** — not in policy.json,
  not in the audit database, not in the repo.
- **Scope is enforced per handle**: a given secret is substitutable only for
  named tools and only toward named hosts.

Permitted description: *"credentials are held in the OS keychain and injected
after policy evaluation, so the model never sees them."* Forbidden: *"secrets
never leave the control plane"*, *"the agent cannot access credentials"*, or
anything implying B4 is satisfied. I have labelled the control **C6a** and left
C6 UNVERIFIED, following the C4a/C5a precedent from S3a.

Meeting B4 properly means Aegis performing the HTTP request itself and
returning only the response — which is C4 (the TLS-terminating egress proxy),
not a substitution broker. The two controls are the same piece of engineering,
and S4 is the half that can exist before it.

---

## Evaluation order and the fetch-ordering rule

```
deny_paths → DLP → egress → credentials → tool rule → containment → default
                              ↑ authorization only, no keychain access
                                            ... ALLOW ...
                                                  ↓
                                  substitution, then forward
```

**Authorization and resolution are separate steps on purpose.** `policy.py`
checks the handle against the `credentials` grant using configuration alone.
The keychain is read only after the full chain has returned ALLOW, in
`proxy.py`. A call that will be denied never causes a keychain read — verified
by pointing the fake backend at a log file and asserting the file is never
created across three denied calls (`tests/s4.py` §2).

Substitution runs *before* the audit write, so the recorded decision is the one
actually enforced. If a secret cannot be resolved, the ALLOW becomes a DENY with
`rule_id: credential_unavailable` and that is what the audit records — rather
than an ALLOW row for a call that was never sent.

Grants are `{"tools": [...], "hosts": [...]}`. Both must be present and
non-empty; either absent denies. Every URL in the call must be covered by the
handle's hosts — one unlisted URL alongside a listed one is enough to smuggle a
credential somewhere it was not granted, so that denies too. Host matching
reuses `egress.host_allowed`, and host entries reuse the same validator as
`allowed_domains`, so the two cannot drift into disagreeing about what a host
entry may look like.

---

## Disclosure

The rules, and how each is verified at byte level in `tests/s4.py` §4:

| Channel | Result |
|---|---|
| Audit database (+ `-wal`, `-shm`) | value absent; handle **name** recorded |
| Proxy stderr | value absent |
| Denial frames | value absent |
| Every frame reaching the model | value absent |

An allowed substitution records `matched allow rule; substituted credential
handle(s) github_token`. A redaction records a row with `rule_id
credential_redacted` naming the handle and the occurrence count. The chain still
verifies (`aegis/verify.py` unchanged, and the row_hash formula and schema are
untouched).

### Exceptions

**`raise ... from None` is not enough, and that was the first version of this
file.** It clears `__cause__` and suppresses *display* of the original, but
`__context__` still points at the original exception, whose traceback frames
hold the secret in their locals. Anything that walks `__context__` — a logger,
a crash reporter, a debugger, an LLM asked to explain an error — can still
reach it.

`__context__` is set from the thread's currently-handled exception at raise
time, so a helper function cannot fix it for the caller: the raise must happen
*outside* the `except` block. Every failure path in `broker.py` therefore
builds the `BrokerError` inside the handler and raises it after the block ends,
then clears `__context__` explicitly as a guard against someone moving the
raise back inside later. Confirmed empirically — the three patterns were tested
against each other, and only this one leaves `__context__` empty.

The test that caught this is in `tests/s4.py` §6: a fake keyring backend that
puts the secret into its own exception message, asserted absent from stdout,
stderr and the audit database, with no traceback printed at all.

### Response redaction

`tests/echo_server.py` reflects its arguments back, in a normal result and
inside an error string. Both come back to the model as
`[AEGIS-REDACTED:github_token]`, and both are audited. The redactor also matches
the JSON-escaped spelling of each value, because frames on the wire are JSON: a
secret containing a quote or backslash appears escaped, and a naive scan for the
raw bytes sails straight past it. Verified with a deliberately awkward value.

Redaction is **exact-match only**. A server that returns the credential base64'd,
hashed, reversed, or split across two fields is not caught and cannot be. This
stops accidental echo and naive reflection; it is not a defence against a server
that wants the value.

---

## Verification

| Suite | Result | Exit |
|---|---|---|
| `tests/s4.py` on `python3` 3.14.3, keyring 25.7.0 | **65 passed, 0 failed, 2 NOT RUN** | 1 |
| `tests/s4.py` where §7b can also run | **68 passed, 0 failed, 1 NOT RUN** | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |
| `tests/drive.py` | 6 allowed / 21 denied | 0 |

**The S4 suite exits non-zero on this machine, and should.** Two of its claims
are not established by any run here. It is not green and must not be reported
as green.

Sections 1–6 (59 checks) run against `tests/fixtures/keyring.py`, a fake module
resolved ahead of the real one on `PYTHONPATH`, so the suite never touches the
macOS login keychain. Section 7 exists to say how much of the production path
that leaves unproven, split into three separately-verifiable claims:

| | Claim | Status here |
|---|---|---|
| 7a | The real `keyring` library loads, and `broker`'s read path works through it — backend is `keyring.backends.macOS.Keyring`, a missing handle raises a `BrokerError` naming the handle with nothing chained | **6 checks pass.** Writes nothing |
| 7b | End-to-end substitution and redaction through the real library | **4 checks pass** on an interpreter with `keyrings.alt`; **NOT RUN** on this one. Uses a plaintext **file** backend, so it proves library wiring, not keychain integration |
| 7c | The real OS keychain **write** path — `aegis-secret set` through to substitution | **NOT RUN, and not automatable.** See below |

### Why 7c cannot be automated, and why that is not a skip

`keyring.backends.macOS.Keyring` accepts a keychain path — attribute
`keychain`, settable through `KEYCHAIN_PATH` — and ignores it. Read out of the
installed 25.7.0 source rather than assumed:

- the `@warn_keychain` decorator warns `"Specified keychain is ignored. See #623"`
- `api.set_generic_password(name, service, username, password)` takes the
  keychain `name` first and never references it
- it calls `SecItemAdd(q, None)` with no `kSecUseKeychain`, and
  `SecKeychainOpen` does not appear in the module at all

Every write therefore lands in the default login keychain. There is no isolated
keychain to point a test at, so the write path cannot be exercised without
writing to the developer's real credential store — which this suite is
forbidden to do. `tests/manual/keychain-check.md` is the by-hand procedure,
with cleanup; until someone runs it, 7c stays UNVERIFIED.

The suite records 7b and 7c through `mark_unverified()`, which prints them in
the summary and forces a non-zero exit. The previous version printed `SKIP`
inside an otherwise-passing run, which is the failure mode this whole project
is supposed to be allergic to: a tick next to something nobody checked.

---

## Control status

| ID | Control | Tier | Basis |
|---|---|---|---|
| C6 | Credential broker per B4 — broker performs the operation | **UNVERIFIED** | not built; substitution is a different design |
| C6a | Handle substitution, model never sees the value | **VERIFIED (harness, macOS) — fake keychain only** | 59 checks against `tests/fixtures/keyring.py`, plus 6 read-path checks against the real library |
| C6a-keychain | The OS keychain read path | **VERIFIED (harness, macOS)** | §7a: real `keyring.backends.macOS.Keyring`, miss path only, no writes |
| C6a-keychain-write | The OS keychain write path, end to end | **UNVERIFIED** | structurally unautomatable; `tests/manual/keychain-check.md` |

**What C6a actually rests on.** Every disclosure guarantee — value absent from
the audit database, stderr, denial frames and every frame reaching the model —
was established with a fake keychain supplying the value. Those guarantees are
about what Aegis does with a secret *after* it has it, so the source of the
secret does not weaken them. What is genuinely unproven is that
`aegis-secret set` followed by a real keychain read returns the same bytes that
were stored. That is one `security`-framework round trip, it is the most
boring part of the system, and it is still unverified.

**Tier definitions** are S1's: VERIFIED (harness, macOS) means observed on real
macOS hardware against the real proxy, store and verifier with raw output
captured, decisions driven by `tests/` rather than a live model session. No S4
control reaches unqualified VERIFIED, which requires a live Claude Code session
with the client's own log captured.

**To reach VERIFIED unqualified:** a live Claude Code session where the model is
told to use `${aegis:github_token}` against `api.github.com` and separately
asked to print the token, with the client's own session log captured showing the
handle in the transcript and the value nowhere. That is the same interactive
gate S2, S3a and S3b are all still waiting on.

---

## Findings

### 0. This report overstated its own evidence, and the harness helped it

The first revision claimed "63/63 with the real keyring library" as the
headline. Two separate faults produced that:

- **The harness hid its own failure.** Section 7 caught a seeding error and
  printed `seed.stderr.strip()[:160]` — 160 characters, which cut the child's
  traceback off *above* the exception line, so the cause (`ModuleNotFoundError:
  No module named 'keyrings'`) was invisible. It then printed `SKIP` and let
  the run finish green with exit 0. Fixed: `run_child()` now prints the
  command, the exit code and both streams in full, and `mark_unverified()`
  forces a non-zero exit.
- **I conflated "the real library" with "the real keychain."** The 63/63 run
  used `keyrings.alt.file.PlaintextKeyring` — a plaintext file. It never
  touched a keychain. Writing "real library, real backend" next to "secrets
  live in the OS keychain" invited exactly the wrong conclusion.

The lesson is the one S1 already recorded — *a tool reporting its own success
is not verification* — applied to my own test harness rather than to a tool
under test. A suite that can print `SKIP` and still exit 0 is a suite that will
eventually launder an unverified claim into a report.

### 1. `keyring` is a new third-party dependency in the trusted computing base

Every line of Aegis until now was stdlib. `keyring` pulls in a dependency chain
that runs inside the control plane, with access to the keychain, and B3 says the
TCB must stay small enough to audit by hand. This was specified, so it is built,
but it is a real widening and should be a conscious choice rather than an
inherited one. On macOS the alternative is the `security` CLI, which is stdlib
`subprocess` and no new dependency, at the cost of portability.

It is now installed in the default interpreter — `python3` 3.14.3, keyring
25.7.0, backend `keyring.backends.macOS.Keyring` — which it was not when this
report was first written. `keyrings.alt` is not, which is why §7b does not run
here; `python3 -m pip install keyrings.alt` closes that one gap, though it does
nothing for 7c.

### 2. The credential is in proxy memory for the process lifetime

`Redactor` holds every substituted value so responses can be scanned. That is
unavoidable for redaction and it widens the exposure window: a core dump, a
debugger, or a memory-scraping process on the same account can read them. Values
are never written anywhere from there, but "in RAM in the control plane" is
weaker than "never materialized".

### 3. Handle names leak to the server on a denied substitution

If substitution fails the call is denied and never forwarded, so the handle
name does not reach the server. But a *successful* call whose arguments contain
a handle that policy permits reveals nothing, while an argument containing an
unresolvable handle in a call that is otherwise allowed is now a denial the
model can use as an oracle: it learns which handle names exist and which are
granted for which tool and host. That is a small information leak to a possibly
injected model, inherent to giving useful denial reasons.

### 4. The CLI refuses pipes, which will annoy someone

`aegis-secret set` requires a TTY. `echo $TOKEN | aegis-secret set x` is refused
because it puts the secret in shell history and in the process table. This makes
provisioning unautomatable by design. If that becomes untenable the right answer
is a file-descriptor argument, not accepting stdin.

---

## Known gaps (do not claim these are handled)

1. **The MCP server receives the plaintext credential** (§What this is not).
   T3 is entirely undefended. This is the big one.
2. **Redaction is exact-match**; any transformation defeats it.
3. **Values live in proxy memory** for the session (finding 2).
4. **No revocation, rotation, expiry or use limits.** A grant is permanent until
   the policy changes, and Aegis cannot tell one use from a thousand.
5. **No per-call approval.** Every permitted use is silent; C7 is S5.
6. **The host scope is checked against URLs in the arguments**, so it inherits
   every S3a limitation — redirects, server-derived URLs, and DNS rebinding all
   move the destination after the check.
7. **A secret substituted into a path argument would be recorded** in the audit
   `paths` column, which is populated before substitution — so in practice it
   holds the handle, not the value. Verified for the tested shapes only.
8. **The OS keychain write path has never been executed by any test.** Storing
   via `aegis-secret set` and reading the same bytes back through the real
   macOS backend is unverified, because it cannot be automated without writing
   to the real login keychain (§Verification). It is the least interesting code
   in S4 and the only part with no automated coverage at all.
9. **`keyrings.alt` is not installed here**, so even the real-library
   end-to-end check (§7b) does not run on this machine.
10. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty.

---

## Reproduce

Expect **exit 1** with `2 NOT RUN`. That is the correct result on this machine,
not a broken suite:

```bash
python3 tests/s4.py
```

Closes 7b only — 7c remains unautomatable:

```bash
python3 -m pip install keyrings.alt && python3 tests/s4.py
```

The one path a machine cannot check for you:

```bash
open tests/manual/keychain-check.md
```
