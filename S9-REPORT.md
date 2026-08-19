# Aegis S9 — the sandbox

**Sprint:** S9
**Date:** 2026-08-18
**Control:** C11 — constrain the agent's whole process tree, not just its MCP traffic
**Status:** **VERIFIED (harness, macOS)**. Not unqualified VERIFIED: no live
Claude Code session has been run inside `aegis run`.
Suite: **67 passed, 0 failed, 0 NOT RUN**, exit 0. Every prior suite at its
documented figure.

---

## The gap this closes

S1 gap #4, repeated by every sprint since:

> Aegis mediates the MCP channel; a bash tool bypasses it entirely. Anything not
> spoken over this stdio pipe is outside the boundary — THREAT-MODEL.md §7.6.
> **Observed live:** three of four attempts on the secret went via Bash and were
> stopped by Claude Code's own permission rules, not by Aegis. Aegis alone would
> not have blocked them.

That sentence has been the honest caveat on every control for nine sprints. The
MCP layer sees the frames that cross one pipe; `npm install` running a
postinstall script, a `curl` in a shell, the agent's own native file tools, and
every subprocess of any of them, saw nothing at all.

C11 moves the same rules down to the kernel. `evidence/S9-kernel-enforcement.txt`
runs S1's own attempts inside `aegis run`:

```
$ cat $LAB/fake-home/.ssh/id_rsa
  cat: …/fake-home/.ssh/id_rsa: Operation not permitted        [exit 1]
$ python3 -c "print(open('…/.ssh/id_rsa').read())"
  Traceback … PermissionError                                  [exit 1]
$ cat $LAB/workspace/.env
  cat: …/workspace/.env: Operation not permitted               [exit 1]
$ cat $LAB/workspace/main.py
  ordinary source file                                         [exit 0]
$ echo new > $LAB/workspace/created.txt && echo WROTE-INSIDE
  WROTE-INSIDE                                                 [exit 0]
$ echo escape > /tmp/aegis-s9-escape.txt
  /bin/bash: /tmp/…: Operation not permitted                   [exit 1]
$ curl -s -w 'http=%{http_code}' https://evil.xyz/
  http=000                                                     [exit 0]
$ echo '{}' > $LAB/policy.json && echo REWROTE-POLICY
  /bin/bash: …/policy.json: Operation not permitted            [exit 1]
```

`Operation not permitted` is EPERM from the kernel. There is no Aegis in that
error, no policy layer, and nothing to ask a human about. The control preceding
it — the same files read successfully with no sandbox — is in the same file, so
a denial cannot be mistaken for an absence.

---

## Evaluating ASRT

D2: *"Wrap the vendor sandbox; do not rebuild it… Reimplementing kernel isolation
as a solo founder is a multi-month detour with a high chance of producing
something weaker."* The brief asked for that evaluation before any code, so it
was done first.

**`@anthropic-ai/sandbox-runtime` 0.0.73** (`srt`, Apache-2.0) is the
implementation D2 names — `sandbox-exec`/Seatbelt on macOS, bubblewrap on Linux,
network filtering via its own HTTP and SOCKS5 proxies. It was installed and
driven directly against files that exist, before a line of `aegis/sandbox.py`:

| Probe | Result |
|---|---|
| `cat` a denied file that exists | `Operation not permitted` |
| `cat` a denied file inside an allowed region | denied — deny beats allow, matching policy.py's precedence |
| `cat` an ordinary file in the workspace | works |
| write outside `allowWrite` | `Operation not permitted` |
| write inside | works |
| `curl` a non-allowlisted host | fails |
| `curl` an allowlisted host | 200 |
| invalid settings file | *it* refuses to run, and says it is refusing |
| exit code | passed through unchanged |

Its settings shape — `filesystem.{allowRead,denyRead,allowWrite,denyWrite}`,
`network.{allowedDomains,deniedDomains}` — maps onto policy.json without
distortion. **Decision: use it. Write no sandbox.** `aegis/sandbox.py` contains
no isolation logic and the suite asserts that (§1 greps it for hand-written
profile syntax and namespace calls).

**What that costs, stated because it is real.** ASRT is a Node package with four
dependencies and `node >= 20.11`, and `aegis-mcp` is a zero-dependency Python
package. pip cannot install it, so it is an externally-provisioned prerequisite
that `preflight()` detects and refuses without. That is a genuine widening of
what has to be present for a control to work, and it is not a widening of the
Python TCB — the kernel-facing code is Anthropic's, reviewed by people who do
this full time, which is the entire point of D2.

**One caveat worth knowing:** `srt --version` reports `1.0.0`, not the npm
package version (`0.0.73`). Anyone pinning a version by that string would be
pinning nothing.

---

## What was built

| File | Role |
|---|---|
| `aegis/sandbox.py` | policy.json → sandbox profile, digest, preflight, fail-closed establishment |
| `aegis/cli.py` | `aegis run -- <agent-command>`, `--deny-all-network`, `--print-profile` |
| `tests/s9.py` | 67 checks: real processes, real runtime, files that exist |
| `evidence/S9-suite.txt` | Suite output plus a regression run of every prior suite |
| `evidence/S9-kernel-enforcement.txt` | S1's own attempts, run inside `aegis run` |

`aegis/policy.py` is **unchanged** — no decision logic touched. S7's onboarding
is untouched: `init`, `doctor` and `uninstall` are byte-identical.

### One source of truth

The profile is generated from policy.json and nothing else, then written 0600
next to it and digested. From the real policy on this machine:

```json
{ "filesystem": {
    "denyRead":  ["/**/*.pem", "/**/.aws", "/**/.aws/**", "/**/.env",
                  "/**/.ssh", "/**/.ssh/**", "/**/id_rsa"],
    "allowWrite": ["/Users/adarsh/Library/Application Support/Aegis",
                   "/Users/adarsh/code/aegis-testlab/workspace"],
    "denyWrite": [ …the same deny patterns…,
                   "…/Aegis/KILLSWITCH", "…/Aegis/policy.json"] },
  "network": { "allowedDomains": ["api.example.com", "example.com"],
               "deniedDomains": [] } }
```

Two entries in `denyWrite` are not from `deny_paths` and are the reason the rest
of the design holds together:

- **policy.json.** The agent cannot rewrite the policy that constrains it. S1
  argued this structurally — the file sits outside every workspace root — and
  now the kernel enforces it (A7). Verified: the write fails with EPERM and
  `deny_paths` is unchanged afterwards.
- **KILLSWITCH.** The agent cannot delete the stop button. A kill switch an
  agent can remove is not a kill switch (C10). Verified: `rm -f` leaves the file
  in place.

The profile is regenerated on every launch, so an edited policy cannot leave
yesterday's rules in force. The suite asserts that a changed `deny_paths`
produces a different digest and that the new pattern is present.

---

## Finding 1 — the first translation enforced nothing, and looked right

The headline requirement is that a path denied in policy is denied by the
kernel. The first version of `_deny_globs` translated policy's `.env` into
`**/.env`, which is what ASRT's own README shows. The suite caught it
immediately: **`cat` of the ssh key succeeded inside the sandbox.**

Measured rather than guessed:

```
denyRead=["**/id_rsa","**/.env"]   cwd=/tmp/globtest      -> Operation not permitted
denyRead=["**/id_rsa","**/.env"]   cwd=~/code/aegis       -> KEYBYTES / ENVBYTES
denyRead=["/**/id_rsa","/**/.env"] cwd=~/code/aegis       -> Operation not permitted
```

**A relative glob in this runtime is rooted at the process's working directory,
not at the filesystem root.** So `**/.env` denies `.env` only under wherever the
agent happens to have been started, and `cat ~/.ssh/id_rsa` from a workspace in
`/tmp` sails straight through. Every pattern is now anchored as `/**/…`, which
the runtime does treat as filesystem-wide, and which is also the correct
translation of policy.py's semantics — it matches each pattern against the full
path *and* the basename, so a bare `.env` means "any file named .env, anywhere".

Two things are worth taking from this beyond the fix.

**The failure was silent and passed every structural check.** The profile was
valid, the runtime accepted it, `aegis run` reported a sandbox established with
seven read-denied patterns, and the audit row recorded a digest. Everything that
reads a file said yes. Only running `cat` said no. This is the same lesson S7's
doctor was built around and S8's TLS probe re-taught: a control is not verified
by its inputs looking plausible.

**A partial kernel rule is worse than none.** If the kernel denies less than the
MCP layer, the two layers disagree about what is forbidden and the weaker answer
is the one that decides — while the report claims both. `tests/s9.py` now carries
a regression guard asserting every deny pattern is absolute, which is the
specific shape of this bug rather than a general gesture at it.

A second, quieter version of the same class: paths were mixed between `/var/...`
and `/private/var/...` (macOS symlinks one to the other), because the policy path
was resolved and the data directory was not. Everything in the profile now goes
through one `_resolved()` helper, and the suite asserts every path equals its own
`resolve()`.

---

## The network residual

The brief asked that only the proxy's own egress path reach the network. **That
is not what was built, and it cannot be with this design.** Stated plainly:

The MCP proxy runs *inside* the sandbox, because the MCP client spawns it as a
child and inherits the confinement to it. Network filtering in ASRT is by
domain, applied to the whole sandbox — it cannot distinguish a request made by
`aegis/fetch.py` from one made by `curl` in a shell, because both are processes
in the same sandbox talking to the same filtering proxy. So:

- `allowedDomains` is set to policy's `allowed_domains`, and bash inside the
  sandbox **can** reach those same hosts. Observed, not assumed — the suite runs
  the curl and prints what happened (`200`).
- Everything else fails. `curl evil.xyz` returns `http=000`.
- `--deny-all-network` sets `allowedDomains: []`, which closes bash egress
  completely **and disables C4's egress with it**. Both halves verified.

What this is, honestly: before S9 a shell inside the agent could reach any host
on the internet. After S9 it can reach only the hosts policy already permits an
MCP tool to reach. That is a large reduction and it is not the same thing as
"only the proxy may reach the network".

Closing it properly means running the proxy *outside* the sandbox and giving the
sandboxed client a stdio relay to it over a permitted socket. That is a real
design, and S6's removed approval bridge is the reason it is not in this sprint:
a socket any process running as the user can talk to, built and shipped without
ever having been exercised, is precisely the mistake that report exists to
record. It needs its own sprint and its own gate.

### The data directory is writable, and what follows

`allowWrite` includes the Aegis data directory, because the proxy inside the
sandbox must write `audit.db` before every forwarded call (C3) and stage copies
into `trash_dir` (C9). A sandbox that denied it would take C1–C10 down with it —
the proxy fails closed and denies everything.

The consequence: bash inside the sandbox can also write there. `policy.json` and
`KILLSWITCH` are individually write-denied so A7 and C10 survive, but
**`audit.db` is writable from inside**. That is not new — S2 gap 1 has always
said an attacker with write access can rewrite the chain, and `verify.py`
detects edits while an external anchor is the only defence against a wholesale
rewrite. It is worth naming here because a reader could reasonably assume a
kernel sandbox protects the audit log, and it does not.

---

## Verification

| Suite | Result | Exit |
|---|---|---|
| `tests/s9.py` | **67 passed, 0 failed, 0 NOT RUN** | 0 |
| `tests/s8.py` | 109 passed, 0 failed | 0 |
| `tests/s7.py` | 138 passed, 0 failed | 0 |
| `tests/s5.py` | 80 passed, 0 failed, 1 NOT RUN | 1 |
| `tests/s4.py` | 67 passed, 0 failed, 2 NOT RUN | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |

**Tier: VERIFIED (harness, macOS)** per S1's definition — real macOS hardware,
the real sandbox runtime, real processes, files that really exist, raw output
captured, driven by `tests/` rather than a live model session.

### The seven cases the brief named

| Case | Result |
|---|---|
| bash `cat` of a `deny_paths` file fails inside | EPERM, and the same denial via `python3 open()` — not specific to one program |
| bash `curl` to any host fails | non-allowlisted host fails; with `--deny-all-network` an allowlisted one fails too |
| a write outside `workspace_roots` fails | EPERM, and the file does not appear |
| a legitimate write inside succeeds | written and present on disk |
| the MCP proxy still functions inside | proxy speaks MCP, an allowed read is forwarded, a `deny_paths` read is denied with `AEGIS DENIED`, audit rows written from inside, chain verifies |
| `aegis run` refuses when the sandbox cannot be established | exit non-zero, nothing launched, `REFUSING TO LAUNCH`, refusal recorded as `sandbox_refused` |
| the profile matches policy.json and regenerates on change | asserted both directions, with the digest |

Both layers now cover a denied path, and the suite checks they agree: the MCP
layer answers `AEGIS DENIED … rule deny_paths` with an explanation the model can
act on, and the kernel answers EPERM to anything that tries another route.

### Fail-closed, and what it records

`aegis run` loads the policy, establishes the sandbox, records establishment with
the profile digest, and only then launches. Every failure before the launch
refuses and is recorded:

```
1|aegis run|allow|sandbox_established|sandbox established via srt on darwin; profile 57bd62b2…
```

There is no flag that turns a failed sandbox into an unconfined launch. Verified
paths: no runtime (`sandbox_refused`), unloadable policy, unavailable audit log,
runtime rejects the profile. The refusal message says why a fallback would be
worse — an agent that looks sandboxed and is not is worse than one nobody
believed was.

### Not established by this sprint

- **No live Claude Code session inside `aegis run`.** The gate would be: launch
  a real session sandboxed, tell the model to read a denied file, and capture the
  client's own log showing it failing at the kernel — and, separately, confirm
  the model's native file tools are confined too, which is the half no MCP-layer
  control could ever reach.
- **Linux.** The bubblewrap branch of `preflight()` exists and has never
  executed. Nothing here has run on Linux.
- **Windows.** ASRT supports it via a dedicated user account and WFP filters;
  `preflight()` refuses outright rather than pretending.
- **That the sandbox holds against an attempt to escape it.** Nothing here
  attacks Seatbelt. §7.7 is inherited, not tested.

---

## Known gaps (do not claim these are handled)

1. **A kernel escape defeats C11 entirely** (§7.7). It is now load-bearing: it is
   the reason `cat ~/.ssh/id_rsa` fails, and it is exactly as strong as
   `sandbox-exec` and the runtime driving it. Aegis would neither prevent nor
   notice a bypass.
2. **Only agents `aegis run` launches are confined** (§7.6). An agent the user
   starts themselves gets no sandbox, and **nothing detects that** — not Aegis,
   not `aegis doctor`. Same shape as S7's stale-client gap, without S7's
   process-table check.
3. **`aegis doctor` says nothing about the sandbox.** No S7 onboarding was
   changed, by instruction. So a stale profile on disk, a missing runtime, or an
   unsandboxed setup is not reported by the command built to prove the
   installation works. `sandbox.matches_policy()` exists and is called only by
   the suite.
4. **The network residual** (§The network residual): bash inside can reach
   policy's allowed domains. Only `--deny-all-network` closes it, at C4's cost.
5. **`audit.db` is writable from inside the sandbox**, necessarily. S2 gap 1,
   now with a kernel boundary around it that does not protect it.
6. **`aegis init` does not write the sandbox profile or mention `aegis run`.**
   Onboarding a stranger into C11 is a separate piece of work.
7. **No violation reporting.** ASRT can surface Seatbelt violations from the
   system log store; Aegis does not read them, so a denied `cat` inside the
   sandbox produces an EPERM the agent sees and **no audit row at all**. The
   audit log records that a sandbox was established, not what it stopped. This
   is the largest missing piece: C11 enforces without observing.
8. **Read is allow-by-default outside `deny_paths`.** The agent can read most of
   the filesystem — source, dotfiles not matching a deny pattern, other projects.
   Only writes and the named deny patterns are constrained. A read-deny posture
   would need enumerating everything an interpreter needs, which is how a sandbox
   becomes a compatibility problem and then gets switched off.
9. **The profile is trusted once written.** It is 0600 and regenerated per
   launch, but nothing re-checks it mid-session, and a root user can edit
   anything (§7.2).
10. **`srt --version` does not report the package version**, so version pinning
    on that string is meaningless.
11. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty
    after ten sprints.

---

## Reproduce

```bash
npm install -g @anthropic-ai/sandbox-runtime && python3 tests/s9.py
```

The one worth watching, in a scratch directory with a policy that denies `.env`:

```bash
aegis run -- bash -c 'cat ~/.ssh/id_rsa; curl -s -m 5 https://evil.xyz/; echo x > /etc/x'
```

Without the runtime installed, to see the refusal:

```bash
AEGIS_SANDBOX_RUNTIME=/nonexistent aegis run -- echo should-not-run
```
