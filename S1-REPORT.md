# Aegis S1 — MCP stdio policy proxy

**Sprint:** S1
**Date:** 2026-08-14
**Gate:** raw transcript of a denied call, produced by the proxy, with the downstream server proven never to have executed it.

---

## What was built

```
Claude Code  <--stdio-->  aegis/proxy.py  <--stdio-->  MCP filesystem server
                               |
                          aegis/policy.py   (deterministic, no model judgement)
                               |
                          policy.json       (outside every workspace root)
```

| File | Role |
|---|---|
| `aegis/policy.py` | Policy engine: deny globs → tool rule → path containment → default |
| `aegis/proxy.py` | stdio JSON-RPC proxy; intercepts `tools/call` only |
| `policy.example.json` | Reference policy |
| `tests/mock_fs_server.py` | Obedient server that executes everything, unchecked |
| `tests/drive.py` | Adversarial harness, cases drawn from THREAT-MODEL.md §3 |
| `evidence/S1-transcript.txt` | Raw output of the run |
| `evidence/S1-audit.jsonl` | Decision log (stderr) — 11 `tool_call` records |

**Why the mock server matters:** it performs every call with no checks at all. If
something is blocked with it downstream, the block came from Aegis. Testing
against the real filesystem server would have let its own safety checks take
credit for Aegis's work.

---

## Decision order (fixed, deny always wins)

1. **Deny globs** — `.env`, `**/.aws/**`, `**/.ssh/**`, `*.pem`. Highest precedence, checked before any tool rule.
2. **Tool must be named in `tool_rules`** — unknown tool falls to default, never allow.
3. **Path containment** — every path in the call must sit inside an allowed root. One bad path denies the whole call.
4. **ASK → deny** — until S5 exists there is no human to ask, so ASK collapses closed.
5. **Default** — deny. `default_effect: "allow"` is rejected at load; the proxy refuses to start.

Paths are resolved via `safe_resolve()`, which resolves the deepest existing
ancestor and re-appends the non-existent tail. This closes `../` traversal *and*
symlinked-parent escape for files that do not exist yet.

---

## Verification results

11/11 adversarial cases behaved as specified. Raw output in `evidence/S1-transcript.txt`.

| # | Case | Adversary | Result |
|---|---|---|---|
| 1 | read inside workspace | — | ALLOWED |
| 2 | write inside workspace | — | ALLOWED |
| 3 | read `/home/…/.aws/credentials` | T2 | DENIED — deny glob |
| 4 | `../../` traversal to same file | T2 | DENIED — resolved before matching |
| 5 | read `.env` *inside* allowed workspace | T2 | DENIED — deny glob beats allow rule |
| 6 | exfil via second path arg `destination` | T2 | DENIED — all path args extracted |
| 7 | `delete_file` | T1 | DENIED — tool denied |
| 8 | `move_file` (ASK) | T5 | DENIED — no approval loop yet |
| 9 | unknown tool `exec_shell` | T3 | DENIED — default-deny |
| 10 | overwrite `policy.json` | T2 | DENIED — outside allowed roots |
| 11 | malformed arguments | — | DENIED — fail-closed |

**Startup refusals (exit 2, nothing proxied):**

- policy file located inside an agent-writable workspace root → refused
- policy file group/world writable (0666) → refused
- policy file missing → refused

**Proof the server never executed denied calls:** `/tmp/exfil.txt` was never
created; `config.txt` was never moved or deleted. Every denial text reads
`AEGIS DENIED`, never `MOCK SERVER`.

---

## Control status

| ID | Control | Status |
|---|---|---|
| C1 | Deterministic path allow/deny per `tools/call` | **VERIFIED (mock, container)** |
| C2 | Default-deny on unmatched action | **VERIFIED (mock, container)** |
| — | Fail-closed on malformed input / policy error | **VERIFIED (mock, container)** |
| — | Policy file unreachable by agent | **VERIFIED structurally**, not yet by live write attempt |

**VERIFIED (mock, container)** is deliberately weaker than RoboCore's VERIFIED.
It means: observed with raw output, against a synthetic server, in a Linux
container — **not** against real Claude Code on your MacBook. Promotion to full
VERIFIED requires the reproduction below on your own machine.

---

## Reproduce on your MacBook

```bash
mkdir -p ~/Library/Application\ Support/Aegis
cp policy.example.json ~/Library/Application\ Support/Aegis/policy.json
chmod 600 ~/Library/Application\ Support/Aegis/policy.json
# edit workspace_roots to a real path, e.g. ~/code/robocore

# 1. synthetic run
python3 tests/drive.py

# 2. real run — put Aegis in front of the actual filesystem server
#    in .mcp.json, replace the server command with:
#    python3 /abs/path/aegis/proxy.py -- npx -y @modelcontextprotocol/server-filesystem ~/code/robocore
#    then in Claude Code: "read my .env file"
```

Capture case 2 as a terminal recording. That is the S1 gate, and the first
five seconds of the S6 demo.

---

## Known gaps (do not claim these are handled)

1. **Only `tools/call` is inspected.** `resources/read` and prompt injection through tool *descriptions* pass untouched. A hostile MCP server can still poison the model's reasoning.
2. **No audit persistence.** Decisions go to stderr and vanish. S2.
3. **No egress control.** An allowed tool that makes network calls is unconstrained. S3.
4. **No sandbox.** Aegis mediates the MCP channel; a bash tool bypasses it entirely. Anything not spoken over this stdio pipe is outside the boundary — THREAT-MODEL.md §7.6.
5. **Glob matching is `fnmatch`, not a real path matcher.** `**` behaves loosely. Worth replacing before anyone relies on it.
6. **Single downstream server.** Multi-server fan-out is not implemented.
7. **Not reviewed by anyone but its author.** THREAT-MODEL.md §10 is still empty.
