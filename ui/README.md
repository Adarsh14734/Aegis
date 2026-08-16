# Aegis desktop viewer (S6)

Tauri v2 + React + TypeScript. Fixed 1000×700, light mode only. Four screens:
Status, Activity, Approvals, Data flow.

Visual reference: `design/Aegis.dc.html`, with tokens from `design/_ds/`.

## What it is

**A viewer.** It opens `audit.db` with `SQLITE_OPEN_READ_ONLY` and reads
`policy.json` as text. It holds no write handle to either at any point.
`aegis/audit.py` stays the single writer; a second one would break the chain's
single-writer assumption and make a broken chain ambiguous between tampering
and a race.

The one exception is answering an approval, which does **not** write to the
database. It hands "y" or "n" to the approval bridge, which types it on the
proxy's terminal; `approval.py` parses it and `proxy.py` writes the resulting
rows, exactly as if a person had answered. Same code path, same rule_ids.

## Requirements

- Node 20+ (present)
- **Rust toolchain — not installed on this machine.** Without it the app cannot
  be compiled or run. `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

## Commands

```bash
npm install && npm run build     # type-check + bundle the frontend
```

```bash
npm test                         # the plain-English layer, 10 cases
```

```bash
npm run tauri dev                # needs cargo; runs the real app
```

Browser layout harness — renders the four screens with sample rows so the
design can be checked without Rust. Every screen carries a yellow SAMPLE DATA
banner; the fixture is dynamically imported only when the Tauri runtime is
absent, so the packaged app cannot reach it:

```bash
npm run build && npx vite preview --port 4173
```

## Where it reads from

| What | Path | Override |
|---|---|---|
| Audit database | `~/Library/Application Support/Aegis/audit.db` | `AEGIS_AUDIT_DB` |
| Policy | `~/Library/Application Support/Aegis/policy.json` | `AEGIS_POLICY` |
| Chain verifier | `<repo>/aegis/verify.py` | `AEGIS_HOME` |
| Approval bridge socket | next to the database, `approval.sock` | follows `AEGIS_AUDIT_DB` |

Chain integrity is not recomputed here. The UI shells out to `aegis/verify.py`
and reports its exit code: 0 intact, 1 broken, anything else "could not be
checked". verify.py is the authority (S2) and already carries a deliberate
second copy of the hash rule; a third would be a third thing to keep in step.

## The approval bridge

`bridge/aegis-approval-bridge.py` is optional and **off unless you start it**.
Without it the Approvals screen still shows what is waiting, but says plainly
that this window cannot answer and that the terminal can.

It is new attack surface. Read the header comment in that file before running
it — the short version is that anything able to write to the socket can
approve, which on a single-user machine means any code running as you.
