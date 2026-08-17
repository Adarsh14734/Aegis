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

There are no exceptions: no command changes anything. **The UI cannot answer an
approval.** It shows the request that is waiting and points at the terminal
where it is answered — see "Approvals" below.

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

Chain integrity is not recomputed here. The UI shells out to `aegis/verify.py`
and reports its exit code: 0 intact, 1 broken, anything else "could not be
checked". verify.py is the authority (S2) and already carries a deliberate
second copy of the hash rule; a third would be a third thing to keep in step.

## Approvals

The Approvals screen is a viewer. It reads the newest `approval_prompt` row
that has no resolving row after it, shows what is waiting, and leaves the two
buttons visible but disabled with an explanation.

There was a pty supervisor here that let the window type an answer on the
proxy's terminal. It was removed rather than shipped unverified: it had never
been executed, and it depended on a mechanism (`pty.fork`) that has hung in
this environment every time it has been tried. A UI approval path stays unbuilt
until that works and a real staleness check exists. See S6-REPORT.md.

Approvals are answered where C7 puts them: at the terminal the proxy is running
in. Nothing is lost except the buttons.
