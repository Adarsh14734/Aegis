"""Aegis S7 — `aegis doctor`.

The point of this command is that it does not take anyone's word for anything,
including its own. Reading a `.mcp.json` and finding the word "aegis" in it
proves that a config file contains a string. What it does not prove is that a
tool call leaving the agent reaches the policy engine, or that anything is
written down when it does.

So the last check runs the configured server command exactly as the MCP client
would, speaks real MCP to it, sends a real `tools/call` for a path the policy
should refuse, and then reopens the audit database to confirm a row appeared
for it and that the chain still verifies with that row in it. If the proxy is
not in the pipe, there is no denial and no row, and doctor exits non-zero.

Safety rule, and it is why the structural check has to come first: the probe is
only ever sent through a command already shown to be an Aegis proxy invocation.
Sending "read my ssh key" to a bare filesystem server would be doctor executing
the attack it is supposed to be testing for.
"""

import argparse
import json
import os
import queue
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import clients
from .audit import AuditError, AuditStore, default_db_path
from .policy import Effect, Policy, PolicyError
from .proxy import default_policy_path

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
SYMBOL = {PASS: "  ok  ", FAIL: " FAIL ", WARN: " warn ", SKIP: " skip "}

VERIFIER = Path(__file__).with_name("verify.py")

# Candidate probe targets, in order. The first one the loaded policy predicts a
# DENY for is used. All of them are non-existent files: doctor must not depend
# on the user actually having an ssh key, and a probe that reads a real secret
# to prove the secret cannot be read would be self-defeating.
PROBE_CANDIDATES = (
    ("~/.ssh/aegis-doctor-probe", "a file in your ssh directory"),
    ("~/.aws/aegis-doctor-probe", "a file in your aws credentials directory"),
    ("~/.aegis-doctor-probe.env", "a .env file in your home directory"),
    ("/etc/aegis-doctor-probe", "a file in /etc"),
)


@dataclass
class Check:
    name: str
    status: str
    lines: list[str] = field(default_factory=list)


class Report:
    def __init__(self):
        self.checks: list[Check] = []

    def add(self, name: str, status: str, *lines: str) -> Check:
        check = Check(name, status, [l for l in lines if l])
        self.checks.append(check)
        return check

    @property
    def failed(self) -> bool:
        return any(c.status == FAIL for c in self.checks)

    def render(self) -> None:
        for check in self.checks:
            print(f"[{SYMBOL[check.status]}] {check.name}")
            for line in check.lines:
                print(f"           {line}")


# ---------------------------------------------------------------------------
# talking MCP to whatever the client was told to launch
# ---------------------------------------------------------------------------


class Chain:
    """The configured server command, run the way the MCP client runs it."""

    def __init__(self, argv: list[str], env: dict, cwd: Path):
        self.argv = argv
        self.env = env
        self.cwd = cwd
        self.proc: subprocess.Popen | None = None
        self.lines: queue.Queue = queue.Queue()
        self.stderr: list[str] = []

    def __enter__(self) -> "Chain":
        environ = {**os.environ, **{k: str(v) for k, v in (self.env or {}).items()}}
        self.proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self.cwd),
            env=environ,
        )
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def _pump_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        for raw in self.proc.stdout:
            self.lines.put(raw)
        self.lines.put(b"")

    def _pump_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for raw in self.proc.stderr:
            self.stderr.append(raw.decode("utf-8", "replace").rstrip())

    def send(self, message: dict) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def await_id(self, request_id, timeout: float) -> dict | None:
        """The response to one request, ignoring notifications and log frames."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                raw = self.lines.get(timeout=remaining)
            except queue.Empty:
                return None
            if not raw:
                return None  # stdout closed: the chain died
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message


def _entry_argv(entry: dict) -> list[str]:
    return [entry["command"]] + [a for a in (entry.get("args") or []) if isinstance(a, str)]


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


def _check_policy(report: Report) -> Policy | None:
    path = default_policy_path()
    try:
        policy = Policy.load(path)
    except PolicyError as exc:
        report.add(
            "Policy file exists and parses", FAIL,
            f"{path}", str(exc),
            "Run `aegis init` to write one.",
        )
        return None
    report.add(
        "Policy file exists and parses", PASS,
        f"{path} (mode {oct(path.stat().st_mode & 0o777)})",
        f"{len(policy.tool_rules)} tool rules, default effect "
        f"'{policy.default_effect.value}', {len(policy.deny_paths)} deny patterns",
    )

    # Policy.load already refuses this, so reaching here means it holds — but a
    # user reading doctor's output should see the property stated, not have to
    # infer it from the absence of an error.
    roots = "\n           ".join(str(r) for r in policy.workspace_roots)
    report.add(
        "Policy file is outside every workspace root", PASS,
        f"policy: {path}",
        f"workspace roots: {roots}",
        "The agent can write anywhere inside a workspace root, so a policy "
        "inside one would be a policy the agent can rewrite.",
    )
    return policy


def _read_head(db: Path) -> tuple[int, str]:
    if not db.exists():
        return 0, ""
    try:
        conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0)
    except (sqlite3.Error, ValueError):
        conn = sqlite3.connect(str(db), timeout=10.0)
    try:
        row = conn.execute(
            "SELECT id, row_hash FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.Error:
        return 0, ""
    finally:
        conn.close()
    return (int(row[0]), str(row[1])) if row else (0, "")


def _read_row(db: Path, row_id: int) -> dict | None:
    try:
        conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0)
    except (sqlite3.Error, ValueError):
        conn = sqlite3.connect(str(db), timeout=10.0)
    try:
        row = conn.execute(
            "SELECT id, tool, effect, rule_id, reason FROM audit WHERE id = ?",
            (row_id,),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    return dict(zip(("id", "tool", "effect", "rule_id", "reason"), row))


def _run_verifier(db: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db)],
        capture_output=True, text=True, timeout=120,
    )


def _check_audit(report: Report) -> Path:
    db = default_db_path()
    try:
        store = AuditStore.open(db)
        store.close()
        report.add(
            "Audit database is writable", PASS,
            f"{db} (mode {oct(db.stat().st_mode & 0o777)})",
        )
    except AuditError as exc:
        report.add("Audit database is writable", FAIL, f"{db}", str(exc))
        return db

    done = _run_verifier(db)
    output = (done.stdout + done.stderr).strip().splitlines()
    first = output[0] if output else "(no output)"
    if done.returncode == 0:
        empty = (
            "The log is empty. An empty chain is a valid chain — this says "
            "nothing has been recorded yet, not that nothing has happened."
            if _read_head(db)[0] == 0 else ""
        )
        report.add("Audit chain verifies", PASS, first, empty)
    else:
        report.add(
            "Audit chain verifies", FAIL, first,
            f"verifier exit {done.returncode}",
            "The record of what happened has been altered or truncated. "
            "Nothing below it can be cited as evidence.",
        )

    anchor = db.parent / "aegis-head.txt"
    if not anchor.exists():
        report.add(
            "Head anchor", WARN,
            f"none at {anchor}",
            "Written when a proxy shuts down cleanly. Without it, rows deleted "
            "off the end of the log are invisible to the verifier.",
        )
    elif done.returncode == 0:
        report.add(
            "Head anchor matches", PASS,
            f"{anchor}",
            "Local and unsigned: anyone who can rewrite the database can rewrite "
            "this too. Keep a copy of the head hash off this machine.",
        )
    else:
        report.add(
            "Head anchor matches", FAIL,
            f"{anchor} — the verifier rejected the chain, see above",
        )
    return db


def _check_keyring(report: Report, policy: Policy | None) -> None:
    declared = sorted(policy.credentials) if policy else []
    try:
        import keyring  # noqa: PLC0415 - the point of the check is the import

        backend = type(keyring.get_keyring()).__name__
        report.add(
            "Credential storage (keyring)", PASS,
            f"backend: {backend}",
            f"handles granted in policy: {', '.join(declared) or 'none'}",
        )
        return
    except Exception as exc:  # noqa: BLE001 - a broken backend must read like a missing one
        detail = f"{type(exc).__name__}: {exc}"

    if declared:
        report.add(
            "Credential storage (keyring)", FAIL,
            detail,
            f"policy grants {', '.join(declared)}, so every call carrying one of "
            f"those handles will be denied.",
            "Install it with: pip install 'aegis-mcp[keyring]'",
        )
    else:
        report.add(
            "Credential storage (keyring)", WARN,
            detail,
            "No credential handles are granted in policy, so nothing needs it "
            "today. Calls carrying a ${aegis:...} handle would be denied, not "
            "sent unprotected.",
            "Install it with: pip install 'aegis-mcp[keyring]'",
        )


def _check_wiring(report: Report, project: Path) -> list[tuple[clients.Detected, str]]:
    found = clients.detect(project)
    wired: list[tuple[clients.Detected, str]] = []
    loose: list[str] = []
    lines: list[str] = []

    for det in found:
        for name in det.wrapped_servers():
            wired.append((det, name))
            lines.append(f"{name} -> Aegis proxy   ({det.path})")
        for name in det.unwrapped_servers():
            loose.append(f"{name} ({det.path})")

    if not found:
        report.add(
            "MCP configuration points at the proxy", FAIL,
            f"no MCP server configuration found for {project}",
            "Looked in: "
            + ", ".join(str(p) for _, p, _ in clients.candidate_locations(project)),
            "Run `aegis init` in the project directory.",
        )
        return wired

    if not wired:
        report.add(
            "MCP configuration points at the proxy", FAIL,
            *lines,
            "Servers configured, none of them through Aegis: " + ", ".join(loose),
            "Every tool call these servers receive is unmediated and unrecorded.",
            "Run `aegis init` to route them through the proxy.",
        )
        return wired

    check = report.add("MCP configuration points at the proxy", PASS, *lines)
    if loose:
        report.add(
            "Servers NOT going through Aegis", WARN,
            *loose,
            "These are outside the boundary entirely. Their tool calls are not "
            "checked and not recorded.",
        )
    return wired


def _pick_probe(policy: Policy, cwd: Path) -> tuple[str, str, str, str] | None:
    """(tool, path, human description, predicted rule_id) or None.

    The tool is chosen from the policy's own *allow* rules where possible, so a
    denial can only have come from the path check. An allowed tool refused on a
    path is a much stronger signal than an unknown tool refused by default-deny,
    which any broken pipe could imitate.
    """
    preferred = ("read_text_file", "read_file", "get_file_info", "list_directory")
    tools = [t for t in preferred if policy.tool_rules.get(t, {}).get("effect") == "allow"]
    tools += [
        t for t, rule in sorted(policy.tool_rules.items())
        if rule.get("effect") == "allow" and t not in tools
    ]
    tools = tools or ["read_text_file"]

    for tool in tools:
        for raw, description in PROBE_CANDIDATES:
            path = str(Path(raw).expanduser())
            decision = policy.evaluate(tool, {"path": path}, cwd)
            if decision.effect is Effect.DENY:
                return tool, path, description, decision.rule_id
    return None


def _check_live(
    report: Report, policy: Policy, db: Path, wired: list, project: Path, timeout: float
) -> None:
    if not wired:
        report.add(
            "PROOF: a real tool call is denied and recorded", FAIL,
            "not attempted — no configured server runs through the Aegis proxy.",
            "Doctor will not send a probe through an unwrapped server: the "
            "server would execute it, which is the thing being tested for.",
            "Nothing here shows Aegis mediating anything. Treat this setup as "
            "having no MCP-layer control at all.",
        )
        return

    probe = _pick_probe(policy, project)
    if probe is None:
        report.add(
            "PROOF: a real tool call is denied and recorded", FAIL,
            "could not find a path this policy refuses — every candidate probe "
            "target was permitted.",
            "Candidates: " + ", ".join(raw for raw, _ in PROBE_CANDIDATES),
            "That is itself a finding: check deny_paths and workspace_roots.",
        )
        return
    tool, path, description, predicted_rule = probe

    det, server = wired[0]
    entry = det.servers[server]
    argv = _entry_argv(entry)
    before_id, _ = _read_head(db)

    lines = [
        f"server '{server}' from {det.path}",
        f"ran: {' '.join(argv)}",
        f"asked it to open {path} ({description}) with the '{tool}' tool, "
        f"which this policy otherwise allows",
    ]

    try:
        with Chain(argv, entry.get("env") or {}, project) as chain:
            chain.send({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "aegis-doctor", "version": "0.7.0"},
                },
            })
            handshake = chain.await_id(1, timeout)
            if handshake is None:
                report.add(
                    "PROOF: a real tool call is denied and recorded", FAIL,
                    *lines,
                    f"the chain never answered `initialize` within {timeout:.0f}s.",
                    "stderr: " + (" | ".join(chain.stderr[-4:]) or "(nothing)"),
                    "The proxy or the server behind it is not starting. Nothing "
                    "was proved either way.",
                )
                return

            chain.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            chain.send({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": {"path": path}},
            })
            answer = chain.await_id(2, timeout)
            stderr_tail = list(chain.stderr[-6:])
    except OSError as exc:
        report.add(
            "PROOF: a real tool call is denied and recorded", FAIL,
            *lines, f"could not run it: {exc}",
        )
        return

    if answer is None:
        report.add(
            "PROOF: a real tool call is denied and recorded", FAIL,
            *lines, f"no answer to the tool call within {timeout:.0f}s",
            "stderr: " + (" | ".join(stderr_tail) or "(nothing)"),
        )
        return

    text = json.dumps(answer.get("result") or answer.get("error") or {})
    denied_by_aegis = "AEGIS DENIED" in text
    after_id, _ = _read_head(db)
    new_row = _read_row(db, after_id) if after_id > before_id else None

    lines.append(
        f"it answered: {'AEGIS DENIED' if denied_by_aegis else text[:160]}"
    )
    if new_row:
        lines.append(
            f"audit row {new_row['id']} appeared (was {before_id}): "
            f"tool={new_row['tool']} effect={new_row['effect']} "
            f"rule={new_row['rule_id']}"
        )
    else:
        lines.append(f"audit log head is still {before_id} — no row was written")

    problems = []
    if not denied_by_aegis:
        problems.append("the call was not denied by Aegis")
    if new_row is None:
        problems.append("no audit row was written")
    else:
        if new_row["effect"] != "deny":
            problems.append(f"the row records effect '{new_row['effect']}', not 'deny'")
        if new_row["tool"] != tool:
            problems.append(
                f"the row names tool '{new_row['tool']}', not the '{tool}' that was called"
            )
        if new_row["rule_id"] != predicted_rule:
            problems.append(
                f"the row cites rule '{new_row['rule_id']}'; the local policy "
                f"engine predicted '{predicted_rule}'"
            )

    after = _run_verifier(db)
    if after.returncode != 0:
        problems.append("the chain no longer verifies with that row in it")
    else:
        lines.append("the chain still verifies with that row in it")

    if problems:
        report.add(
            "PROOF: a real tool call is denied and recorded", FAIL,
            *lines, "PROBLEM: " + "; ".join(problems),
            "stderr: " + (" | ".join(stderr_tail) or "(nothing)"),
        )
    else:
        report.add(
            "PROOF: a real tool call is denied and recorded", PASS,
            *lines,
            "The proxy is in the pipe. This is the only check here that shows "
            "that; every other one reads a file.",
        )


NOT_COVERED = """
WHAT THIS DOES NOT COVER
========================
Everything above concerns tool calls that cross an MCP stdio pipe Aegis was put
in front of. That is a narrow boundary, and these are outside it:

  Bash, and every shell command.  An agent that runs `cat ~/.ssh/id_rsa` never
  touches this proxy. In the S1 live test three of the model's four attempts on
  a secret went through Bash; Aegis blocked none of them — the client's own
  permission rules did. Those rules are your agent's configuration, not an
  Aegis control, and a different client may not have them.

  Native file tools built into the agent (Read, Write, Edit in Claude Code).
  Same pipe, same absence: they are not MCP calls.

  MCP servers not routed through the proxy.  Listed above if any were found.

  Anything the downstream server does on its own — the requests it makes, the
  files it touches that were not named in the call's arguments.

  Malware already on this machine, and anyone with root.  Both can edit the
  policy, the audit database, and the head anchor.

  Deleting the whole audit database.  An empty chain is a valid chain.

THREAT-MODEL.md §7 is the full list and it is longer than this. Read it before
describing Aegis to anyone else.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis doctor",
        description="Prove the Aegis proxy is actually in the pipe, or say why not.",
    )
    parser.add_argument("--project", default=None, help="project directory (default: cwd)")
    parser.add_argument(
        "--timeout", type=float, default=45.0,
        help="seconds to wait for the MCP chain to answer (default 45)",
    )
    parser.add_argument(
        "--no-probe", action="store_true",
        help="skip the live tool call. Nothing then proves the proxy is in the pipe.",
    )
    args = parser.parse_args(argv)
    project = Path(args.project).expanduser().resolve() if args.project else Path.cwd()

    print("Aegis doctor")
    print("=" * 72)
    print(f"project: {project}\n")

    report = Report()
    policy = _check_policy(report)
    db = _check_audit(report)
    _check_keyring(report, policy)
    wired = _check_wiring(report, project)

    if args.no_probe:
        report.add(
            "PROOF: a real tool call is denied and recorded", SKIP,
            "--no-probe was passed. Every remaining check reads a file; none of "
            "them shows that a tool call reaches the policy engine.",
        )
    elif policy is None:
        report.add(
            "PROOF: a real tool call is denied and recorded", FAIL,
            "not attempted — there is no loadable policy to predict a denial from.",
        )
    else:
        _check_live(report, policy, db, wired, project, args.timeout)

    report.render()

    failures = [c for c in report.checks if c.status == FAIL]
    print("\n" + "=" * 72)
    if failures:
        print(f"{len(failures)} check(s) FAILED:")
        for check in failures:
            print(f"  - {check.name}")
    else:
        print("All checks passed.")
    print(NOT_COVERED)
    return 1 if failures else 0
