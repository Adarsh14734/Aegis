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


def _proxy_ages() -> list[tuple[int, float, str]]:
    """[(pid, seconds running, command)] for every Aegis proxy currently up.

    `ps -o etime=` gives elapsed time as [[dd-]hh:]mm:ss. Parsed rather than
    guessed at, because the whole check turns on comparing it to an edit
    timestamp.
    """
    try:
        done = subprocess.run(
            ["ps", "-ww", "-eo", "pid=,etime=,command="],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if done.returncode != 0:
        return []

    out = []
    for line in done.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid_s, etime, cmd = parts
        if "aegis.proxy" not in cmd and "aegis/proxy.py" not in cmd:
            continue
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        days, _, clock = etime.rpartition("-")
        bits = [float(b) for b in clock.split(":")]
        seconds = 0.0
        for b in bits:
            seconds = seconds * 60 + b
        if days:
            try:
                seconds += float(days) * 86400
            except ValueError:
                pass
        out.append((pid, seconds, cmd))
    return out


def _check_policy_freshness(report: Report) -> None:
    """S10. Did someone edit the policy while a proxy was already running?

    `Policy.load()` runs once at proxy startup and the result is cached for the
    life of the process. So an edit made from the Permissions screen — or by any
    other means — does not reach a session that is already up. The user is told
    that at edit time, but "I was told" and "it is currently happening" are
    different facts, and only this one can be checked.

    The comparison is a proxy's elapsed run time against the age of the newest
    `policy_edited` row. A proxy older than the edit is enforcing rules that no
    longer match the file.
    """
    from . import policyedit

    edit = policyedit.last_edit()
    if edit is None:
        report.add(
            "Policy edits have reached the running proxy", SKIP,
            "no policy edit has ever been recorded, so there is nothing that "
            "could be stale.",
        )
        return

    running = _proxy_ages()
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(edit["ts"]))
    stale = [(pid, age, cmd) for pid, age, cmd in running if age > edit["age_seconds"]]

    if not running:
        report.add(
            "Policy edits have reached the running proxy", PASS,
            f"last edit {when}: {edit['reason'][:100]}",
            "no proxy is running, so the next one to start reads the current "
            "policy.",
        )
        return

    if stale:
        report.add(
            "Policy edits have reached the running proxy", FAIL,
            f"last edit {when} ({int(edit['age_seconds'])}s ago): "
            f"{edit['reason'][:100]}",
            *[f"pid {pid} has been running {int(age)}s — longer than that — so it "
              f"is still enforcing the policy it read at startup"
              for pid, age, _ in stale],
            "Restart your agent. Aegis loads the policy once per session on "
            "purpose (a policy that could change mid-session is a policy an "
            "agent could race), and the cost is that an edit needs a restart.",
        )
        return

    report.add(
        "Policy edits have reached the running proxy", PASS,
        f"last edit {when}: {edit['reason'][:100]}",
        f"{len(running)} proxy process(es) running, all started since that edit.",
    )


def _check_launch(report: Report) -> bool:
    """S9c. Is the client's own launch actually routed through the sandbox?

    Returns True when at least one detected client resolves to an Aegis wrapper.
    Resolution, not file existence: a wrapper the user's PATH never reaches is a
    file, and reporting it as coverage would be the same mistake S7's doctor was
    built to avoid.
    """
    from . import launcher

    clients_found = launcher.detect_clients()
    if not clients_found:
        report.add(
            "Client launches through the sandbox (C11 by default)", SKIP,
            "no known agent client found on PATH, so there is nothing to route.",
        )
        return False

    statuses = [launcher.effective_status(n, l) for n, l, _ in clients_found]
    wrapped = [s_ for s_ in statuses if s_.effective]
    shim = launcher.shim_installed()

    lines = [f"{s_.label}: {s_.reason}" for s_ in statuses]
    if shim:
        lines.append(f"shell shim present in {shim} (advice only — it applies to "
                     f"shells that sourced it, and not to a full binary path)")

    if wrapped:
        report.add(
            "Client launches through the sandbox (C11 by default)", PASS,
            *lines,
            "Started this way, the client and everything it spawns — Bash, "
            "native file edits, MCP servers, npm install — run inside the "
            "sandbox.",
            "Still bypassed by running the real binary path directly, and a "
            "client already running when this changed is unaffected.",
        )
        return True

    fix = [
        "Run `aegis init` and accept the launch-wrapper offer, or "
        "`aegis shell-init` for a shell-only version.",
    ]
    if any(s_.wrapper_exists for s_ in statuses) and not launcher.wrapper_dir_on_path():
        fix = [
            f"A wrapper exists but {launcher.wrapper_dir()} is not on PATH, so "
            f"it is never reached. Add:",
            f"    {launcher.path_hint()}",
        ]
    report.add(
        "Client launches through the sandbox (C11 by default)", WARN,
        *lines,
        "Your client starts UNSANDBOXED. Aegis still mediates its MCP tool "
        "calls, but its Bash tool, its native file edits and everything it "
        "spawns have no kernel boundary.",
        *fix,
    )
    return False


def _check_sandbox(report: Report, policy, launch_wrapped: bool = False) -> None:
    """S9b. Report the kernel boundary's status, including that it is opt-in.

    The single most misleading thing `doctor` could do is pass on a machine
    where the agent runs unconfined. Every other check here concerns the MCP
    pipe; C11 concerns everything else the agent can do, and **it applies only
    to agents launched with `aegis run`**. A user who starts their agent the
    normal way gets no sandbox at all, and nothing else in this report would
    say so.

    So this is reported as a WARN rather than a FAIL when the runtime is
    present: not having opted into the sandbox is a configuration choice, not a
    broken installation. It is a FAIL only when a profile on disk disagrees with
    the policy, because that is a real inconsistency — the kernel would enforce
    yesterday's rules if `aegis run` were used without regenerating.
    """
    from . import sandbox as sandbox_mod

    runtime = sandbox_mod.find_runtime()
    problems = sandbox_mod.preflight()
    if launch_wrapped:
        # S9c: saying "only applies to aegis run" once the launch IS wrapped
        # would be false, and a warning that is false where it matters is how
        # people learn to skip the warnings.
        always = (
            "Your client's launch is routed through `aegis run`, so this "
            "applies to it by default. It does not apply to a client started "
            "by its full binary path, or one already running."
        )
    else:
        always = (
            "The sandbox applies ONLY to agents started with `aegis run`. An "
            "agent you launch any other way has no kernel boundary — its Bash, "
            "its subprocesses and its native file tools are unconstrained, "
            "exactly as they were before S9."
        )

    if problems:
        report.add(
            "OS sandbox (C11)", WARN,
            *[p.splitlines()[0] for p in problems],
            f"Install it with: {sandbox_mod.RUNTIME_INSTALL_HINT}",
            "Without it `aegis run` refuses to launch — it never runs an agent "
            "unconfined — so this is a missing capability, not a silent hole.",
            always,
        )
        return

    if policy is None:
        report.add(
            "OS sandbox (C11)", WARN,
            f"runtime present: {runtime}",
            "no loadable policy, so no profile can be generated or compared.",
            always,
        )
        return

    matches, wanted = sandbox_mod.matches_policy(policy)
    path = sandbox_mod.profile_path()
    if not path.exists():
        report.add(
            "OS sandbox (C11)", WARN,
            f"runtime present: {runtime}",
            f"no profile written yet at {path} — `aegis run` generates one on "
            f"each launch, so this only means the sandbox has not been used.",
            f"the profile this policy would generate has digest {wanted[:16]}",
            always,
        )
    elif matches:
        report.add(
            "OS sandbox (C11)", PASS,
            f"runtime present: {runtime}",
            f"profile {path} matches the current policy (digest {wanted[:16]})",
            always,
        )
    else:
        report.add(
            "OS sandbox (C11)", FAIL,
            f"runtime present: {runtime}",
            f"the profile at {path} does NOT match the current policy.",
            f"policy would generate digest {wanted[:16]}.",
            "The policy has been edited since that profile was written. "
            "`aegis run` regenerates it on every launch, so a live session is "
            "not affected — but anything reading this file, or a stale copy "
            "used by hand, describes rules the policy no longer states.",
            always,
        )


def _check_wiring(
    report: Report, project: Path
) -> tuple[list[tuple[clients.Detected, str]], list[clients.Detected]]:
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
        return wired, found

    if not wired:
        report.add(
            "MCP configuration points at the proxy", FAIL,
            *lines,
            "Servers configured, none of them through Aegis: " + ", ".join(loose),
            "Every tool call these servers receive is unmediated and unrecorded.",
            "Run `aegis init` to route them through the proxy.",
        )
        return wired, found

    check = report.add("MCP configuration points at the proxy", PASS, *lines)
    if loose:
        report.add(
            "Servers NOT going through Aegis", WARN,
            *loose,
            "These are outside the boundary entirely. Their tool calls are not "
            "checked and not recorded.",
        )
    return wired, found


# ---------------------------------------------------------------------------
# is a client still running the old wiring?
# ---------------------------------------------------------------------------

# Interpreters and launchers say nothing about *which* server a process is, so
# they are dropped when fingerprinting a configured command. What is left — a
# script path, a package name, a workspace directory — is what a running
# process can be recognised by.
LAUNCHERS = {
    "npx", "npm", "node", "nodejs", "bun", "deno", "uvx", "uv", "pipx",
    "python", "python3", "python3.10", "python3.11", "python3.12", "python3.13",
    "python3.14", "sh", "bash", "zsh", "env", "docker", "podman", "exec",
}

# Ancestor names worth reporting back as "restart this". Matched on the process
# basename, case-insensitively, as a substring.
CLIENT_HINTS = (
    "claude", "cursor", "windsurf", "code helper", "electron", "vscode", "zed",
)


def _process_table() -> list[tuple[int, int, str]] | None:
    """(pid, ppid, command line) for every visible process, or None.

    None means "could not look", which is reported differently from "looked and
    found nothing". `-ww` because the default width truncates a command line,
    and a truncated command line is one that quietly stops matching.
    """
    try:
        done = subprocess.run(
            ["ps", "-ww", "-eo", "pid=,ppid=,command="],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None

    rows: list[tuple[int, int, str]] = []
    for line in done.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
        except ValueError:
            continue
    return rows or None


def _is_proxy_cmdline(cmd: str) -> bool:
    return "aegis.proxy" in cmd or "aegis/proxy.py" in cmd


def _fingerprint(argv: list[str]) -> list[str]:
    """Tokens that identify a server process, from its configured command.

    Absolute paths are kept whole; everything else is reduced to its last path
    segment, so `@modelcontextprotocol/server-filesystem` in the config still
    matches the `.../server-filesystem/dist/index.js` that npx actually execs.
    """
    tokens: list[str] = []
    for raw in argv:
        if raw.startswith("-"):
            continue
        base = raw.rsplit("/", 1)[-1]
        if not base or base.lower() in LAUNCHERS:
            continue
        tokens.append(raw if raw.startswith("/") else base)
    return tokens


def _matches(cmd: str, tokens: list[str]) -> bool:
    if not tokens:
        return False
    hits = sum(1 for t in tokens if t in cmd)
    # Two tokens where two exist. One token is too loose — a workspace path on
    # its own matches the editor that has the folder open.
    return hits >= min(2, len(tokens))


def _ancestry(pid: int, parent: dict[int, int], cmd: dict[int, str]) -> list[int]:
    chain: list[int] = []
    seen = {pid}
    cur = parent.get(pid, 0)
    while cur and cur > 1 and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = parent.get(cur, 0)
    return chain


def _client_hint(chain: list[int], cmd: dict[int, str]) -> str:
    """A name for the application to restart, or "".

    Deliberately weak, and the caller words it as a guess. A shell basename is
    replaced by the hint that matched it: a server launched from a terminal
    inside an editor has a shell in its ancestry whose command line mentions
    that editor, and reporting "zsh" there would send the user to restart the
    wrong thing.
    """
    shells = {"sh", "bash", "zsh", "fish", "dash", "csh", "tcsh", "login", "-zsh", "-bash"}
    for pid in chain:
        line = cmd.get(pid, "")
        head = line.split(None, 1)[0].rsplit("/", 1)[-1] if line else ""
        for hint in CLIENT_HINTS:
            if hint in line.lower():
                return hint if head.lower() in shells or not head else head
    return ""


def _check_stale_clients(report: Report, found: list[clients.Detected]) -> None:
    """Gap 9 from S7: a correct config proves nothing about a running client.

    An MCP client launches its servers once, at startup. `aegis init` edits the
    file it launched them from; it cannot reach into a process that has already
    started. So a client still running from before the edit keeps talking to an
    unwrapped server, and every other check here — which reads files — reports
    green while nothing is mediated.

    This looks for the actual processes: for each configured server, does a
    process matching its downstream command exist with no Aegis proxy anywhere
    in its ancestry? A match is a FAIL naming the client to restart.

    It is a heuristic and is described as one. `ps` may be restricted, a server
    may be launched in a way its configuration does not predict, and a client
    may hold a server whose command line resembles nothing in the config. So a
    clean result is never reported as proof, and the restart instruction is
    printed whatever this finds.
    """
    servers: list[tuple[str, Path, list[str]]] = []
    for det in found:
        for name, entry in det.servers.items():
            downstream = clients.unwrap_entry(entry) if clients.is_wrapped(entry) else entry
            if not isinstance(downstream, dict) or not downstream.get("command"):
                continue
            tokens = _fingerprint(_entry_argv(downstream))
            if tokens:
                servers.append((name, det.path, tokens))

    if not servers:
        report.add(
            "No client is still running the old wiring", SKIP,
            "no configured server command to look for in the process table.",
        )
        return

    table = _process_table()
    if table is None:
        report.add(
            "No client is still running the old wiring", WARN,
            "could not read the process table, so this was not checked.",
            "RESTART YOUR MCP CLIENT after running `aegis init`. A client that "
            "was already running kept the server it launched before the change.",
        )
        return

    parent = {pid: ppid for pid, ppid, _ in table}
    cmdline = {pid: cmd for pid, _, cmd in table}
    mine = {os.getpid(), *_ancestry(os.getpid(), parent, cmdline)}

    stale: list[str] = []
    for pid, _, cmd in table:
        if pid in mine or _is_proxy_cmdline(cmd):
            continue
        chain = _ancestry(pid, parent, cmdline)
        if any(_is_proxy_cmdline(cmdline.get(a, "")) for a in chain):
            continue  # this one is behind a proxy: mediated, fine
        for name, path, tokens in servers:
            if _matches(cmd, tokens):
                client = _client_hint(chain, cmdline)
                stale.append(
                    f"pid {pid} looks like the '{name}' server from {path}, "
                    f"running with no Aegis proxy above it"
                    + (f" (launched by {client})" if client else "")
                )
                stale.append(f"    {cmd[:160]}")
                break

    if stale:
        report.add(
            "No client is still running the old wiring", FAIL,
            *stale,
            "",
            "QUIT AND REOPEN THAT APPLICATION. An MCP client starts its servers "
            "once, when it launches. Editing the configuration afterwards does "
            "not move a server that is already running, so this one is still "
            "being talked to directly and none of its tool calls are checked or "
            "recorded — however green everything above looks.",
        )
        return

    report.add(
        "No client is still running the old wiring", PASS,
        f"looked at {len(table)} processes for the {len(servers)} configured "
        f"server command(s); none is running outside an Aegis proxy.",
        "This is a heuristic, not a guarantee: a client can hold a server whose "
        "command line resembles nothing in the configuration. If you have not "
        "restarted your MCP client since running `aegis init`, do that now.",
    )


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

  Bash, every shell command, and the agent's native file tools (Read, Write,
  Edit in Claude Code) — UNLESS the agent was started with `aegis run`, which
  puts the whole process tree inside an OS sandbox and is the only thing that
  covers them. Without it: in the S1 live test three of the model's four
  attempts on a secret went through Bash; Aegis blocked none of them — the
  client's own permission rules did. Those rules are your agent's
  configuration, not an Aegis control, and a different client may not have
  them. The sandbox check above says whether that boundary is even available
  here.

  Where the agent goes on the network from inside the sandbox.  Kernel denials
  of denied FILE paths are audited; a blocked domain is refused by the sandbox
  runtime's proxy and never reaches the kernel log, so it is counted and not
  individually recorded. Egress Aegis performs itself is fully recorded.

  A kernel escape.  The sandbox is exactly as strong as Seatbelt or bubblewrap
  underneath it, and a bypass returns the agent to full authority.

  MCP servers not routed through the proxy.  Listed above if any were found.

  Anything the downstream server does on its own — the requests it makes, the
  files it touches that were not named in the call's arguments.

  Malware already on this machine, and anyone with root.  Both can edit the
  policy, the audit database, and the head anchor.

  Deleting the whole audit database.  An empty chain is a valid chain.

THREAT-MODEL.md §7 is the full list and it is longer than this. Read it before
describing Aegis to anyone else.
"""


def _restart_notice(report: Report) -> str:
    """Printed on every run, pass or fail.

    Everything doctor checks about wiring is a fact about files. A running MCP
    client is not a file: it launched its servers once and is still talking to
    them. The process scan above catches the common case and cannot promise to
    catch every one, so the instruction is given unconditionally rather than
    only when something was detected.
    """
    detected = any(
        c.name.startswith("No client is still running") and c.status == FAIL
        for c in report.checks
    )
    if detected:
        return """
+----------------------------------------------------------------------+
|  RESTART REQUIRED — a client is still running the old wiring          |
+----------------------------------------------------------------------+
Quit and reopen the application named above. Until you do, its tool calls
are going straight to the server, unchecked and unrecorded, no matter what
the configuration on disk now says.
"""
    return """
+----------------------------------------------------------------------+
|  RESTART YOUR MCP CLIENT AFTER `aegis init`                           |
+----------------------------------------------------------------------+
A client starts its MCP servers once, when it launches. Changing the
configuration afterwards does not move a server that is already running.
Doctor checked the process table and saw nothing running outside a proxy,
but it cannot see inside an already-running client, and this check is a
heuristic. If you have not restarted the client since setup, do it now —
a green report and an unmediated agent look identical from here.
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
    wired, found = _check_wiring(report, project)
    _check_policy_freshness(report)
    launch_wrapped = _check_launch(report)
    _check_sandbox(report, policy, launch_wrapped)

    # Before the probe, not after: the probe launches its own copy of the
    # configured command, and a check that scans the process table has no
    # business running while doctor's own children are in it.
    _check_stale_clients(report, found)

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

    print(_restart_notice(report))
    print(NOT_COVERED)
    return 1 if failures else 0
