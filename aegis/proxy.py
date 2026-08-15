"""Aegis S1 stdio MCP policy proxy.

Sits between an MCP client (Claude Code) and one MCP server child process.

    Claude Code  <--stdio-->  aegis.proxy  <--stdio-->  mcp filesystem server

Only `tools/call` is evaluated. Everything else is forwarded untouched.

CRITICAL: stdout is the JSON-RPC channel. Nothing may ever be printed to stdout
except protocol frames. All logging goes to stderr.

Fail-closed (S0 decision #3): any unexpected failure in parsing, policy loading,
evaluation, or *audit recording* results in the call being denied, never
forwarded.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from audit import AuditError, AuditStore, default_db_path
from policy import Decision, Effect, Policy, PolicyError

LOG_PREFIX = "[aegis]"


def log(event: str, **fields) -> None:
    """Structured line to stderr, for live debugging only. The durable record
    is the hash-chained store in audit.py; stderr is volatile and unchained,
    so nothing may be claimed on its strength alone."""
    record = {"ts": round(time.time(), 3), "event": event, **fields}
    print(f"{LOG_PREFIX} {json.dumps(record)}", file=sys.stderr, flush=True)


def default_policy_path() -> Path:
    """S0 decision #2: protected application-data directory, outside the workspace."""
    if override := os.environ.get("AEGIS_POLICY"):
        return Path(override).expanduser()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Aegis"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "aegis"
    return base / "policy.json"


def denial_frame(request_id, decision: Decision) -> dict:
    """MCP tool errors are returned as a *result* with isError, not a JSON-RPC
    error, so the model can read the refusal and adjust rather than crashing."""
    text = (
        f"AEGIS DENIED: {decision.tool}\n"
        f"Reason: {decision.reason}\n"
        f"Rule: {decision.rule_id}\n"
    )
    if decision.paths:
        text += "Paths: " + ", ".join(decision.paths) + "\n"
    text += "This action was blocked by policy and was not forwarded to the server."
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


class Proxy:
    def __init__(self, policy: Policy, cwd: Path, store: AuditStore):
        self.policy = policy
        self.cwd = cwd
        self.store = store
        self.stats = {"seen": 0, "allowed": 0, "denied": 0, "audit_failures": 0}

    def decide(self, message: dict) -> Decision:
        """Never raises. Any failure is a DENY (S0 decision #3)."""
        try:
            params = message.get("params") or {}
            tool = params.get("name")
            if not isinstance(tool, str):
                return Decision(Effect.DENY, "tools/call has no string tool name", "malformed", "?")
            args = params.get("arguments")
            if args is not None and not isinstance(args, dict):
                return Decision(Effect.DENY, "tool arguments are not an object", "malformed", tool)
            return self.policy.evaluate(tool, args or {}, self.cwd)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all, fail closed
            return Decision(
                Effect.DENY,
                f"policy evaluation failed ({type(exc).__name__}); failing closed",
                "fail_closed",
                str((message.get("params") or {}).get("name", "?")),
            )

    def audit(self, decision: Decision) -> Decision:
        """Record the decision, then return the decision that is actually
        enforced. Called before the call is forwarded and before any denial
        frame is written, so no tool call can execute without a row committed.

        C3 fail-closed: if the row cannot be written, the decision is replaced
        with a DENY. An action nobody can reconstruct afterwards is worse than
        an action that did not happen.
        """
        try:
            row_id, row_hash = self.store.record(
                tool=decision.tool,
                effect=decision.effect.value,
                rule_id=decision.rule_id,
                reason=decision.reason,
                paths=list(decision.paths),
            )
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all, fail closed
            # AuditError is the expected failure, but anything escaping here
            # would otherwise kill this pump silently and stop enforcement.
            self.stats["audit_failures"] += 1
            log("audit_write_failed", error=f"{type(exc).__name__}: {exc}", tool=decision.tool)
            return Decision(
                Effect.DENY,
                f"decision could not be recorded to the audit log ({exc}); failing closed",
                "audit_fail_closed",
                decision.tool,
                decision.paths,
            )
        log("audit_row", id=row_id, hash=row_hash[:16])
        return decision


async def pump_client_to_server(proxy: Proxy, writer, out_lock: asyncio.Lock) -> None:
    """Client -> policy -> server. Denied calls are answered here and stop."""
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
        if not line:
            break

        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            log("malformed_frame_dropped", bytes=len(line))
            continue  # fail closed: do not forward anything we cannot parse

        if isinstance(message, dict) and message.get("method") == "tools/call":
            proxy.stats["seen"] += 1
            decision = proxy.decide(message)
            log(
                "tool_call",
                tool=decision.tool,
                effect=decision.effect.value,
                rule=decision.rule_id,
                reason=decision.reason,
                paths=list(decision.paths),
            )
            decision = proxy.audit(decision)
            if not decision.is_allowed():
                proxy.stats["denied"] += 1
                async with out_lock:
                    sys.stdout.write(json.dumps(denial_frame(message.get("id"), decision)) + "\n")
                    sys.stdout.flush()
                continue
            proxy.stats["allowed"] += 1

        writer.write(line)
        await writer.drain()

    writer.close()


async def pump_server_to_client(reader, out_lock: asyncio.Lock) -> None:
    """Server -> client, untouched."""
    while True:
        line = await reader.readline()
        if not line:
            break
        async with out_lock:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()


async def run(server_cmd: list[str]) -> int:
    policy_path = default_policy_path()
    try:
        policy = Policy.load(policy_path)
    except PolicyError as exc:
        # Fail closed at startup: no policy means no proxy, not an open proxy.
        log("startup_refused", error=str(exc), policy=str(policy_path))
        print(f"{LOG_PREFIX} refusing to start: {exc}", file=sys.stderr, flush=True)
        return 2

    db_path = default_db_path()
    try:
        store = AuditStore.open(db_path)
    except AuditError as exc:
        # Same posture as a missing policy: a proxy that cannot record its
        # decisions is not a degraded proxy, it is an absent control (A6).
        log("startup_refused", error=str(exc), audit=str(db_path))
        print(f"{LOG_PREFIX} refusing to start: {exc}", file=sys.stderr, flush=True)
        return 2

    head_id, head_hash = store.head()
    log(
        "started",
        policy=str(policy_path),
        roots=[str(r) for r in policy.workspace_roots],
        server=server_cmd,
        audit=str(db_path),
        audit_head_id=head_id,
        audit_head_hash=head_hash[:16],
    )

    proc = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # child stderr passes through for debugging
    )

    proxy = Proxy(policy, Path.cwd(), store)
    out_lock = asyncio.Lock()

    try:
        await asyncio.gather(
            pump_client_to_server(proxy, proc.stdin, out_lock),
            pump_server_to_client(proc.stdout, out_lock),
            return_exceptions=True,
        )
        await proc.wait()
    finally:
        head_id, head_hash = store.head()
        # S3b: anchor the head next to the db so verify.py has a reference
        # point without the operator having written one down. Best effort —
        # the rows are already committed, so a failure here is not worth
        # denying anything over, but it must be visible.
        anchored = store.write_head_anchor()
        if anchored is None:
            log("head_anchor_write_failed", path=str(store.head_file_path()))
        store.close()

    log(
        "stopped",
        **proxy.stats,
        audit_head_id=head_id,
        audit_head_hash=head_hash,
        head_anchor=str(store.head_file_path()) if anchored else None,
    )
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if "--" in argv:
        argv = argv[argv.index("--") + 1:]
    if not argv:
        print(
            f"{LOG_PREFIX} usage: python aegis/proxy.py -- <mcp-server-command> [args...]",
            file=sys.stderr,
        )
        return 64
    try:
        return asyncio.run(run(argv))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
