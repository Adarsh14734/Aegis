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

try:  # S7: see the note in policy.py. Import plumbing only.
    from . import approval, broker, trash
    from .audit import AuditError, AuditStore, default_db_path
    from .policy import Decision, Effect, Policy, PolicyError
except ImportError:  # pragma: no cover - exercised by running this as a script
    import approval
    import broker
    import trash
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
        self.redactor = broker.Redactor()
        self.inflight: dict = {}  # request id -> tool, for correlating responses
        self.ask_timeout = policy.ask_timeout_seconds
        self.stats = {
            "seen": 0, "allowed": 0, "denied": 0, "audit_failures": 0,
            "substituted": 0, "redactions": 0,
            "approvals_requested": 0, "approvals_granted": 0,
            "trash_snapshots": 0, "trash_failures": 0,
        }

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

    async def resolve_ask(self, decision: Decision, loop) -> Decision:
        """C7. Block on a human, then return the decision actually enforced.

        Only the terminal I/O goes to an executor thread; every audit write
        stays on the event-loop thread. The SQLite connection is owned by the
        thread that opened it (`check_same_thread`), and the alternative —
        relaxing that and serializing writes with a lock — would mean editing
        the S2 audit store to suit a caller. The store is the thing whose
        integrity everything else rests on, so the caller bends instead.

        The prompt row is written *before* asking, so a proxy killed mid-prompt
        still leaves evidence that a human was asked and never answered.
        """
        try:
            self.store.record(
                tool=decision.tool,
                effect="ask",
                rule_id="approval_prompt",
                reason=(
                    f"blocking for human approval ({decision.rule_id}): "
                    f"{decision.reason}; timeout {int(self.ask_timeout)}s, "
                    f"denies on timeout"
                ),
                paths=list(decision.paths),
            )
        except AuditError as exc:
            # Same fail-closed rule as any other decision: if it cannot be
            # recorded, it does not happen.
            log("audit_write_failed", error=str(exc), tool=decision.tool)
            self.stats["audit_failures"] += 1
            return Decision(
                Effect.DENY,
                f"approval prompt could not be recorded ({exc}); failing closed",
                "audit_fail_closed",
                decision.tool,
                decision.paths,
            )

        result = await loop.run_in_executor(
            None, approval.resolve,
            decision.tool, decision.rule_id, decision.reason, list(decision.paths),
            self.ask_timeout,
        )
        self.stats["approvals_requested"] += 1
        self.stats["approvals_granted"] += int(result.approved)
        log("approval", rule=result.rule_id, approved=result.approved,
            resolver=result.resolver)

        return Decision(
            Effect.ALLOW if result.approved else Effect.DENY,
            f"{result.detail} (resolved by: {result.resolver})",
            result.rule_id,
            decision.tool,
            decision.paths,
        )

    def stage_destructive(self, decision: Decision) -> Decision:
        """C9. Copy every target into the trash before the call is forwarded.

        A failure here denies the call. The whole point is that a destructive
        action is only allowed to proceed once it is recoverable, so 'could not
        make it recoverable' has exactly one safe answer.
        """
        if not self.policy.tool_is_destructive(decision.tool) or not decision.paths:
            return decision
        if self.policy.trash_dir is None:  # policy load already refuses this
            return Decision(
                Effect.DENY,
                "tool is marked destructive but no trash_dir is configured",
                "trash_unavailable", decision.tool, decision.paths,
            )
        try:
            snap = trash.stage(decision.paths, self.policy.trash_dir, decision.tool)
        except trash.TrashError as exc:
            self.stats["trash_failures"] += 1
            log("trash_failed", error=str(exc), tool=decision.tool)
            return Decision(
                Effect.DENY,
                f"could not preserve the target(s) before a destructive call "
                f"({exc}); denying rather than allowing an unrecoverable action",
                "trash_failed", decision.tool, decision.paths,
            )
        self.stats["trash_snapshots"] += 1
        log("trash_staged", snapshot=snap.snapshot_id, saved=len(snap.saved))
        return Decision(
            decision.effect,
            f"{decision.reason}; {snap.summary()}",
            decision.rule_id, decision.tool, decision.paths,
        )

    def substitute(self, message: dict, decision: Decision):
        """Fill in credential handles for a call that policy has ALLOWED.

        Returns (message_to_forward, decision, handles). The decision comes
        back DENY if a secret could not be resolved: a call carrying an
        unresolvable handle would otherwise reach the server with a literal
        '${aegis:...}' in it, which is a broken credential and a leak of the
        handle name to the server for no benefit.

        Only reached when the policy chain returned ALLOW, so a denied call
        never causes a keychain read. That ordering is the reason this lives
        here and not in policy.py.
        """
        params = message.get("params") or {}
        args = params.get("arguments")
        if not isinstance(args, dict) or not broker.find_handles(args):
            return message, decision, ()

        try:
            filled, resolved = broker.substitute(args, redactor=self.redactor)
        except broker.BrokerError as exc:
            # exc is already scrubbed and unchained by broker.substitute.
            return message, Decision(
                Effect.DENY,
                f"credential substitution failed: {exc}",
                "credential_unavailable",
                decision.tool,
                decision.paths,
            ), ()
        except BaseException as exc:  # noqa: BLE001 - belt and braces
            return message, Decision(
                Effect.DENY,
                f"credential substitution raised {type(exc).__name__}; "
                f"details withheld in case they carry a secret",
                "credential_unavailable",
                decision.tool,
                decision.paths,
            ), ()

        handles = tuple(sorted(resolved))
        self.stats["substituted"] += 1
        # Rebuild the frame around the filled arguments. From here the message
        # holds plaintext credentials: it goes to the server and nowhere else,
        # and must never be logged.
        forwarded = {**message, "params": {**params, "arguments": filled}}
        return forwarded, decision, handles

    def redact_frame(self, line: bytes) -> bytes:
        """Strip any substituted credential out of a server response.

        Byte-preserving when there is nothing to do, which is the overwhelming
        common case: an untouched frame is written back exactly as received.
        """
        if not self.redactor.values:
            return line
        text = line.decode("utf-8", errors="surrogateescape")
        redacted, hits = self.redactor.redact(text)
        if not hits:
            return line

        total = sum(hits.values())
        self.stats["redactions"] += total
        names = ", ".join(sorted(hits))
        log("credential_redacted", handles=sorted(hits), occurrences=total)

        # Correlate to the call that carried the credential. Parsed only on
        # this rare path, never for ordinary responses.
        tool = "<server response>"
        try:
            tool = self.inflight.get(json.loads(text).get("id"), tool)
        except (json.JSONDecodeError, AttributeError, TypeError):
            pass

        try:
            self.store.record(
                tool=tool,
                effect="redact",
                rule_id="credential_redacted",
                reason=(
                    f"server response echoed credential handle(s) {names} "
                    f"({total} occurrence(s)); redacted before the frame reached "
                    f"the model. The value is deliberately not recorded."
                ),
                paths=[],
            )
        except AuditError as exc:
            # Not fail-closed: the response already exists and dropping it
            # would hang the client. Redaction still happened; the gap in the
            # record is reported loudly instead.
            log("audit_write_failed", error=str(exc), tool=tool)
            self.stats["audit_failures"] += 1

        return redacted.encode("utf-8", errors="surrogateescape")

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

            # C7: an ASK blocks here until a human answers, times out, or the
            # absence of a terminal denies it. Run in an executor so the
            # server->client pump keeps flowing while somebody reads the
            # prompt; the client->server pump stays blocked, which serializes
            # approvals deliberately — two prompts competing for one terminal
            # is how the wrong one gets approved.
            if decision.effect is Effect.ASK:
                decision = await proxy.resolve_ask(decision, loop)

            # C9: make the action recoverable before it is forwarded.
            if decision.is_allowed():
                decision = proxy.stage_destructive(decision)

            # C6: substitute only after ALLOW, and before the audit write, so
            # the recorded decision is the one actually enforced rather than an
            # ALLOW that a failed substitution later turned into a denial.
            handles = ()
            if decision.is_allowed():
                message, decision, handles = proxy.substitute(message, decision)
                if handles:
                    decision = Decision(
                        decision.effect,
                        f"{decision.reason}; substituted credential handle(s) "
                        + ", ".join(handles),
                        decision.rule_id,
                        decision.tool,
                        decision.paths,
                    )

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
            proxy.inflight[message.get("id")] = decision.tool

            if handles:
                # Reserialize: `line` still holds the handle, not the secret.
                line = (json.dumps(message) + "\n").encode("utf-8")

        writer.write(line)
        await writer.drain()

    writer.close()


async def pump_server_to_client(proxy: Proxy, reader, out_lock: asyncio.Lock) -> None:
    """Server -> client, with substituted credentials stripped out.

    A server that echoes the credential back — in an error message, a debug
    field, a reflected request — would otherwise hand the model the exact
    value the broker exists to keep away from it, and the whole control would
    be theatre.
    """
    while True:
        line = await reader.readline()
        if not line:
            break
        line = proxy.redact_frame(line)
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
        killswitch=str(policy.killswitch_path),
        bulk_threshold=policy.bulk_threshold,
        trash_dir=str(policy.trash_dir) if policy.trash_dir else None,
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
            pump_server_to_client(proxy, proc.stdout, out_lock),
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
