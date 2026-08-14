"""Aegis S1 stdio MCP policy proxy.

Sits between an MCP client (Claude Code) and one MCP server child process.

    Claude Code  <--stdio-->  aegis.proxy  <--stdio-->  mcp filesystem server

Only `tools/call` is evaluated. Everything else is forwarded untouched.

CRITICAL: stdout is the JSON-RPC channel. Nothing may ever be printed to stdout
except protocol frames. All logging goes to stderr.

Fail-closed (S0 decision #3): any unexpected failure in parsing, policy loading,
or evaluation results in the call being denied, never forwarded.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from policy import Decision, Effect, Policy, PolicyError

LOG_PREFIX = "[aegis]"


def log(event: str, **fields) -> None:
    """Structured line to stderr. S2 replaces this with the hash-chained store."""
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
    def __init__(self, policy: Policy, cwd: Path):
        self.policy = policy
        self.cwd = cwd
        self.stats = {"seen": 0, "allowed": 0, "denied": 0}

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

    log(
        "started",
        policy=str(policy_path),
        roots=[str(r) for r in policy.workspace_roots],
        server=server_cmd,
    )

    proc = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # child stderr passes through for debugging
    )

    proxy = Proxy(policy, Path.cwd())
    out_lock = asyncio.Lock()

    await asyncio.gather(
        pump_client_to_server(proxy, proc.stdin, out_lock),
        pump_server_to_client(proc.stdout, out_lock),
        return_exceptions=True,
    )

    await proc.wait()
    log("stopped", **proxy.stats)
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
