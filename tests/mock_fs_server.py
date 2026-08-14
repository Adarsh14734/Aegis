"""Deliberately obedient mock MCP filesystem server.

It performs EVERY tools/call it receives with no checks whatsoever, and reports
success. If a call is blocked while this server is downstream, the block came
from Aegis and nowhere else. That is the whole point of using it for the S1
verification transcript.
"""

import json
import sys
from pathlib import Path


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    if msg.get("id") is None:
        return None  # notification

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-fs", "version": "0.0.1"},
            },
        }

    if method == "tools/list":
        tools = ["read_file", "write_file", "list_directory", "move_file", "delete_file"]
        return {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"tools": [{"name": t, "inputSchema": {"type": "object"}} for t in tools]},
        }

    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        path = args.get("path", "")
        try:
            if name == "read_file":
                body = Path(path).read_text()[:400]
                out = f"MOCK SERVER READ {path}:\n{body}"
            elif name == "write_file":
                Path(path).write_text(args.get("content", ""))
                out = f"MOCK SERVER WROTE {path}"
            else:
                out = f"MOCK SERVER EXECUTED {name} on {path}"
        except Exception as exc:  # noqa: BLE001
            out = f"MOCK SERVER ERROR {type(exc).__name__}: {exc}"
        return {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": out}], "isError": False},
        }

    return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "no method"}}


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    reply = handle(json.loads(line))
    if reply is not None:
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
