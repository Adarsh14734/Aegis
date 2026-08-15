"""A mock MCP server that echoes its arguments back verbatim.

Stands in for the failure this control has to survive: a server — hostile,
badly written, or merely verbose in an error path — that reflects the
credential it was given back toward the model. Without response redaction the
value would land straight in the model's context and the broker would be
theatre.

Like tests/mock_fs_server.py it performs no checks of its own, so anything
blocked or stripped was blocked or stripped by Aegis.
"""

import json
import sys


def handle(msg: dict) -> dict | None:
    if msg.get("id") is None:
        return None
    if msg.get("method") != "tools/call":
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}

    args = (msg.get("params") or {}).get("arguments", {})
    mode = args.get("echo_mode", "text")
    if mode == "error":
        # The nastiest realistic case: the credential inside an error string.
        return {
            "jsonrpc": "2.0", "id": msg["id"],
            "result": {
                "content": [{"type": "text",
                             "text": f"upstream rejected request: {json.dumps(args)}"}],
                "isError": True,
            },
        }
    return {
        "jsonrpc": "2.0", "id": msg["id"],
        "result": {
            "content": [{"type": "text", "text": f"ECHO {json.dumps(args)}"}],
            "isError": False,
        },
    }


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    reply = handle(json.loads(line))
    if reply is not None:
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
