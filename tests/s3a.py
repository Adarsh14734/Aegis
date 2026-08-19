"""S3a unit-level harness: DLP patterns, URL extraction, SSRF encodings,
allowed_domains validation, and the disclosure rule.

tests/drive.py drives whole calls through the real proxy. This file goes at the
parts that need many cheap cases rather than a few expensive ones — above all
the false-positive corpus, because a DLP scanner that fires on ordinary code is
the failure mode that gets the whole control switched off.

Section 6 is the one that matters most: it runs the real proxy on an argument
containing a real-shaped secret and then greps the raw audit database, the
write-ahead log, the proxy's stderr and the denial frame for those bytes. The
rule is that the value never appears in any of them.

SAFETY: every credential here is fake or an AWS/jwt.io published example. The
only files written are in a temp directory.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "aegis"))

import dlp  # noqa: E402
import egress  # noqa: E402
from policy import Policy, PolicyError  # noqa: E402

passed = failed = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  pass  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}{('  <- ' + detail) if detail else ''}")


def rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def scan_text(text: str):
    return dlp.scan([("arguments.content", text)])


# ---- 1. DLP must not fire on ordinary content ------------------------------

rule("1. DLP FALSE POSITIVES — none of this ordinary content may match")

BENIGN = [
    ("git sha in a comment",
     "# pinned at commit 9f2b1c4e8a7d6f3b2c1a0e9d8c7b6a5f4e3d2c1b"),
    ("40-char base64 with no context word",
     "digest = 'K7MDENGbPxRfiCYEXAMPLEKEYwJalrXUtnFEMI0y'"),
    ("the words secret and key, no value",
     "Set your AWS_SECRET_ACCESS_KEY in the environment before deploying."),
    ("ordinary key iteration",
     "for key in config.keys():\n    api_key = os.environ.get('API_KEY')"),
    ("keyring lookup",
     "secret = keyring.get_password('svc', key)  # the private key stays there"),
    ("npm lockfile integrity hash",
     '"integrity": "sha512-r0dm2VXQvbYWqjcbGrIVzR9tjLQKlM0ZpmYhO5Bmr0dsRHl1lI="'),
    ("uuid",
     "request_id = '3f2504e0-4f89-11d3-9a0c-0305e82c3301'"),
    ("identifiers that merely contain sk-",
     "from disk-usage import task-runner  # risk-score, whisk-er"),
    ("public key header, not private",
     "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----"),
    ("certificate header",
     "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----"),
    ("bearer token that is not a jwt",
     "Authorization: Bearer 8f4c2b1a9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b"),
    ("stripe test keys",
     "STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc"),
    ("a base64 image blob field name",
     '{"data":1,"key":"value","secret":2}'),
    ("prose about tokens",
     "Rotate the GitHub token and the Slack token every 90 days."),
]
for label, text in BENIGN:
    hit = scan_text(text)
    check(hit is None, f"benign: {label}", f"matched {hit.pattern if hit else ''}")


# ---- 2. DLP must fire on real-shaped secrets -------------------------------

rule("2. DLP TRUE POSITIVES — every one of these must be caught")

SECRETS = [
    ("aws_access_key_id", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    ("aws_access_key_id", "ASIAY34FZKBOKMUTVV7A is a session key"),
    ("aws_secret_access_key",
     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("github_token", "token ghp_0123456789abcdefghijklmnopqrstuvwxyz"),
    ("github_fine_grained_token",
     "github_pat_" + "1A" * 12 + "_" + "b" * 40),
    ("anthropic_api_key", "ANTHROPIC_API_KEY=sk-ant-api03-" + "aB3" * 14),
    ("openai_api_key", "OPENAI_API_KEY=sk-" + "T3BlbkFJ" * 6),
    ("slack_token", "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
    ("stripe_secret_key", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
    ("stripe_publishable_key", "pk_live_TYooMQauvdEDq54NiTphI7jx"),
    ("private_key_pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n"),
    ("private_key_pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("jwt",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
     "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
]
for expected, text in SECRETS:
    hit = scan_text(text)
    check(hit is not None and hit.pattern == expected,
          f"secret: {expected}", f"got {hit.pattern if hit else 'no match'}")

check("sk-ant-" not in str(scan_text("sk-ant-api03-" + "aB3" * 14)),
      "the Finding never carries the matched value")


# ---- 3. URL extraction -----------------------------------------------------

rule("3. URL EXTRACTION")

EXTRACT = [
    ("plain https", "https://example.com/x", 1),
    ("url in prose with trailing period", "See https://example.com/x. Thanks", 1),
    ("two urls in one string", "a https://a.com b http://b.com c", 2),
    ("file scheme", "file:///etc/passwd", 1),
    ("gopher scheme", "gopher://evil.xyz:70/1", 1),
    ("data url", "data:text/plain;base64,SGVsbG8=", 1),
    ("no scheme is not a url", "example.com/path and www.example.com", 0),
    ("colon in prose is not a url", "TODO: fix this. NOTE:see below", 0),
    ("compact json is not a data url", '{"data":1,"x":2}', 0),
    ("yaml mapping is not a data url", "data: application/json, more", 0),
    ("windows path is not a url", r"C:\Users\adarsh\notes.txt", 0),
]
for label, text, want in EXTRACT:
    got = egress.extract_urls([("arguments.content", text)])
    check(len(got) == want, f"extract {want}: {label}", f"got {got}")

nested = {"request": {"body": {"callback": "https://evil.xyz/beacon"}},
          "headers": ["x", {"deep": ["y", "https://also.evil.xyz/2"]}]}
found = egress.extract_urls(egress.walk_strings(nested))
check(len(found) == 2, "urls found at depth 3 and depth 4", f"got {found}")
check(any("request.body.callback" in w for w, _ in found), "argument path is reported")


# ---- 4. Host policy and SSRF ----------------------------------------------

rule("4. HOST POLICY / SSRF — allowlist is ['example.com', 'api.example.com']")

ALLOWED = ("example.com", "api.example.com")
HOSTS = [
    ("https://example.com/x", True, "exact match"),
    ("https://EXAMPLE.COM/x", True, "uppercase host"),
    ("https://example.com./x", True, "trailing dot"),
    ("https://cdn.example.com/x", True, "subdomain"),
    ("https://a.b.c.example.com/x", True, "deep subdomain"),
    ("https://notexample.com/x", False, "suffix without dot must not match"),
    ("https://example.com.evil.xyz/x", False, "allowed host as a prefix label"),
    ("https://evil.xyz/x", False, "unlisted"),
    ("https://api.example.com@evil.xyz/x", False, "userinfo trick"),
    ("http://127.0.0.1/x", False, "loopback"),
    ("http://[::1]/x", False, "ipv6 loopback"),
    ("http://[::ffff:127.0.0.1]/x", False, "ipv4-mapped ipv6 loopback"),
    ("http://2130706433/x", False, "loopback as decimal integer"),
    ("http://0x7f000001/x", False, "loopback as hex integer"),
    ("http://127.1/x", False, "abbreviated loopback"),
    ("http://010.010.010.010/x", False, "octal dotted quad"),
    ("http://169.254.169.254/latest/meta-data/", False, "cloud metadata"),
    ("http://192.168.1.1/x", False, "private"),
    ("http://10.0.0.1/x", False, "private"),
    ("http://172.16.0.1/x", False, "private"),
    ("http://93.184.216.34/x", False, "public raw IP literal"),
    ("http://localhost:8080/x", False, "localhost"),
    ("http://api.localhost/x", False, ".localhost"),
    ("http://nas.local/x", False, ".local mDNS"),
    ("http://metadata.google.internal/x", False, "unlisted internal name"),
    ("file:///etc/passwd", False, "file scheme"),
    ("gopher://evil.xyz:70/1", False, "gopher scheme"),
    ("data:text/html;base64,PHNjcmlwdD4=", False, "data url"),
    ("ftp://example.com/x", False, "ftp to an allowed host is still not http"),
    ("ws://example.com/x", False, "websocket scheme"),
]
for url, want_allowed, label in HOSTS:
    finding = egress.check_url("arguments.url", url, ALLOWED)
    check((finding is None) == want_allowed,
          f"{'allow' if want_allowed else 'deny '} {url}  ({label})",
          finding.reason if finding else "allowed")

check(egress.check_url("arguments.url", "http://127.0.0.1:8000/x",
                       ("example.com", "127.0.0.1")) is None,
      "an explicitly listed loopback address is permitted")
check(egress.check_url("arguments.url", "https://example.com/x", ()) is not None,
      "empty allowlist denies everything")


# ---- 5. Policy loading -----------------------------------------------------

rule("5. allowed_domains VALIDATION")

BASE = {
    "version": 1,
    "workspace_roots": [str(ROOT)],
    "default_effect": "deny",
    "tool_rules": {},
}


def load(**over):
    return Policy({**BASE, **over}, ROOT.parent / "policy.json")


check(load().allowed_domains == (), "absent key means the empty list, not permissive")
check(load(allowed_domains=[]).allowed_domains == (), "explicit empty list")
check(load(allowed_domains=["Example.COM ", ".foo.io."]).allowed_domains
      == ("example.com", "foo.io"), "entries are normalized")

for bad, why in [
    (["*"], "bare wildcard"),
    (["*.example.com"], "wildcard prefix"),
    ([""], "empty entry"),
    (["https://example.com"], "scheme"),
    (["example.com/path"], "path"),
    (["example.com:443"], "port"),
    ([123], "non-string"),
    ("example.com", "not a list"),
]:
    try:
        load(allowed_domains=bad)
        check(False, f"rejects {why}", "loaded without error")
    except PolicyError as exc:
        check(True, f"rejects {why}: {str(exc)[:60]}")

check(load(allowed_domains=["::1", "2001:db8::1"]).allowed_domains
      == ("::1", "2001:db8::1"), "bare IPv6 literals are not mistaken for ports")


# ---- 6. Disclosure rule ----------------------------------------------------

rule("6. DISCLOSURE — the secret must not reach the audit db, stderr, or the frame")

# --- labguard: pins every Aegis path into a temp lab and verifies it, in this
# --- process AND in a child, before anything runs. Five suites have written to
# --- the operator's real installation because env pinning failed silently; this
# --- aborts instead. See tests/labguard.py.
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s3a-")
WS = LAB / "workspace"
WS.mkdir()
DB = LAB / "audit.db"
POLICY_FILE = LAB / "policy.json"
POLICY_FILE.write_text(json.dumps({
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env"],
    "allowed_domains": ["example.com"],
    "default_effect": "deny",
    "ask_behavior": "deny",
    "tool_rules": {"write_file": {"effect": "allow", "within": ["<workspace>"]}},
}))
POLICY_FILE.chmod(0o600)

SECRET = "AKIAIOSFODNN7EXAMPLE"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

proc = subprocess.run(
    [sys.executable, str(ROOT / "aegis" / "proxy.py"), "--",
     sys.executable, str(ROOT / "tests" / "mock_fs_server.py")],
    input="\n".join(json.dumps({
        "jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": "write_file", "arguments": args},
    }) for i, args in enumerate([
        {"path": str(WS / "a.sh"), "content": f"export AWS_ACCESS_KEY_ID={SECRET}\n"},
        {"path": str(WS / "b.txt"), "content": f"Authorization: Bearer {JWT}"},
    ], start=1)) + "\n",
    capture_output=True, text=True,
    env={**os.environ, "AEGIS_POLICY": str(POLICY_FILE), "AEGIS_AUDIT_DB": str(DB)},
    timeout=30,
)

frames = proc.stdout
check(frames.count('"isError": true') == 2, "both calls denied", frames[:200])
check("aws_access_key_id" in frames and "jwt" in frames, "pattern names are reported")

blobs = {"denial frames (stdout)": frames, "proxy stderr": proc.stderr}
for suffix in ("", "-wal", "-shm"):
    f = Path(str(DB) + suffix)
    if f.exists():
        blobs[f"audit db {f.name}"] = f.read_bytes().decode("latin-1")

for where, blob in blobs.items():
    check(SECRET not in blob, f"AWS key absent from {where}")
    check(JWT not in blob, f"JWT absent from {where}")
    check("dozjgNryP4J3" not in blob, f"JWT signature fragment absent from {where}")

audit_rows = subprocess.run(
    [sys.executable, "-c",
     "import sqlite3,sys;print(list(sqlite3.connect(sys.argv[1])"
     ".execute('SELECT id,effect,rule_id,reason,paths FROM audit')))", str(DB)],
    capture_output=True, text=True).stdout
print("\n  audit rows written:")
for row in audit_rows.strip().strip("[]").split("), ("):
    print(f"    ({row.strip('()')})")
check("'dlp'" in audit_rows, "rule_id 'dlp' recorded")
check(SECRET not in audit_rows, "secret absent from the audit rows")

verify = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"), str(DB)],
                        capture_output=True, text=True)
check(verify.returncode == 0, "S2 chain still verifies over S3a rows", verify.stdout)

shutil.rmtree(LAB, ignore_errors=True)

rule("SUMMARY")
print(f"  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
