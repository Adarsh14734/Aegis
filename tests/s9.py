"""Aegis S9 harness — C11, the sandbox.

The claim under test is narrow and physical: inside the sandbox, a shell command
that policy forbids fails with a KERNEL error, not a policy message. Every check
that matters here is a real process, run through the real runtime, against files
that really exist.

Two design rules the suite follows, both learned the hard way:

  - **A denial must be distinguished from an absence.** S8's TLS probe was
    "accepted" because the certificate legitimately covered the name it used; the
    probe was wrong, not the control. So every deny_paths file here is created
    first and read UNSANDBOXED as a control, so "Operation not permitted" cannot
    be confused with "No such file".
  - **A missing runtime is NOT RUN, not a pass.** S4-REPORT.md finding 0: a suite
    that can print SKIP and exit 0 will eventually launder an unverified claim
    into a report. Without `srt` the enforcement sections cannot run, and the
    suite says so and exits non-zero.

    python3 tests/s9.py       exit 0 only if every check ran and passed
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASSED = 0
FAILED = 0
FAILURES: list[str] = []
NOT_RUN: list[tuple[str, str]] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  pass  {label}")
    else:
        FAILED += 1
        FAILURES.append(label)
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))
    return ok


def not_run(what: str, why: str) -> None:
    NOT_RUN.append((what, why))
    print(f"  NOT RUN  {what}\n           {why}")


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


# ---------------------------------------------------------------------------
# lab, pinned before anything resolves a default path (S5 finding 1)
# ---------------------------------------------------------------------------

# --- labguard: pins every Aegis path into a temp lab and verifies it, in this
# --- process AND in a child, before anything runs. Five suites have written to
# --- the operator's real installation because env pinning failed silently; this
# --- aborts instead. See tests/labguard.py.
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s9-")
WS = LAB / "workspace"
SECRETS = LAB / "fake-home"
# Deliberately outside the lab: the suite writes NOTHING here, it only proves
# the sandbox refuses to. labguard covers Aegis's own paths, not this one.
OUTSIDE = Path(tempfile.mkdtemp(prefix="aegis-s9-outside-"))
WS.mkdir(parents=True)
(SECRETS / ".ssh").mkdir(parents=True)
(SECRETS / ".aws").mkdir(parents=True)

REAL_DIR = (
    Path.home() / "Library" / "Application Support" / "Aegis"
    if sys.platform == "darwin"
    else Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "aegis"
)
REAL_WATCH = [REAL_DIR / "audit.db", REAL_DIR / "policy.json",
              REAL_DIR / "KILLSWITCH", REAL_DIR / "sandbox-profile.json"]
BASELINE = {
    str(p): (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "absent")
    for p in REAL_WATCH
}

from aegis import sandbox as sandbox_mod  # noqa: E402
from aegis.policy import Policy  # noqa: E402

# Files that really exist, in paths policy denies. Read unsandboxed below as a
# control, so a denial cannot be mistaken for an absence.
KEYFILE = SECRETS / ".ssh" / "id_rsa"
AWSFILE = SECRETS / ".aws" / "credentials"
ENVFILE = WS / ".env"
PLAIN = WS / "notes.txt"
KEYFILE.write_text("PRIVATE-KEY-BYTES-S9\n")
AWSFILE.write_text("aws_secret_access_key = S9SECRET\n")
ENVFILE.write_text("TOKEN=s9-env-secret\n")
PLAIN.write_text("an ordinary workspace file\n")

POLICY_DOC = {
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env", "*.pem", "id_rsa", "**/.aws/**", "**/.ssh/**"],
    "allowed_domains": ["example.com"],
    "tool_rules": {
        "read_file": {"effect": "allow", "within": ["<workspace>"]},
        "write_file": {"effect": "allow", "within": ["<workspace>"]},
        "list_directory": {"effect": "allow", "within": ["<workspace>"]},
    },
    "default_effect": "deny",
    "ask_behavior": "deny",
}
POLICY_PATH = LAB / "policy.json"
POLICY_PATH.write_text(json.dumps(POLICY_DOC, indent=2))
os.chmod(POLICY_PATH, 0o600)
POLICY = Policy.load(POLICY_PATH)

ENV = {**os.environ, "AEGIS_POLICY": str(POLICY_PATH), "PYTHONPATH": str(ROOT)}

print(f"lab: {LAB}")
print(f"outside-the-sandbox dir: {OUTSIDE}")


def sh(box, script: str, timeout: int = 120):
    """Run a shell script inside the sandbox and return the completed process."""
    return subprocess.run(
        box.wrap(["bash", "-c", script]),
        capture_output=True, text=True, timeout=timeout, env=ENV,
    )


def unsandboxed(script: str):
    return subprocess.run(["bash", "-c", script], capture_output=True,
                          text=True, timeout=60, env=ENV)


# ---------------------------------------------------------------------------
rule("1. WRAPPING, NOT WRITING — what this machine can offer (D2)")
# ---------------------------------------------------------------------------

problems = sandbox_mod.preflight()
runtime = sandbox_mod.find_runtime()
print(f"  platform: {sys.platform}   runtime: {runtime}")
check("the runtime this wraps is Anthropic's, named in D2",
      sandbox_mod.RUNTIME_PACKAGE == "@anthropic-ai/sandbox-runtime")
check("aegis/sandbox.py contains no isolation logic of its own",
      not any(tok in (ROOT / "aegis" / "sandbox.py").read_text()
              for tok in ("(deny file-read", "(allow file", "seatbelt-profile",
                          "unshare(", "CLONE_NEW")),
      "found what looks like a hand-written profile or a namespace call")

if problems:
    for p in problems:
        print(f"  preflight problem: {p.splitlines()[0]}")

check("preflight returns a list of every problem, not just the first",
      isinstance(problems, list))

# The fail-closed path is exercised whether or not a runtime is installed, by
# pointing the override at something that is not a sandbox.
os.environ["AEGIS_SANDBOX_RUNTIME"] = str(LAB / "no-such-binary")
check("a missing runtime is detected", sandbox_mod.find_runtime() is None)
check("...and preflight refuses because of it",
      any("not on PATH" in p for p in sandbox_mod.preflight()),
      str(sandbox_mod.preflight()))
refusal_text = ""
try:
    sandbox_mod.establish(POLICY)
    established = True
except sandbox_mod.SandboxError as exc:
    established = False
    refusal_text = str(exc)
check("establish() raises rather than returning an unsandboxed handle",
      not established)
check("...and the message says how to install the runtime",
      "npm install -g @anthropic-ai/sandbox-runtime" in refusal_text,
      refusal_text[:200])
os.environ.pop("AEGIS_SANDBOX_RUNTIME")


# ---------------------------------------------------------------------------
rule("2. THE PROFILE IS GENERATED FROM policy.json AND NOTHING ELSE")
# ---------------------------------------------------------------------------

doc = sandbox_mod.profile_from_policy(POLICY)
fs, net = doc["filesystem"], doc["network"]
print("  " + json.dumps(doc, indent=2).replace("\n", "\n  "))

RWS = str(WS.resolve())
ROUT = str(OUTSIDE.resolve())
check("every workspace root is writable", RWS in fs["allowWrite"], str(fs["allowWrite"]))
check("a directory outside the policy is not writable", ROUT not in fs["allowWrite"])
check("every path in the profile is absolute and already symlink-resolved",
      all(pp == str(Path(pp).resolve()) for pp in fs["allowWrite"]),
      str([pp for pp in fs["allowWrite"] if pp != str(Path(pp).resolve())]))
check("every deny_paths pattern is denied for READ",
      all(any(pat in p for p in fs["denyRead"]) for pat in (".env", "id_rsa", ".aws")),
      str(fs["denyRead"]))
check("...and for WRITE too",
      all(any(pat in p for p in fs["denyWrite"]) for pat in (".env", "id_rsa", ".aws")),
      str(fs["denyWrite"]))
check("a bare pattern becomes a basename glob, matching policy.py's two-way match",
      "/**/.env" in fs["denyRead"] and "/**/id_rsa" in fs["denyRead"],
      str(fs["denyRead"]))
check("a directory pattern denies the directory as well as its contents",
      "/**/.aws" in fs["denyRead"] and "/**/.aws/**" in fs["denyRead"],
      str(fs["denyRead"]))
# Regression guard for S9 finding 1. A relative glob is rooted at the process's
# cwd in this runtime, so it enforces nothing outside wherever the agent was
# started. Every deny pattern must be anchored at the filesystem root.
check("EVERY deny pattern is anchored at the filesystem root, not at cwd",
      all(pp.startswith("/") for pp in fs["denyRead"] + fs["denyWrite"]),
      str([pp for pp in fs["denyRead"] + fs["denyWrite"] if not pp.startswith("/")]))
check("policy.json itself is write-denied (A7, at the kernel)",
      str(POLICY_PATH.resolve()) in fs["denyWrite"], str(fs["denyWrite"]))
check("the kill switch cannot be removed from inside (C10)",
      str((LAB / "KILLSWITCH").resolve()) in fs["denyWrite"], str(fs["denyWrite"]))
check("network is the policy's allowed_domains and nothing more",
      net["allowedDomains"] == ["example.com"], str(net))
check("--deny-all-network allows no domain at all",
      sandbox_mod.profile_from_policy(POLICY, deny_all_network=True)
      ["network"]["allowedDomains"] == [])

digest = sandbox_mod.digest_of(doc)
check("the digest is stable across identical documents",
      digest == sandbox_mod.digest_of(sandbox_mod.profile_from_policy(POLICY)))

ok, wanted = sandbox_mod.matches_policy(POLICY)
check("no profile on disk yet reads as 'does not match'", not ok)
written = sandbox_mod.write_profile(doc)
check("the profile is written at 0600",
      (written.stat().st_mode & 0o777) == 0o600,
      oct(written.stat().st_mode & 0o777))
ok, _ = sandbox_mod.matches_policy(POLICY)
check("...and now matches the policy", ok)

# Change the policy; the profile must stop matching and regenerate differently.
changed = dict(POLICY_DOC,
               deny_paths=[".env", "*.pem", "id_rsa", "**/.aws/**", "**/.ssh/**",
                           "secrets.txt"])
CHANGED_PATH = LAB / "policy-changed.json"
CHANGED_PATH.write_text(json.dumps(changed))
os.chmod(CHANGED_PATH, 0o600)
CHANGED = Policy.load(CHANGED_PATH)
ok_after, digest_after = sandbox_mod.matches_policy(CHANGED)
check("an edited policy no longer matches the profile on disk", not ok_after)
check("...and the regenerated digest differs", digest_after != digest)
check("...because the new pattern is in it",
      "/**/secrets.txt"
      in sandbox_mod.profile_from_policy(CHANGED)["filesystem"]["denyRead"])


# ---------------------------------------------------------------------------
rule("3. KERNEL ENFORCEMENT — the checks the sprint exists for")
# ---------------------------------------------------------------------------

# Controls first: prove the files exist and are readable with no sandbox, so a
# denial below cannot be an absence wearing a denial's clothes.
for path, label in ((KEYFILE, "the fake ssh key"), (AWSFILE, "the fake aws creds"),
                    (ENVFILE, "the workspace .env")):
    got = unsandboxed(f"cat {path}")
    check(f"CONTROL: {label} really exists and is readable unsandboxed",
          got.returncode == 0 and got.stdout.strip() != "",
          f"rc={got.returncode} {got.stderr[:80]}")

box = None
if problems:
    not_run("kernel enforcement (§3) and the proxy inside the sandbox (§4)",
            "no usable sandbox runtime on this machine: "
            + "; ".join(p.splitlines()[0] for p in problems))
else:
    box = sandbox_mod.establish(POLICY)
    print(f"  {box.summary()}")
    check("the runtime accepted the generated profile", True)

if box is not None:
    # --- reads -------------------------------------------------------------
    got = sh(box, f"cat {KEYFILE}")
    check("bash cat of a deny_paths file FAILS inside the sandbox",
          got.returncode != 0 and "PRIVATE-KEY-BYTES-S9" not in got.stdout,
          f"rc={got.returncode} out={got.stdout[:80]}")
    check("...with a kernel error, not a policy message",
          "Operation not permitted" in got.stderr and "AEGIS" not in got.stderr,
          got.stderr[:160])

    got = sh(box, f"cat {AWSFILE}")
    check("a deny_paths directory pattern is enforced too (**/.aws/**)",
          got.returncode != 0 and "S9SECRET" not in got.stdout, got.stdout[:80])

    got = sh(box, f"cat {ENVFILE}")
    check("a deny_paths file INSIDE the workspace is still denied",
          got.returncode != 0 and "s9-env-secret" not in got.stdout,
          f"rc={got.returncode} out={got.stdout[:80]}")
    check("...which is deny-beats-allow, the same precedence policy.py uses",
          "Operation not permitted" in got.stderr, got.stderr[:120])

    got = sh(box, f"cat {PLAIN}")
    check("an ordinary workspace file is still readable",
          got.returncode == 0 and "ordinary workspace file" in got.stdout,
          f"rc={got.returncode} {got.stderr[:120]}")

    # Reading the key by a route that is not `cat`, in case cat is special.
    got = sh(box, f"python3 -c \"print(open('{KEYFILE}').read())\"")
    check("the denial is not specific to one program",
          "PRIVATE-KEY-BYTES-S9" not in got.stdout, got.stdout[:120])

    # --- writes ------------------------------------------------------------
    got = sh(box, f"echo written > {WS}/new-file.txt && echo OK")
    check("a legitimate write inside a workspace root SUCCEEDS",
          got.returncode == 0 and "OK" in got.stdout,
          f"rc={got.returncode} {got.stderr[:160]}")
    check("...and really landed on disk", (WS / "new-file.txt").exists())

    got = sh(box, f"echo escaped > {OUTSIDE}/escape.txt && echo OK")
    check("a write OUTSIDE workspace_roots fails",
          got.returncode != 0 and not (OUTSIDE / "escape.txt").exists(),
          f"rc={got.returncode} out={got.stdout[:80]}")
    check("...with a kernel error", "not permitted" in got.stderr.lower(),
          got.stderr[:160])

    got = sh(box, f"echo '{{}}' > {POLICY_PATH} && echo OK")
    check("the agent cannot rewrite policy.json (A7, kernel-enforced)",
          got.returncode != 0, f"rc={got.returncode}")
    check("...and the policy is unchanged afterwards",
          json.loads(POLICY_PATH.read_text())["deny_paths"] == POLICY_DOC["deny_paths"])

    (LAB / "KILLSWITCH").write_text("engaged_by=test\n")
    got = sh(box, f"rm -f {LAB}/KILLSWITCH; echo rc=$?")
    check("the agent cannot delete the kill switch (C10 survives inside)",
          (LAB / "KILLSWITCH").exists(), got.stdout[:120])
    (LAB / "KILLSWITCH").unlink()

    # --- network -----------------------------------------------------------
    got = sh(box, "curl -s -m 15 -o /dev/null -w '%{http_code}' "
                  "https://evil.xyz/ ; echo \" rc=$?\"")
    check("bash curl to a host outside allowed_domains fails",
          " rc=0" not in got.stdout, got.stdout[:120])

    closed = sandbox_mod.establish(POLICY, deny_all_network=True)
    got = sh(closed, "curl -s -m 15 -o /dev/null -w '%{http_code}' "
                     "https://example.com/ ; echo \" rc=$?\"")
    check("with --deny-all-network, even an allowed domain is unreachable",
          " rc=0" not in got.stdout, got.stdout[:120])

    # Put the ordinary profile back for the sections that follow.
    box = sandbox_mod.establish(POLICY)

    # The residual, observed rather than only described: the sandbox cannot tell
    # the proxy's request from bash's, so an allowed domain IS reachable here.
    got = sh(box, "curl -s -m 20 -o /dev/null -w '%{http_code}' "
                  "https://example.com/ ; echo \" rc=$?\"")
    print("  KNOWN RESIDUAL — bash reaching an allowed domain from inside the")
    print(f"           sandbox: observed {got.stdout.strip()[:40]!r}. Documented in")
    print("           S9-REPORT.md §The network residual; not a pass or a fail.")


# ---------------------------------------------------------------------------
rule("4. THE MCP PROXY STILL WORKS INSIDE THE SANDBOX")
# ---------------------------------------------------------------------------

if box is None:
    not_run("the proxy inside the sandbox", "no sandbox runtime")
else:
    db = LAB / "audit.db"
    before = 0
    if db.exists():
        con = sqlite3.connect(str(db))
        before = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        con.close()

    frames = "\n".join(json.dumps(f) for f in [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "s9", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": str(PLAIN)}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": str(KEYFILE)}}},
    ]) + "\n"

    inner = box.wrap([sys.executable, str(ROOT / "aegis" / "proxy.py"), "--",
                      sys.executable, str(ROOT / "tests" / "mock_fs_server.py")])
    got = subprocess.run(inner, input=frames, capture_output=True, text=True,
                         timeout=180, env=ENV)
    replies = [json.loads(l) for l in got.stdout.splitlines() if l.strip()]
    by_id = {r.get("id"): r for r in replies}

    check("the proxy starts and speaks MCP inside the sandbox", 2 in by_id,
          got.stderr[-400:])
    if 2 in by_id:
        text2 = by_id[2]["result"]["content"][0]["text"]
        check("an allowed read is forwarded and answered",
              by_id[2]["result"].get("isError") is not True and "MOCK SERVER" in text2,
              text2[:120])
    if 3 in by_id:
        text3 = by_id[3]["result"]["content"][0]["text"]
        check("a deny_paths read is still denied by the MCP layer",
              by_id[3]["result"].get("isError") is True and "AEGIS DENIED" in text3,
              text3[:120])
        check("...so both layers cover it: the MCP layer says why, the kernel says no",
              "deny_paths" in text3, text3[:160])

    con = sqlite3.connect(str(db))
    after = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    con.close()
    check("the audit log was written from inside the sandbox (C3 survives)",
          after > before, f"{before} -> {after}")

    v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"), str(db)],
                       capture_output=True, text=True, timeout=120)
    check("the chain still verifies", v.returncode == 0, (v.stdout + v.stderr)[:200])


# ---------------------------------------------------------------------------
rule("5. `aegis run` — refusal, and what it records")
# ---------------------------------------------------------------------------


def aegis_run(args, extra_env=None, timeout=180):
    return subprocess.run(
        [sys.executable, "-m", "aegis.cli", "run", *args],
        capture_output=True, text=True, timeout=timeout,
        env={**ENV, **(extra_env or {})},
    )


got = aegis_run(["--", "echo", "SHOULD-NOT-RUN"],
                {"AEGIS_SANDBOX_RUNTIME": str(LAB / "no-such-binary")})
check("aegis run REFUSES when the sandbox cannot be established",
      got.returncode != 0, f"exit {got.returncode}")
check("...and launches nothing", "SHOULD-NOT-RUN" not in got.stdout, got.stdout[:120])
check("...and says REFUSING TO LAUNCH", "REFUSING TO LAUNCH" in got.stderr,
      got.stderr[:200])
check("...and explains why an unconfined fallback would be worse",
      "looks sandboxed" in got.stderr, got.stderr[-300:])

db = LAB / "audit.db"
rows = list(sqlite3.connect(str(db)).execute(
    "SELECT effect, rule_id, reason FROM audit WHERE tool='aegis run' ORDER BY id"))
check("the refusal is recorded", any(r[1] == "sandbox_refused" for r in rows),
      str(rows)[:200])
check("...as a denial",
      any(r[0] == "deny" and r[1] == "sandbox_refused" for r in rows))

if problems:
    not_run("aegis run launching successfully", "no sandbox runtime")
else:
    got = aegis_run(["--", "echo", "LAUNCHED-INSIDE"])
    check("aegis run launches the command inside the sandbox",
          got.returncode == 0 and "LAUNCHED-INSIDE" in got.stdout,
          f"exit {got.returncode} {got.stderr[-300:]}")
    check("...and reports the boundary it does not cover",
          "§7.6" in got.stderr and "§7.7" in got.stderr, got.stderr[-300:])

    rows = list(sqlite3.connect(str(db)).execute(
        "SELECT effect, rule_id, reason FROM audit WHERE tool='aegis run' ORDER BY id"))
    est = [r for r in rows if r[1] == "sandbox_established"]
    check("establishment is recorded", bool(est), str(rows)[:200])
    check("...with the profile digest in the reason",
          any(sandbox_mod.digest_of(sandbox_mod.profile_from_policy(POLICY))[:16] in r[2]
              for r in est), str(est)[:300])

    got = aegis_run(["--print-profile"])
    check("--print-profile emits the document without launching",
          got.returncode == 0 and "allowWrite" in got.stdout, got.stdout[:120])

got = aegis_run([])
check("aegis run with no command is a usage error", got.returncode == 64,
      f"exit {got.returncode}")

BAD_POLICY = LAB / "broken-policy.json"
BAD_POLICY.write_text("{ not json")
os.chmod(BAD_POLICY, 0o600)
got = aegis_run(["--", "echo", "NOPE"], {"AEGIS_POLICY": str(BAD_POLICY)})
check("an unloadable policy refuses the launch too",
      got.returncode != 0 and "NOPE" not in got.stdout, f"exit {got.returncode}")
check("...naming the policy as the source of the profile",
      "generated from" in got.stderr, got.stderr[:300])


# ---------------------------------------------------------------------------
rule("6. KERNEL DENIALS REACH THE AUDIT LOG (S9 gap 7)")
# ---------------------------------------------------------------------------

from aegis import violations as violations_mod  # noqa: E402

# --- the parser, against real captured lines --------------------------------
REAL_LINES = {
    "file": "2026-08-19 16:06:14.960 E  kernel[0:21d8a] (Sandbox) Sandbox: "
            "cat(7866) deny(1) file-read-data /private/tmp/x/.ssh/id_rsa",
    "dup":  "2026-08-19 16:06:12.959 E  kernel[0:21d5c] (Sandbox) 3 duplicate "
            "reports for Sandbox: assistantd(800) deny(1) "
            "iokit-open-user-client AppleKeyStoreUserClient",
    "net":  "2026-08-19 16:07:01.452 E  kernel[0:2232b] (Sandbox) Sandbox: "
            "nc(7936) deny(1) network-outbound remote:*:443",
}
m = violations_mod.VIOLATION_RE.search(REAL_LINES["file"])
check("a real kernel violation line parses", m is not None)
if m:
    check("...with the process, pid, operation and path",
          (m.group("proc"), m.group("pid"), m.group("op"), m.group("detail"))
          == ("cat", "7866", "file-read-data", "/private/tmp/x/.ssh/id_rsa"),
          str(m.groups()))
m = violations_mod.VIOLATION_RE.search(REAL_LINES["dup"])
check("the kernel's 'N duplicate reports' form also parses",
      m is not None and m.group("proc") == "assistantd", str(m and m.groups()))
m = violations_mod.VIOLATION_RE.search(REAL_LINES["net"])
check("a network denial parses but carries NO host, only a port",
      m is not None and m.group("detail") == "remote:*:443"
      and "nc" not in m.group("detail"), str(m and m.group("detail")))

pats = violations_mod.deny_patterns(sandbox_mod.profile_from_policy(POLICY))
check("a denied path matching our policy is attributable",
      violations_mod.matches_policy(str(KEYFILE.resolve()), pats), str(pats)[:120])
check("an ordinary workspace path is NOT attributable",
      not violations_mod.matches_policy(str(PLAIN.resolve()), pats))
check("a macOS daemon's own denial is not attributable to our policy",
      not violations_mod.matches_policy("/System/Library/Frameworks/x", pats))

# --- end to end through aegis run -------------------------------------------
if problems:
    not_run("kernel denials reaching the audit log",
            "no sandbox runtime, so nothing can be denied by a kernel")
else:
    denial_db = LAB / "denials.db"
    got = aegis_run(
        ["--", "bash", "-c",
         f"cat {KEYFILE}; cat {ENVFILE}; cat {PLAIN}; "
         f"curl -s -m 8 -o /dev/null https://evil.xyz/ || true"],
        {"AEGIS_AUDIT_DB": str(denial_db)}, timeout=300)

    rows = list(sqlite3.connect(str(denial_db)).execute(
        "SELECT tool, effect, rule_id, reason, paths FROM audit ORDER BY id"))
    denied = [r for r in rows if r[2] == "sandbox_denied"]
    for r in denied:
        print(f"    {r[0]:<16} {r[2]}  {json.loads(r[4])}")

    check("a kernel denial produces an audit row", len(denied) >= 1,
          f"rows={[(r[0], r[2]) for r in rows]}  stderr={got.stderr[-300:]}")
    check("...one per denied path, for both denied files", len(denied) >= 2,
          str([json.loads(r[4]) for r in denied]))
    check("...recording the path", any(str(KEYFILE.resolve()) in r[4] for r in denied),
          str([r[4] for r in denied]))
    check("...naming the process that was refused",
          any(r[0].startswith("sandbox:") for r in denied), str([r[0] for r in denied]))
    check("...as a denial", all(r[1] == "deny" for r in denied))
    check("...saying the KERNEL refused it, not the policy engine",
          all("OS-level denial (EPERM)" in r[3] and "not a policy-engine" in r[3]
              for r in denied), str(denied[:1]))
    check("the allowed read produced no denial row",
          not any(str(PLAIN.resolve()) in r[4] for r in denied))

    est = [r for r in rows if r[2] == "sandbox_established"]
    closed = [r for r in rows if r[2] == "sandbox_closed"]
    check("the session records that it was watching", bool(est))
    check("...and a closing row summarising what was seen", bool(closed))
    check("...which counts the denials it could not attribute rather than "
          "dropping them silently",
          any("not recorded" in r[3] or "benign" in r[3] for r in closed),
          str(closed)[:300])
    check("...and states plainly that blocked HOSTS are not recordable",
          any("never reaches the kernel log" in r[3] for r in closed),
          str(closed)[:400])
    check("no row invents a host for the blocked curl",
          not any("evil.xyz" in r[3] for r in rows), str(rows)[:200])

    v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"),
                        str(denial_db)], capture_output=True, text=True, timeout=120)
    check("the chain verifies with sandbox_denied rows in it", v.returncode == 0,
          (v.stdout + v.stderr)[:200])
    check("...and they use the existing row rule, not a new schema",
          "row(s) verified" in v.stdout, v.stdout[:120])

# --- doctor reports sandbox status ------------------------------------------
doc_env = {"AEGIS_POLICY": str(POLICY_PATH), "PYTHONPATH": str(ROOT),
           "AEGIS_AUDIT_DB": str(LAB / "doctor.db"),
           "AEGIS_SANDBOX_PROFILE": str(LAB / "sandbox-profile.json"),
           "AEGIS_KILLSWITCH": str(LAB / "KILLSWITCH")}
got = subprocess.run([sys.executable, "-m", "aegis.cli", "doctor", "--no-probe"],
                     capture_output=True, text=True, timeout=300,
                     env={**os.environ, **doc_env}, cwd=str(LAB))
check("doctor reports the sandbox", "OS sandbox (C11)" in got.stdout, got.stdout[:300])
check("...saying whether the runtime is present",
      "runtime present" in got.stdout or "not on PATH" in got.stdout, got.stdout[:400])
check("...and that aegis run is REQUIRED for any kernel enforcement",
      "ONLY to agents started with `aegis run`" in got.stdout, got.stdout[:600])
check("...and that an agent started any other way has no boundary",
      "no kernel boundary" in got.stdout, got.stdout[:600])
check("doctor's NOT COVERED section no longer claims Bash is simply uncovered",
      "UNLESS the agent was started with `aegis run`" in got.stdout,
      got.stdout[-1500:])

# A profile that disagrees with the policy is a FAIL, not a warning.
(LAB / "sandbox-profile.json").write_text(json.dumps(
    {"filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
     "network": {"allowedDomains": [], "deniedDomains": []}}))
got = subprocess.run([sys.executable, "-m", "aegis.cli", "doctor", "--no-probe"],
                     capture_output=True, text=True, timeout=300,
                     env={**os.environ, **doc_env}, cwd=str(LAB))
check("a profile that does not match the policy FAILS doctor",
      "[ FAIL ] OS sandbox (C11)" in got.stdout and got.returncode != 0,
      got.stdout[:600])
sandbox_mod.write_profile(sandbox_mod.profile_from_policy(POLICY))


# ---------------------------------------------------------------------------
rule("SUMMARY")
# ---------------------------------------------------------------------------

now = {
    str(p): (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "absent")
    for p in REAL_WATCH
}
check("the operator's real Aegis state is untouched", now == BASELINE,
      str([k for k in BASELINE if BASELINE[k] != now[k]]))

print(f"\n  {PASSED} passed, {FAILED} failed, {len(NOT_RUN)} NOT RUN")
if FAILURES:
    print("\n  failures:")
    for name in FAILURES:
        print(f"    - {name}")
if NOT_RUN:
    print("\n  NOT established by this run:")
    for what, why in NOT_RUN:
        print(f"    - {what}\n      {why}")
    print("\n  The suite exits non-zero because of them. A skipped check that")
    print("  reads as green puts a tick next to something nobody verified.")

print(f"\n  lab: {LAB}   (delete when done)")
print(f"  outside dir: {OUTSIDE}")
print(
    "\n  Never established by this suite, on any machine:\n"
    "    - that a kernel escape is survivable. It is not (THREAT-MODEL.md §7.7)\n"
    "    - anything about an agent the user starts themselves (§7.6)\n"
    "    - Linux/bubblewrap. Nothing here has run on Linux\n"
)
sys.exit(1 if (FAILED or NOT_RUN) else 0)
