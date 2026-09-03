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
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
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

from aegis import egress  # noqa: E402
from aegis import launcher as launcher_mod  # noqa: E402
from aegis import sandbox as sandbox_mod  # noqa: E402
from aegis.policy import Policy, PolicyError  # noqa: E402

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

# --- S9d: the client's own endpoints, and the line between the two lists ----
#
# The reported failure: `aegis init` writes allowed_domains: [], the profile
# therefore grants zero hosts, and a client wrapped by S9c cannot reach its own
# API. Measured with the runtime's own debug output — twenty refusals of
# api.anthropic.com in one Claude Code start, and "Session creation failed" on
# screen. `sandbox_domains` is the narrow fix: it opens the socket without
# opening C4's egress allowlist.
NO_NET_PATH = LAB / "policy-nonet.json"
NO_NET_PATH.write_text(json.dumps(dict(POLICY_DOC, allowed_domains=[])))
os.chmod(NO_NET_PATH, 0o600)
POLICY_NO_NET = Policy.load(NO_NET_PATH)
check("the reported shape reproduces: an empty policy grants zero hosts",
      sandbox_mod.profile_from_policy(POLICY_NO_NET)["network"]["allowedDomains"] == [],
      "a wrapped client here cannot reach its own API")

NETDOC = dict(POLICY_DOC, allowed_domains=["example.com"],
              sandbox_domains=["api.anthropic.com", "downloads.claude.ai"])
NET_PATH = LAB / "policy-net.json"
NET_PATH.write_text(json.dumps(NETDOC))
os.chmod(NET_PATH, 0o600)
NETPOL = Policy.load(NET_PATH)
netdoc = sandbox_mod.profile_from_policy(NETPOL)

check("sandbox_domains reaches the kernel profile",
      set(netdoc["network"]["allowedDomains"])
      == {"example.com", "api.anthropic.com", "downloads.claude.ai"},
      str(netdoc["network"]))
check("...and does NOT widen the proxy's egress allowlist (C4)",
      NETPOL.allowed_domains == ("example.com",), str(NETPOL.allowed_domains))
check("...so a fetch to the client's API is still refused by policy",
      not egress.host_allowed("api.anthropic.com", NETPOL.allowed_domains))
check("--deny-all-network clears sandbox_domains too",
      sandbox_mod.profile_from_policy(NETPOL, deny_all_network=True)
      ["network"]["allowedDomains"] == [])
check("adding a client endpoint changes the digest, so doctor reports it",
      sandbox_mod.digest_of(netdoc) != sandbox_mod.digest_of(doc))
# Each profile write-denies its OWN policy file, so the two documents differ by
# exactly that path and by nothing else. Comparing them raw would fail for a
# reason that has nothing to do with the network grant.
def _fs_without_policy_file(document, policy_file):
    fs = {k: list(v) for k, v in document["filesystem"].items()}
    fs["denyWrite"] = [e for e in fs["denyWrite"] if e != str(Path(policy_file).resolve())]
    return fs

check("nothing about the filesystem moved with it",
      _fs_without_policy_file(netdoc, NET_PATH)
      == _fs_without_policy_file(doc, POLICY_PATH),
      "the network grant touched denyRead/allowWrite/denyWrite")

def _refuses(build) -> bool:
    """True when constructing that policy raises rather than accepting it."""
    try:
        build()
    except PolicyError:
        return True
    return False


# No spelling of "everything" exists in either list.
for bad in ("*", "*.anthropic.com", "https://api.anthropic.com", "api.anthropic.com/v1"):
    check(f"sandbox_domains refuses {bad!r} — an allowlist that can say "
          f"'everything' is not one",
          _refuses(lambda b=bad: Policy(dict(POLICY_DOC, sandbox_domains=[b]), NET_PATH)))

check("the endpoint table only names hosts that were measured",
      all(isinstance(h, str) and "/" not in h and "*" not in h
          for h, _p, _r in launcher_mod.client_endpoints("claude")),
      str(launcher_mod.CLIENT_ENDPOINTS["claude"]))
check("...and an unmeasured client gets an empty list, not a guess",
      launcher_mod.client_endpoints("cursor") == [],
      str(launcher_mod.CLIENT_ENDPOINTS.get("cursor")))
check("...with api.anthropic.com marked required, since no session starts without it",
      ("api.anthropic.com", True) in
      [(h, r) for h, _p, r in launcher_mod.client_endpoints("claude")],
      str(launcher_mod.client_endpoints("claude")))
# --- S9f: the client's own state -------------------------------------------
#
# The sandbox granted write access to the workspace, the data directory and
# /tmp. A client's own state directory was none of those, so a wrapped client
# started and then failed every request with a 401 it could not refresh, lost
# its transcripts, and could not start remote control. Measured from kernel
# denials, not guessed.
STATE_HOME = LAB / "fakehome"
STATE_DIR = STATE_HOME / ".claude"
STATE_DIR.mkdir(parents=True, exist_ok=True)
(STATE_DIR / "settings.json").write_text('{"hooks": {}}\n')
(STATE_DIR / "plugins").mkdir(exist_ok=True)
(STATE_DIR / "projects").mkdir(exist_ok=True)

STATE_DOC = dict(POLICY_DOC,
                 sandbox_state_paths=[str(STATE_DIR)],
                 sandbox_state_protect=[str(STATE_DIR / "settings.json"),
                                        str(STATE_DIR / "plugins"),
                                        str(STATE_DIR / ".credentials.json")])
STATE_PATH = LAB / "policy-state.json"
STATE_PATH.write_text(json.dumps(STATE_DOC))
os.chmod(STATE_PATH, 0o600)
STATEPOL = Policy.load(STATE_PATH)
statedoc = sandbox_mod.profile_from_policy(STATEPOL)

check("a state path reaches the profile's allowWrite",
      str(STATE_DIR.resolve()) in statedoc["filesystem"]["allowWrite"],
      str(statedoc["filesystem"]["allowWrite"]))
check("...and the protected paths reach denyWrite, which beats it",
      all(str((STATE_DIR / n).resolve()) in statedoc["filesystem"]["denyWrite"]
          for n in ("settings.json", "plugins", ".credentials.json")),
      str(statedoc["filesystem"]["denyWrite"]))
check("...including the contents of a protected directory",
      str((STATE_DIR / "plugins").resolve()) + "/**"
      in statedoc["filesystem"]["denyWrite"],
      str(statedoc["filesystem"]["denyWrite"]))
check("...while READING them is deliberately still allowed, or the client "
      "could not read its own settings to start",
      not any(str((STATE_DIR / "settings.json").resolve()) == e
              for e in statedoc["filesystem"]["denyRead"]),
      str(statedoc["filesystem"]["denyRead"]))
check("the grant does not touch the network rules",
      statedoc["network"] == doc["network"], str(statedoc["network"]))
check("...and every deny_paths pattern survives it",
      all(any(pat in e for e in statedoc["filesystem"]["denyRead"])
          for pat in (".env", "id_rsa", ".aws")),
      str(statedoc["filesystem"]["denyRead"]))
check("adding a state path changes the digest, so doctor reports it",
      sandbox_mod.digest_of(statedoc) != sandbox_mod.digest_of(doc))

# THE rule the sprint turns on: a state grant may never be the home directory.
for bad, why in ((str(Path.home()), "the home directory"),
                 ("~", "the home directory, spelled with a tilde"),
                 ("/", "the filesystem root"),
                 (str(STATE_HOME / ".claud*"), "a pattern")):
    check(f"sandbox_state_paths refuses {why}",
          _refuses(lambda b=bad: Policy(dict(POLICY_DOC, sandbox_state_paths=[b]),
                                        STATE_PATH)))
check("sandbox_state_protect refuses the same things",
      _refuses(lambda: Policy(dict(POLICY_DOC, sandbox_state_protect=["~"]),
                              STATE_PATH)))
check("a state path is not required to exist yet — a credentials file that "
      "has never been written is still protectable",
      Policy(dict(POLICY_DOC,
                  sandbox_state_protect=[str(STATE_DIR / "never-created.json")]),
             STATE_PATH).sandbox_state_protect != ())

check("the state table only names measured paths",
      all("*" not in p_ for p_, _pu, _r in launcher_mod.client_state_paths("claude")),
      str(launcher_mod.CLIENT_STATE_PATHS["claude"]))
check("...with ~/.claude marked required, since no request succeeds without it",
      ("~/.claude", True) in
      [(p_, r) for p_, _pu, r in launcher_mod.client_state_paths("claude")],
      str(launcher_mod.client_state_paths("claude")))
check("...and an unmeasured client gets an empty list, not a guess",
      launcher_mod.client_state_paths("cursor") == [])
# Every entry must be a directory INSIDE the home directory, never the home
# directory itself and never an ancestor of it. `~/.claude` has `~` among its
# parents, which is the point; `/Users` would have `~` among its children,
# which is the thing being forbidden.
_home = Path.home().resolve()
check("...and no entry is the home directory or an ancestor of it",
      all((lambda r: r != _home and r not in _home.parents)(
              Path(p_).expanduser().resolve())
          for p_, _pu, _r in launcher_mod.client_state_paths("claude")),
      str(launcher_mod.client_state_paths("claude")))
check("the files that are code or credentials are protected by default",
      {"~/.claude/settings.json", "~/.claude/plugins", "~/.claude/.credentials.json"}
      <= set(launcher_mod.client_state_protect("claude")),
      str(launcher_mod.client_state_protect("claude")))

check("the telemetry sink is NOT granted by default",
      not any("datadoghq" in h for h, _p, _r in launcher_mod.client_endpoints("claude")),
      str(launcher_mod.client_endpoints("claude")))

# --- and doctor has to SAY so ----------------------------------------------
#
# The reported configuration passed `aegis doctor` cleanly: the profile matched
# the policy exactly, because it was a correct profile for an unusable setup.
# Nothing in the report mentioned that the wrapped client could reach nothing.
from aegis import doctor as doctor_mod  # noqa: E402


def _sandbox_net_check(policy, wrapped):
    report = doctor_mod.Report()
    doctor_mod._check_sandbox_network(report, policy, wrapped)
    return report.checks


starved = _sandbox_net_check(POLICY_NO_NET, True)
check("a wrapped client with no reachable host is a doctor FAIL",
      len(starved) == 1 and starved[0].status == doctor_mod.FAIL,
      str([(c.name, c.status) for c in starved]))
check("...saying what the user will actually see, not an Aegis error code",
      any("Session creation failed" in l for l in starved[0].lines),
      str(starved[0].lines))
check("...and naming sandbox_domains as the fix",
      any("sandbox_domains" in l for l in starved[0].lines), str(starved[0].lines))

fed = _sandbox_net_check(NETPOL, True)
check("...and a PASS once the client can reach its API",
      len(fed) == 1 and fed[0].status == doctor_mod.PASS,
      str([(c.name, c.status) for c in fed]))
check("...naming the hosts rather than counting them",
      any("api.anthropic.com" in l for l in fed[0].lines), str(fed[0].lines))
check("...and restating the residual in the same breath",
      any("Bash tool" in l for l in fed[0].lines), str(fed[0].lines))

check("an UNWRAPPED client with no domains is not warned about — that is the "
      "right default and a warning there would be noise",
      _sandbox_net_check(POLICY_NO_NET, False) == [])

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

# --- S9e: the terminal ------------------------------------------------------
#
# Reported as "mouse escape sequences leak into the input line as literal
# text", and it was neither the mouse nor `aegis run`'s spawn. The runtime's
# profile omitted its pty block, so the kernel refused every ioctl on
# /dev/ttys*, tcsetattr returned EPERM, and nothing inside could enter raw
# mode. A terminal left in canonical+echo echoes back everything the terminal
# sends it — including the SGR mouse reports the client had just asked for.
check("the profile allows terminal control by default",
      doc.get("allowPty") is True, str(doc.get("allowPty")))

NOPTY_PATH = LAB / "policy-nopty.json"
NOPTY_PATH.write_text(json.dumps(dict(POLICY_DOC, sandbox_pty=False)))
os.chmod(NOPTY_PATH, 0o600)
NOPTY = Policy.load(NOPTY_PATH)
nopty_doc = sandbox_mod.profile_from_policy(NOPTY)
check("...and a policy can turn it off for a headless run",
      nopty_doc.get("allowPty") is False, str(nopty_doc.get("allowPty")))
check("...which moves the digest, so doctor reports the change",
      sandbox_mod.digest_of(nopty_doc) != sandbox_mod.digest_of(doc))
check("sandbox_pty refuses a non-boolean rather than guessing at it",
      _refuses(lambda: Policy(dict(POLICY_DOC, sandbox_pty="yes"), NOPTY_PATH)))

# The constraint on this fix: it may not move one path or one domain.
check("granting the terminal moves NOTHING in the filesystem rules",
      _fs_without_policy_file(nopty_doc, NOPTY_PATH)
      == _fs_without_policy_file(doc, POLICY_PATH),
      "the pty grant touched denyRead/allowWrite/denyWrite")
check("...and nothing in the network rules",
      nopty_doc["network"] == doc["network"], str(nopty_doc["network"]))
# Each document write-denies its own policy file, so `filesystem` differs by
# that one path whatever else is true. It is compared above with that path
# removed; here it is simply excluded from the key comparison.
_differs = {k for k in set(doc) | set(nopty_doc) if doc.get(k) != nopty_doc.get(k)}
_differs.discard("filesystem")
check("...so allowPty is the only key that differs",
      _differs == {"allowPty"}, str(_differs))


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
rule("3b. RAW MODE — the reported terminal bug, reproduced through a real pty")
# ---------------------------------------------------------------------------

# The bug: `aegis run -- claude`, move the mouse, and the prompt fills with
# `^[[<65;63;22M`. Running claude directly never does it.
#
# It is not the mouse and it is not `aegis run`'s spawn — `Popen` passes the
# real tty straight through, and the failure is byte-identical under `srt`
# alone. The runtime's profile simply omitted its pty block, so the kernel
# refused ioctls on /dev/ttys*, `tcsetattr` returned EPERM, and the terminal
# stayed in canonical+echo. A terminal in canonical+echo echoes back whatever
# the terminal sends it, which is exactly the SGR mouse reports the client had
# just enabled.
#
# So this section does what no unit assertion can: it allocates a real pty,
# makes it a controlling terminal, and asks a child inside the sandbox whether
# it can enter raw mode. Without a pty a suite cannot see this class of bug at
# all, which is why twelve sprints of green runs did not.

PTY_PROBE = LAB / "ttyprobe.py"
PTY_PROBE.write_text(
    "import json, os, sys, termios, tty\n"
    "info = {}\n"
    "info['isatty'] = os.isatty(0)\n"
    "try:\n"
    "    before = termios.tcgetattr(0)\n"
    "    tty.setraw(0)\n"
    "    after = termios.tcgetattr(0)\n"
    "    info['raw'] = not (after[3] & termios.ICANON) and not (after[3] & termios.ECHO)\n"
    "    info['err'] = None\n"
    "    termios.tcsetattr(0, termios.TCSADRAIN, before)\n"
    "except Exception as exc:\n"
    "    info['raw'], info['err'] = False, repr(exc)\n"
    "try:\n"
    "    info['fg'] = os.tcgetpgrp(0) == os.getpgrp()\n"
    "except Exception as exc:\n"
    "    info['fg'] = repr(exc)\n"
    "print('PROBE ' + json.dumps(info), flush=True)\n"
)


def ask_through_a_pty(argv, seconds=60):
    """Run argv on a real controlling terminal; return the probe's answer."""
    import fcntl
    import pty as pty_mod
    import select
    import struct
    import termios as tmod

    TIOCSCTTY = 0x20007461  # _IO('t', 97) on Darwin
    master, slave = pty_mod.openpty()
    fcntl.ioctl(slave, tmod.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))

    def become_session_leader():
        os.setsid()
        fcntl.ioctl(0, TIOCSCTTY, 0)

    proc = subprocess.Popen(
        argv, stdin=slave, stdout=slave, stderr=slave, env=ENV, cwd=str(LAB),
        close_fds=True, preexec_fn=become_session_leader,
    )
    os.close(slave)
    buf, deadline = b"", time.time() + seconds
    while time.time() < deadline and proc.poll() is None:
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    os.close(master)
    found = re.findall(r"PROBE (\{.*?\})", buf.decode("utf-8", "replace"))
    return json.loads(found[-1]) if found else None


try:
    control = ask_through_a_pty([sys.executable, str(PTY_PROBE)])
except OSError as exc:
    control = None
    not_run("every raw-mode check", f"no pty could be allocated here: {exc}")

if control is None:
    not_run("every raw-mode check", "the control probe produced no output")
else:
    # The control. If raw mode does not work OUTSIDE the sandbox, nothing below
    # means anything — the harness would be measuring itself.
    check("OUTSIDE the sandbox, a child can put the terminal into raw mode",
          control.get("raw") is True, json.dumps(control))
    check("...and it is in the foreground process group, as a shell would leave it",
          control.get("fg") is True, json.dumps(control))

    if control.get("raw") is True:
        pty_box = sandbox_mod.establish(POLICY)
        inside = ask_through_a_pty(pty_box.wrap([sys.executable, str(PTY_PROBE)]))
        print(f"  inside, sandbox_pty on:  {json.dumps(inside)}")
        check("INSIDE the sandbox it can too — this is the fix",
              inside is not None and inside.get("raw") is True,
              json.dumps(inside))
        check("...with the terminal ioctls no longer refused",
              inside is not None and inside.get("err") is None,
              str(inside.get("err") if inside else None))

        # And the regression itself: turn the grant off and the bug comes back.
        # A test that only proves the fixed state cannot tell you the fix is
        # what did it.
        nopty_box = sandbox_mod.establish(NOPTY)
        broken = ask_through_a_pty(nopty_box.wrap([sys.executable, str(PTY_PROBE)]))
        print(f"  inside, sandbox_pty off: {json.dumps(broken)}")
        check("with sandbox_pty off the bug returns — raw mode is refused",
              broken is not None and broken.get("raw") is False,
              json.dumps(broken))
        check("...with EPERM from the kernel, not a missing terminal",
              broken is not None and broken.get("isatty") is True
              and "not permitted" in str(broken.get("err", "")).lower(),
              json.dumps(broken))

        # `establish()` writes to ONE path, so pty_box and nopty_box name the
        # same file on disk and the last one written wins. Re-establish before
        # asserting anything about the granting profile — the first draft of
        # this section did not, ran the checks below against the OTHER
        # policy's profile, and cheerfully overwrote the lab's policy.json.
        pty_box = sandbox_mod.establish(POLICY)

        # The constraint, live rather than by inspection: the profile that
        # grants the terminal must still deny everything it denied before.
        got = sh(pty_box, f"cat {KEYFILE}")
        check("...and the ssh key is STILL unreadable with the terminal granted",
              "PRIVATE-KEY-BYTES-S9" not in got.stdout, got.stdout[:120])
        got = sh(pty_box, f"cat {ENVFILE}")
        check("...and .env inside the workspace STILL is too",
              "s9-env-secret" not in got.stdout, got.stdout[:120])
        got = sh(pty_box, f"echo escaped > {OUTSIDE}/pty-escape.txt && echo OK")
        check("...and a write outside workspace_roots STILL fails",
              got.returncode != 0 and not (OUTSIDE / "pty-escape.txt").exists(),
              f"rc={got.returncode} {got.stdout[:80]}")
        got = sh(pty_box, f"echo '{{}}' > {POLICY_PATH} && echo OK")
        check("...and policy.json STILL cannot be rewritten",
              got.returncode != 0, f"rc={got.returncode}")
        check("...and it is still the policy this suite wrote",
              json.loads(POLICY_PATH.read_text())["version"] == 1,
              "the lab policy was overwritten by a check that was supposed to fail")
        got = sh(pty_box, "curl -s -m 15 -o /dev/null -w '%{http_code}' "
                          "https://evil.xyz/ ; echo \" rc=$?\"")
        check("...and a host outside allowed_domains STILL is not reachable",
              " rc=0" not in got.stdout, got.stdout[:120])

        # Put the ordinary profile back for the sections that follow.
        box = sandbox_mod.establish(POLICY)


# ---------------------------------------------------------------------------
rule("3c. THE CLIENT'S STATE — granted at the kernel, and bounded there")
# ---------------------------------------------------------------------------

# A profile that grants a state directory is only defensible if the carve-outs
# inside it actually hold. denyWrite beating allowWrite is a documented
# property of the runtime; documented is not measured, so it is measured here.
#
# `establish()` writes to ONE path, so the box has to be re-established
# immediately before use — the same trap §3b fell into.
state_box = sandbox_mod.establish(STATEPOL)

got = sh(state_box, f"echo transcript > {STATE_DIR}/projects/session.jsonl && echo OK")
check("a state file inside the granted directory CAN be written",
      "OK" in got.stdout, f"rc={got.returncode} {got.stderr[:160]}")
check("...and really landed", (STATE_DIR / "projects" / "session.jsonl").exists())

SETTINGS = STATE_DIR / "settings.json"
original = SETTINGS.read_text()
for label, script in (
    ("appended to", f"echo evil >> {SETTINGS} && echo OK"),
    ("truncated", f": > {SETTINGS} && echo OK"),
    ("deleted", f"rm -f {SETTINGS} && echo OK"),
    ("renamed away", f"mv {SETTINGS} {SETTINGS}.bak && echo OK"),
):
    got = sh(state_box, script)
    check(f"settings.json cannot be {label} — it can define hooks, so writing "
          f"it is code execution outside the sandbox",
          "OK" not in got.stdout, f"rc={got.returncode} {got.stdout[:80]}")
check("...and it is byte-for-byte unchanged after all four attempts",
      SETTINGS.exists() and SETTINGS.read_text() == original,
      "settings.json was modified by a sandboxed shell")

got = sh(state_box, f"echo code > {STATE_DIR}/plugins/evil.js && echo OK")
check("nothing can be written into the plugins directory either",
      "OK" not in got.stdout and not (STATE_DIR / "plugins" / "evil.js").exists(),
      f"rc={got.returncode} {got.stdout[:80]}")

got = sh(state_box, f"echo token > {STATE_DIR}/.credentials.json && echo OK")
check("a credentials file cannot be created or replaced there",
      "OK" not in got.stdout and not (STATE_DIR / ".credentials.json").exists(),
      f"rc={got.returncode} {got.stdout[:80]}")

# The residual, asserted so it cannot change without someone noticing. This is
# NOT a protection — it is the thing THREAT-MODEL.md §7.11 says out loud.
got = sh(state_box, f"cat {SETTINGS}")
check("READING the protected files is still possible — the documented residual",
      "hooks" in got.stdout, got.stdout[:120])

# And the grant moves nothing else.
got = sh(state_box, f"cat {KEYFILE}")
check("...the ssh key is STILL unreadable with a state directory granted",
      "PRIVATE-KEY-BYTES-S9" not in got.stdout, got.stdout[:120])
got = sh(state_box, f"echo escaped > {OUTSIDE}/state-escape.txt && echo OK")
check("...a write outside workspace_roots STILL fails",
      "OK" not in got.stdout and not (OUTSIDE / "state-escape.txt").exists(),
      f"rc={got.returncode}")
got = sh(state_box, f"echo '{{}}' > {STATE_PATH} && echo OK")
check("...and the policy that granted it STILL cannot be rewritten",
      "OK" not in got.stdout, f"rc={got.returncode}")
check("...and that policy is intact on disk",
      json.loads(STATE_PATH.read_text())["version"] == 1)

# Put the ordinary profile back for the sections that follow.
box = sandbox_mod.establish(POLICY)


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
        {"AEGIS_AUDIT_DB": str(denial_db),
         "AEGIS_DENIAL_LOG": str(LAB / "denials.log")}, timeout=300)

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

    # --- S9g: where the per-denial LINES go -------------------------------
    #
    # They used to be printed to stderr while the child ran. Against a batch
    # command that is right; against a full-screen client it is unusable — the
    # client repaints the alternate screen continuously and every line lands
    # mid-frame, dozens of them per turn.
    #
    # This block is stderr-is-a-pipe, because aegis_run captures output. That
    # is the NON-interactive case and must be unchanged, which is what the
    # existing checks above already assert. What is added here is the file.
    check("the run streamed denials, because stderr was a pipe, not a terminal",
          "kernel denied" in got.stderr, got.stderr[-300:])
    check("...and said nothing about suppressing them",
          "not printed here" not in got.stderr, got.stderr[-300:])

    dlog = LAB / "denials.log"
    check("every denial ALSO went to the rotating file",
          dlog.exists() and dlog.read_text().count("kernel denied") >= len(denied),
          f"{dlog}: {dlog.read_text()[:200] if dlog.exists() else 'missing'}")
    check("...at 0600, like everything else Aegis writes",
          dlog.exists() and (dlog.stat().st_mode & 0o777) == 0o600,
          oct(dlog.stat().st_mode & 0o777) if dlog.exists() else "missing")
    check("...naming the path the kernel refused",
          dlog.exists() and str(KEYFILE.resolve()) in dlog.read_text(),
          dlog.read_text()[:200] if dlog.exists() else "missing")
    check("...and timestamped, so tailing it is useful",
          dlog.exists() and re.search(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ",
                                      dlog.read_text(), re.M) is not None,
          dlog.read_text()[:120] if dlog.exists() else "missing")

    # --- the file rotates rather than growing forever ---------------------
    rot = LAB / "rotate.log"
    log = violations_mod.DenialLog(rot)
    log.write("x" * 400)
    real_max = violations_mod.DENIAL_LOG_MAX_BYTES
    try:
        violations_mod.DENIAL_LOG_MAX_BYTES = 200
        for _ in range(4):
            log.write("y" * 400)
    finally:
        violations_mod.DENIAL_LOG_MAX_BYTES = real_max
    check("the denial log rotates instead of growing without bound",
          rot.with_name(rot.name + ".1").exists(), str(sorted(
              p_.name for p_ in LAB.glob("rotate.log*"))))
    check("...keeping a bounded number of old files",
          len(list(LAB.glob("rotate.log*"))) <= violations_mod.DENIAL_LOG_KEEP + 1,
          str(sorted(p_.name for p_ in LAB.glob("rotate.log*"))))

    # --- a log that cannot be written never ends the session ---------------
    broken = violations_mod.DenialLog(LAB / "no-such-dir" / "x" / "denials.log")
    (LAB / "no-such-dir").write_text("this is a file, so mkdir under it fails\n")
    broken.write("a denial that cannot be written down")
    check("a denial log that cannot be written records the failure, never raises",
          broken.error is not None and broken.written == 0, str(broken.error))
    (LAB / "no-such-dir").unlink()

    # --- S9j, live: one session must not record another's denials ---------
    #
    # The unit checks above drive the classifier directly. This drives the
    # whole thing: a real `aegis run` that touches nothing at all, and a real
    # second sandbox that reads a denied file while it is open. Before S9j the
    # first session recorded the second session's denial as its own.
    cross_db = LAB / "cross-session.db"
    quiet = subprocess.Popen(
        [sys.executable, "-m", "aegis.cli", "run", "--", "bash", "-c", "sleep 22"],
        env={**ENV, "AEGIS_AUDIT_DB": str(cross_db),
             "AEGIS_DENIAL_LOG": str(LAB / "cross.log")},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(9)
    # A DIFFERENT sandbox, using the same profile so the path matches the same
    # deny patterns — which is exactly what made the two indistinguishable.
    subprocess.run(
        [sandbox_mod.find_runtime(), "-s", str(sandbox_mod.profile_path()),
         "-c", f"cat {KEYFILE}"],
        capture_output=True, timeout=180)
    quiet.wait(timeout=120)

    cross = sqlite3.connect(str(cross_db))
    cross_rows = list(cross.execute(
        "SELECT rule_id, paths FROM audit WHERE rule_id LIKE 'sandbox_denied%'"))
    closing = list(cross.execute(
        "SELECT reason FROM audit WHERE rule_id = 'sandbox_closed'"))
    check("a session that touched nothing records NO denial rows",
          cross_rows == [],
          f"rows another sandbox caused: {[(r[0], r[1]) for r in cross_rows]}")
    check("...and its closing row says a different session's denial was seen",
          closing and "DIFFERENT sandbox session" in closing[0][0],
          str(closing)[:300])
    check("...and states which regime attributed the session",
          closing and "attributed to this session by its sandbox log tag" in closing[0][0],
          str(closing)[:300])
    v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"),
                        str(cross_db)], capture_output=True, text=True, timeout=120)
    check("...and that log verifies", v.returncode == 0, (v.stdout + v.stderr)[:200])

    # --- S9j: whose denial is this? ---------------------------------------
    #
    # The unified log is machine-wide. Until S9j a line became a row whenever
    # its path matched a deny pattern in this session's profile, and nothing
    # checked that this session's tree was what the kernel refused. Measured:
    # a session running `bash -c "sleep 22"`, which touched nothing, recorded a
    # denial caused by an entirely different sandbox.
    #
    # The runtime tags every rule it emits with the sandboxed command, and
    # macOS prints that tag on the line after the violation. That is the
    # attribution.

    check("the wrapped argv separates the agent's flags from the runtime's",
          "--" in box.wrap(["bash", "-c", "x"]),
          str(box.wrap(["bash", "-c", "x"])))
    check("...before the agent's command, so the runtime stops parsing there",
          box.wrap(["bash", "-c", "x"]).index("--")
          < box.wrap(["bash", "-c", "x"]).index("bash"),
          str(box.wrap(["bash", "-c", "x"])))

    prefix = violations_mod.session_tag_prefix(["bash", "-c", "cat /a b"])
    decoded = __import__("base64").b64decode(
        prefix[len(violations_mod.TAG_MARKER):-len("_END_")]).decode()
    check("the session tag encodes the command SHELL-QUOTED, as the runtime does",
          decoded == "bash -c 'cat /a b'", decoded)
    check("...and is truncated where the runtime truncates",
          len(violations_mod.session_tag_prefix(["x" * 400])) < 400,
          str(len(violations_mod.session_tag_prefix(["x" * 400]))))

    def observer_for(command):
        obs = violations_mod.Observer(
            {"filesystem": {"denyRead": ["/**/id_rsa"], "denyWrite": []}},
            command=command)
        return obs

    def vio(tag, path="/home/u/.ssh/id_rsa", op="file-read-data"):
        return violations_mod.Violation(process="cat", pid=1, operation=op,
                                        detail=path, raw="", tag=tag)

    OURS = violations_mod.session_tag_prefix(["cat", "/x"])
    obs = observer_for(["cat", "/x"])
    obs.queue.put(vio(OURS + "_abc_SBX"))
    rows = obs.drain()
    check("a denial carrying THIS session's tag is recorded", len(rows) == 1, str(rows))
    check("...and marked attributed", rows and rows[0].attributed is True)
    check("...and counted as this session's", obs.observation.foreign == 0)

    # Foreign, once our own tag has been proven by any line at all.
    obs = observer_for(["cat", "/x"])
    obs.queue.put(vio(OURS + "_abc_SBX", op="sysctl-read", path="kern.x"))
    obs.queue.put(vio("CMD64_c29tZXRoaW5nIGVsc2U=_END__zzz_SBX"))
    rows = obs.drain()
    check("a denial carrying a DIFFERENT session's tag is NOT recorded",
          rows == [], str(rows))
    check("...it is counted as foreign, not dropped silently",
          obs.observation.foreign == 1, str(obs.observation.foreign))
    check("...and the closing summary names it",
          "DIFFERENT sandbox session" in obs.observation.summary(),
          obs.observation.summary())

    # An untagged denial, once attribution is proven, is equally not ours.
    obs = observer_for(["cat", "/x"])
    obs.queue.put(vio(OURS + "_abc_SBX", op="sysctl-read", path="kern.x"))
    obs.queue.put(vio(""))
    check("an UNTAGGED denial is not claimed either", obs.drain() == [])

    # THE FAIL-SAFE. If this session never sees its own tag, the prefix is
    # unproven — and discarding on an unproven prefix would silently delete
    # real denials, which is worse than the bug being fixed.
    obs = observer_for(["cat", "/x"])
    obs.queue.put(vio("CMD64_c29tZXRoaW5nIGVsc2U=_END__zzz_SBX"))
    rows = obs.drain()
    check("with its own tag never seen, a denial is RECORDED, not discarded",
          len(rows) == 1, str(rows))
    check("...but explicitly marked unattributed", rows and rows[0].attributed is False)
    check("...and its reason says so in words, not by omission",
          rows and "NOT attributed to this session" in rows[0].reason(),
          rows[0].reason()[-160:] if rows else "")
    check("...and the summary says the session never saw its own tag",
          "never saw its own sandbox tag" in obs.observation.summary(),
          obs.observation.summary())

    # No command at all: the same fail-safe, and the session row says so.
    obs = violations_mod.Observer(
        {"filesystem": {"denyRead": ["/**/id_rsa"], "denyWrite": []}})
    obs.queue.put(vio(""))
    rows = obs.drain()
    check("with no command to compare, denials are recorded but unattributed",
          len(rows) == 1 and rows[0].attributed is False, str(rows))
    check("...and the session declares that regime up front",
          obs.observation.attributed_by == "none", obs.observation.attributed_by)

    # The parser pairs a violation with the tag line that follows it.
    class FakeStdout:
        def __init__(self, lines): self.lines = lines
        def __iter__(self): return iter(self.lines)

    class FakeProc:
        def __init__(self, lines): self.stdout = FakeStdout(lines)

    obs = observer_for(["cat", "/x"])
    obs.proc = FakeProc([
        "ts kernel: Sandbox: cat(11) deny(1) file-read-data /home/u/.ssh/id_rsa\n",
        OURS + "_abc_SBX\n",
        "ts kernel: Sandbox: nc(12) deny(1) file-read-data /home/u/.ssh/id_rsa\n",
        "ts something else entirely\n",
    ])
    obs._pump()
    got = []
    while not obs.queue.empty():
        got.append(obs.queue.get_nowait())
    check("the parser attaches the tag line that FOLLOWS a violation",
          len(got) == 2 and got[0].tag.startswith(violations_mod.TAG_MARKER),
          str([(g.process, g.tag[:12]) for g in got]))
    check("...and a violation with no tag line is still emitted, tagless",
          len(got) == 2 and got[1].tag == "",
          str([(g.process, g.tag) for g in got]))

    # --- the interactive case, through a real terminal --------------------
    #
    # The reported bug only exists when a human is sitting in front of a
    # program that owns the screen, and no captured-pipe test can see it: the
    # decision is made from isatty(), which a pipe answers "no" to. So this
    # runs `aegis run` on a real pty, where both stdin and stderr are
    # terminals, and asserts the lines stay off the screen while the audit row
    # is written exactly as before.

    def run_on_a_terminal(args, extra_env=None, seconds=180) -> str:
        import fcntl
        import pty as pty_mod
        import select
        import struct
        import termios as tmod

        TIOCSCTTY = 0x20007461
        master, slave = pty_mod.openpty()
        fcntl.ioctl(slave, tmod.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))

        def become_session_leader():
            os.setsid()
            fcntl.ioctl(0, TIOCSCTTY, 0)

        proc = subprocess.Popen(
            [sys.executable, "-m", "aegis.cli", "run", *args],
            stdin=slave, stdout=slave, stderr=slave,
            env={**ENV, **(extra_env or {})}, cwd=str(LAB),
            close_fds=True, preexec_fn=become_session_leader)
        os.close(slave)
        out, deadline = b"", time.time() + seconds
        while time.time() < deadline and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.5)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        os.close(master)
        return out.decode("utf-8", "replace")

    SCRIPT = f"cat {KEYFILE}; cat {ENVFILE}; cat {PLAIN}"
    tty_db = LAB / "denials-tty.db"
    tty_log = LAB / "denials-tty.log"
    try:
        screen = run_on_a_terminal(
            ["--", "bash", "-c", SCRIPT],
            {"AEGIS_AUDIT_DB": str(tty_db), "AEGIS_DENIAL_LOG": str(tty_log)})
    except OSError as exc:
        screen = None
        not_run("the interactive-terminal denial checks",
                f"no pty could be allocated here: {exc}")

    if screen is not None:
        tty_rows = list(sqlite3.connect(str(tty_db)).execute(
            "SELECT rule_id, paths FROM audit WHERE rule_id = 'sandbox_denied'"))
        # The constraint, checked FIRST: this changes display, not capture.
        check("on a terminal, the denials are still recorded in the audit log",
              len(tty_rows) >= 2, f"rows={tty_rows}")
        check("...naming the same paths as the piped run",
              any(str(KEYFILE.resolve()) in r[1] for r in tty_rows), str(tty_rows))
        # And the bug itself.
        check("...but NOT printed onto the terminal the client is drawing on",
              "kernel denied" not in screen,
              [l for l in screen.splitlines() if "kernel denied" in l][:3])
        check("...with the banner saying where they went instead",
              str(tty_log) in screen and "tail" in screen,
              screen[:400])
        check("...and the exit summary saying how many were held back",
              re.search(r"denial line\(s\) were written to", screen) is not None,
              screen[-400:])
        check("...while the startup banner and closing summary still print",
              "sandbox established" in screen
              and "kernel denial(s) recorded" in screen, screen[:200])
        check("...and the file has them",
              tty_log.exists() and tty_log.read_text().count("kernel denied") >= 2,
              tty_log.read_text()[:200] if tty_log.exists() else "missing")

        # --verbose-denials puts the old behaviour back, on the same terminal.
        loud_db = LAB / "denials-loud.db"
        loud = run_on_a_terminal(
            ["--verbose-denials", "--", "bash", "-c", SCRIPT],
            {"AEGIS_AUDIT_DB": str(loud_db),
             "AEGIS_DENIAL_LOG": str(LAB / "denials-loud.log")})
        check("--verbose-denials streams them to the terminal anyway",
              "kernel denied" in loud,
              loud[-300:])
        check("...and then does not claim it suppressed anything",
              "not printed here" not in loud, loud[:400])

        # The env var is the same switch.
        env_db = LAB / "denials-env.db"
        loud_env = run_on_a_terminal(
            ["--", "bash", "-c", SCRIPT],
            {"AEGIS_AUDIT_DB": str(env_db),
             "AEGIS_DENIAL_LOG": str(LAB / "denials-env.log"),
             "AEGIS_VERBOSE_DENIALS": "1"})
        check("AEGIS_VERBOSE_DENIALS=1 does the same as the flag",
              "kernel denied" in loud_env, loud_env[-300:])

        # And the audit rows are the same either way — the whole constraint.
        def denied_paths(db):
            return sorted(json.loads(r[0])[0] for r in sqlite3.connect(str(db)).execute(
                "SELECT paths FROM audit WHERE rule_id = 'sandbox_denied'"))
        check("quiet and verbose runs record IDENTICAL audit rows",
              denied_paths(tty_db) == denied_paths(loud_db),
              f"{denied_paths(tty_db)} vs {denied_paths(loud_db)}")

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
