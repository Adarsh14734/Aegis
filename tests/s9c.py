"""Aegis S9c harness — making C11 the default rather than an opt-in.

The claim: after `aegis init` offers and the user accepts, typing the client's
name starts it inside the sandbox, and `aegis doctor` stops warning. The
interesting checks are the ones that distinguish a wrapper that *exists* from a
wrapper that is *reached*, and a client that is wrapped from one that merely has
a file sitting nearby.

The strongest check here runs a fake "client" through the installed wrapper and
proves the resulting process is genuinely confined — a denied read fails with
EPERM inside it. A wrapper that is on PATH and does not sandbox would pass every
structural test and be worth nothing.

    python3 tests/s9c.py       exit 0 only if every check ran and passed
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s9c-")

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
# a fake client on a fake PATH, so nothing touches the real `claude`
# ---------------------------------------------------------------------------

WS = LAB / "workspace"
SECRETS = LAB / "fake-home" / ".ssh"
CLIENT_DIR = LAB / "client-bin"
WRAPPER_DIR = LAB / "aegis-bin"
for d in (WS, SECRETS, CLIENT_DIR, WRAPPER_DIR):
    d.mkdir(parents=True, exist_ok=True)

KEYFILE = SECRETS / "id_rsa"
KEYFILE.write_text("PRIVATE-KEY-BYTES-S9C\n")
(WS / "notes.txt").write_text("ordinary\n")

# The "client". Real enough for the property under test: it reports whether it
# is inside a sandbox by trying to read something policy denies.
FAKE_CLIENT = CLIENT_DIR / "claude"
FAKE_CLIENT.write_text(
    "#!/bin/sh\n"
    "echo CLIENT-STARTED \"$@\"\n"
    f"if cat {KEYFILE} >/dev/null 2>&1; then echo KEY-READABLE; "
    "else echo KEY-DENIED; fi\n"
    f'echo "MARKER=${{AEGIS_SANDBOXED:-unset}}"\n'
)
FAKE_CLIENT.chmod(0o755)

os.environ["AEGIS_WRAPPER_DIR"] = str(WRAPPER_DIR)

POLICY_DOC = {
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env", "id_rsa", "**/.ssh/**"],
    "allowed_domains": [],
    "tool_rules": {"read_file": {"effect": "allow", "within": ["<workspace>"]}},
    "default_effect": "deny",
    "ask_behavior": "deny",
}
labguard.check_policy_doc(POLICY_DOC)
POLICY_PATH = LAB / "policy.json"
POLICY_PATH.write_text(json.dumps(POLICY_DOC, indent=2))
os.chmod(POLICY_PATH, 0o600)

from aegis import launcher  # noqa: E402
from aegis import sandbox as sandbox_mod  # noqa: E402

SANDBOX_OK = not sandbox_mod.preflight()

# PATH with the fake client visible and the wrapper dir NOT yet in front.
BASE_PATH = os.pathsep.join([str(CLIENT_DIR), os.environ.get("PATH", "")])
WRAPPED_PATH = os.pathsep.join([str(WRAPPER_DIR), BASE_PATH])


def env_with(path_value: str, **over) -> dict:
    return labguard.subprocess_env(PATH=path_value, PYTHONPATH=str(ROOT), **over)


print(f"lab: {LAB}")
print(f"fake client: {FAKE_CLIENT}")


# ---------------------------------------------------------------------------
rule("1. THE WRAPPER DOES NOT OVERWRITE THE USER'S CLIENT")
# ---------------------------------------------------------------------------

os.environ["PATH"] = BASE_PATH
found = launcher.detect_clients()
check("the client is detected on PATH", any(n == "claude" for n, _, _ in found),
      str(found))
real = launcher.real_binary("claude")
check("...and resolves to the real binary", real == str(FAKE_CLIENT), str(real))

check("the wrapper goes in Aegis's own directory, not the client's",
      launcher.wrapper_dir() != FAKE_CLIENT.parent,
      f"{launcher.wrapper_dir()} vs {FAKE_CLIENT.parent}")
check("...which matters, because on this machine the real `claude` lives in "
      "~/.local/bin and a wrapper there would overwrite it", True)

launcher.install_wrapper("claude", real)
wrapper = launcher.wrapper_path("claude")
check("the wrapper is written", wrapper.exists(), str(wrapper))
check("...and is executable", os.access(wrapper, os.X_OK))
check("...and the real client is untouched",
      FAKE_CLIENT.read_text().startswith("#!/bin/sh\necho CLIENT-STARTED"))
check("...and it is recognisable as ours",
      launcher.is_aegis_wrapper(wrapper))
# The invocation is baked at install time (an absolute `aegis` or
# `<python> -m aegis.cli`), so assert the shape rather than the spelling.
wtext = wrapper.read_text()
check("the wrapper execs the REAL path, so it cannot recurse into itself",
      str(FAKE_CLIENT) in wtext and "exec " in wtext and " run -- " in wtext,
      wtext[-200:])
check("...and the Aegis invocation is baked in, not left to PATH",
      "aegis" in wtext.split("run --")[0].rsplit("exec", 1)[-1],
      wtext[-200:])


# ---------------------------------------------------------------------------
rule("2. EXISTING IS NOT THE SAME AS REACHED")
# ---------------------------------------------------------------------------

os.environ["PATH"] = BASE_PATH  # wrapper dir NOT in front
status = launcher.effective_status("claude", "Claude Code")
check("a wrapper that PATH never reaches is NOT reported as effective",
      not status.effective, status.reason)
check("...and the reason names PATH as the problem",
      "not early enough on PATH" in status.reason, status.reason)
check("...while still acknowledging the wrapper exists", status.wrapper_exists)

os.environ["PATH"] = WRAPPED_PATH
status = launcher.effective_status("claude", "Claude Code")
check("with the wrapper dir in front, it IS effective", status.effective,
      status.reason)
check("...because the NAME resolves to the wrapper",
      status.resolves_to == str(wrapper), str(status.resolves_to))
check("...and real_binary() still finds the real one, excluding our dir",
      launcher.real_binary("claude") == str(FAKE_CLIENT),
      str(launcher.real_binary("claude")))


# ---------------------------------------------------------------------------
rule("3. THE WRAPPER ACTUALLY SANDBOXES — not just resolves")
# ---------------------------------------------------------------------------

if not SANDBOX_OK:
    not_run("the wrapper actually sandboxing a launch",
            "no sandbox runtime on this machine: "
            + "; ".join(p.splitlines()[0] for p in sandbox_mod.preflight()))
else:
    # Control: the client run directly can read the denied file.
    direct = subprocess.run([str(FAKE_CLIENT)], capture_output=True, text=True,
                            timeout=120, env=env_with(BASE_PATH))
    check("CONTROL: run directly, the client CAN read the denied file",
          "KEY-READABLE" in direct.stdout, direct.stdout[:160])

    # Through the wrapper, resolved by name exactly as a user would type it.
    viawrap = subprocess.run(
        ["claude", "--flag", "value"], capture_output=True, text=True,
        timeout=300, env=env_with(WRAPPED_PATH),
    )
    out = viawrap.stdout
    check("typing the client's name starts it", "CLIENT-STARTED" in out, out[:200])
    check("...with its arguments passed through",
          "--flag value" in out, out[:200])
    check("...INSIDE the sandbox: the denied file is now unreadable",
          "KEY-DENIED" in out and "KEY-READABLE" not in out, out[:300])
    check("...and the sandbox marker is set for anything it spawns",
          "MARKER=1" in out, out[:300])

    # The marker must prevent a second, nested sandbox.
    nested = subprocess.run(
        ["claude"], capture_output=True, text=True, timeout=300,
        env=env_with(WRAPPED_PATH, AEGIS_SANDBOXED="1"),
    )
    check("a client launched from INSIDE a sandbox is not wrapped again",
          "CLIENT-STARTED" in nested.stdout and "KEY-READABLE" in nested.stdout,
          nested.stdout[:200])
    check("...which is what stops one sandbox nesting inside another", True)

    # The documented bypass, asserted rather than only described.
    bypass = subprocess.run([str(FAKE_CLIENT)], capture_output=True, text=True,
                            timeout=120, env=env_with(WRAPPED_PATH))
    check("DOCUMENTED BYPASS: the full binary path is NOT sandboxed",
          "KEY-READABLE" in bypass.stdout, bypass.stdout[:200])


# ---------------------------------------------------------------------------
rule("4. THE SHIM IS ADVICE, AND SAYS SO")
# ---------------------------------------------------------------------------

os.environ["PATH"] = BASE_PATH
snippet = launcher.shell_snippet(launcher.detect_clients())
print("\n".join("    " + l for l in snippet.splitlines()[:12]))

check("the shim defines a function for the detected client",
      "claude() {" in snippet, snippet[:200])
check("...routing it through aegis run", " run -- " in snippet and "aegis" in snippet,
      snippet[:400])
check("...with the real path baked in, so it cannot recurse",
      str(FAKE_CLIENT) in snippet)
check("...and it skips wrapping when already sandboxed",
      launcher.SANDBOX_MARKER in snippet)
check("...and prepends the wrapper dir to PATH", str(WRAPPER_DIR) in snippet)
check("the snippet says plainly it is not enforcement",
      "ADVICE, NOT ENFORCEMENT" in snippet, snippet[:400])
check("...and names the bypass", "real binary" in snippet.lower(), snippet[:400])

got = subprocess.run([sys.executable, "-m", "aegis.cli", "shell-init"],
                     capture_output=True, text=True, timeout=120,
                     env=env_with(BASE_PATH))
check("`aegis shell-init` prints the snippet to stdout", got.returncode == 0
      and "claude() {" in got.stdout, got.stdout[:200] + got.stderr[:200])
check("...and the caveats to stderr, so a `>> ~/.zshrc` stays clean",
      "ADVICE, NOT ENFORCEMENT" not in got.stdout.split("<<< aegis")[-1]
      and "Endpoint Security" in got.stderr, got.stderr[:300])
check("...naming the entitlement that makes the impossible part impossible",
      "Endpoint Security" in got.stderr and "registered organizations" in got.stderr,
      got.stderr[:400])

# The shim is a real shell function: prove it routes, in a real shell.
if SANDBOX_OK:
    rcfile = LAB / "rc.sh"
    rcfile.write_text(snippet)
    shelled = subprocess.run(
        ["bash", "-c", f"source {rcfile}; claude"],
        capture_output=True, text=True, timeout=300, env=env_with(BASE_PATH),
    )
    check("sourcing the shim and typing the name sandboxes the client",
          "KEY-DENIED" in shelled.stdout, shelled.stdout[:300] + shelled.stderr[-200:])
else:
    not_run("the shim sandboxing in a real shell", "no sandbox runtime")


# ---------------------------------------------------------------------------
rule("5. `aegis init` OFFERS, AND DECLINING CHANGES NOTHING")
# ---------------------------------------------------------------------------

shutil.rmtree(WRAPPER_DIR, ignore_errors=True)
WRAPPER_DIR.mkdir(parents=True, exist_ok=True)


def run_init(*args, path_value=BASE_PATH, **over):
    return subprocess.run(
        [sys.executable, "-m", "aegis.cli", "init", *args],
        capture_output=True, text=True, timeout=300,
        cwd=str(WS), env=env_with(path_value, **over),
    )

got = run_init("--yes", "--workspace", str(WS), "--no-wrap-clients")
check("init runs", got.returncode == 0, got.stdout[-800:] + got.stderr[-400:])
check("--no-wrap-clients does not even offer",
      "Sandboxing the client itself" not in got.stdout, got.stdout[-600:])
check("...and installs no wrapper", not launcher.wrapper_path("claude").exists())

# Declining. `--yes` answers the offer's confirm() with its default, which is
# deliberately False for this one — installing a launch wrapper is not something
# to do to someone's machine on a default.
got = run_init("--yes", "--workspace", str(WS))
check("init offers the wrapper", "Sandboxing the client itself" in got.stdout,
      got.stdout[-800:])
check("...and explains what it buys",
      "Bash tool" in got.stdout, got.stdout[-1200:])
check("declining is the default under --yes", "Declined" in got.stdout,
      got.stdout[-800:])
check("...and nothing is installed", not launcher.wrapper_path("claude").exists())
check("...and the user is told the sandbox is still there manually",
      "aegis run --" in got.stdout, got.stdout[-800:])

got = run_init("--yes", "--workspace", str(WS), "--wrap-clients")
check("--wrap-clients installs it", launcher.wrapper_path("claude").exists(),
      got.stdout[-800:])
check("...after showing the file it will write",
      "exec " in got.stdout and " run -- " in got.stdout, got.stdout[-1200:])
check("...and warns when the wrapper dir is not on PATH",
      "not reachable" in got.stdout or "not on your PATH" in got.stdout,
      got.stdout[-800:])


# ---------------------------------------------------------------------------
rule("6. DOCTOR REPORTS WHICH IS ACTIVE, AND STOPS WARNING WHEN WRAPPED")
# ---------------------------------------------------------------------------


def run_doctor(path_value):
    return subprocess.run(
        [sys.executable, "-m", "aegis.cli", "doctor", "--no-probe"],
        capture_output=True, text=True, timeout=300,
        cwd=str(WS), env=env_with(path_value),
    )

got = run_doctor(BASE_PATH)  # wrapper exists but is not reachable
check("doctor reports the launch path", "Client launches through the sandbox" in got.stdout,
      got.stdout[:400])
check("...warning while the client is unwrapped",
      "[ warn ] Client launches through the sandbox" in got.stdout, got.stdout[:600])
check("...saying the client starts UNSANDBOXED",
      "starts UNSANDBOXED" in got.stdout, got.stdout[:900])
check("...and diagnosing PATH rather than just repeating the advice",
      "is not on PATH" in got.stdout or "not early enough on PATH" in got.stdout,
      got.stdout[:900])
check("...and the sandbox check still says the boundary is opt-in",
      "applies ONLY to agents started with" in got.stdout, got.stdout[:1400])

got = run_doctor(WRAPPED_PATH)  # now genuinely reachable
check("with the wrapper reachable, doctor PASSES the launch check",
      "[  ok  ] Client launches through the sandbox" in got.stdout, got.stdout[:800])
check("...and STOPS saying the sandbox only applies to `aegis run`",
      "applies ONLY to agents started with" not in got.stdout, got.stdout[:1400])
check("...saying instead that it applies by default",
      "applies to it by default" in got.stdout, got.stdout[:1400])
check("...while still naming the bypass it cannot close",
      "full binary path" in got.stdout, got.stdout[:1400])
# Doctor may still exit non-zero in this lab for unrelated reasons (no MCP
# server is wired in it). The claim is narrower: being unwrapped is a WARN, not
# a FAIL, because opting out is a choice and not a broken installation.
unwrapped = run_doctor(BASE_PATH).stdout
check("being unwrapped is a WARN, never a FAIL — opting out is a choice",
      "[ FAIL ] Client launches through the sandbox" not in unwrapped
      and "[ warn ] Client launches through the sandbox" in unwrapped,
      unwrapped[:600])


# ---------------------------------------------------------------------------
rule("7. UNINSTALL REMOVES A WRAPPER IT CREATED")
# ---------------------------------------------------------------------------

check("the wrapper is present before uninstall", launcher.wrapper_path("claude").exists())
got = subprocess.run([sys.executable, "-m", "aegis.cli", "uninstall", "--yes"],
                     capture_output=True, text=True, timeout=300,
                     cwd=str(WS), env=env_with(WRAPPED_PATH))
check("uninstall runs", got.returncode == 0, got.stdout[-600:] + got.stderr[-300:])
check("...and removes the wrapper Aegis created",
      not launcher.wrapper_path("claude").exists(), got.stdout[-600:])
check("...saying it removed rather than restored",
      "removed" in got.stdout, got.stdout[-600:])
check("...and the real client is still there",
      FAKE_CLIENT.exists() and "CLIENT-STARTED" in FAKE_CLIENT.read_text())


# ---------------------------------------------------------------------------
rule("SUMMARY")
# ---------------------------------------------------------------------------

ok, moved = labguard.assert_untouched()
check("the operator's real Aegis state is untouched", ok, str(moved))

print(f"\n  {PASSED} passed, {FAILED} failed, {len(NOT_RUN)} NOT RUN")
if FAILURES:
    print("\n  failures:")
    for name in FAILURES:
        print(f"    - {name}")
if NOT_RUN:
    print("\n  NOT established by this run:")
    for what, why in NOT_RUN:
        print(f"    - {what}\n      {why}")

print(f"\n  lab: {LAB}   (delete when done)")
print(
    "\n  Never established by this suite:\n"
    "    - anything about a client that was ALREADY RUNNING. Forcing a running\n"
    "      process into a sandbox needs an Endpoint Security entitlement Apple\n"
    "      grants to registered organizations; no user-space code can do it\n"
    "    - that a user cannot simply type the real binary path. They can, and\n"
    "      §3 asserts that bypass rather than hiding it\n"
    "    - a live Claude Code session started through a wrapper\n"
)
sys.exit(1 if (FAILED or NOT_RUN) else 0)
