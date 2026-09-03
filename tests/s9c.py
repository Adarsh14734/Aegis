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
rule("5b. THE PATH LINE — offered, never assumed, never written twice")
# ---------------------------------------------------------------------------

# The wrappers are unreachable until the wrapper directory is early on PATH,
# and `aegis init` used to print the line and leave the edit to the user. Most
# people do not make it, and doctor then correctly reports the client as
# unsandboxed — the flow ending one manual step short of working.
#
# The offer is the fix. The SAFETY property is asserted first, because a shell
# rc is the most personal file Aegis touches and appending to one uninvited
# would be worse than the friction it removes.

FAKE_HOME = LAB / "fakehome"
FAKE_HOME.mkdir(exist_ok=True)


def init_with_home(*args, shell="/bin/zsh", home=None, **over):
    home = home or FAKE_HOME
    return subprocess.run(
        [sys.executable, "-m", "aegis.cli", "init", *args],
        capture_output=True, text=True, timeout=300, cwd=str(WS),
        env=env_with(BASE_PATH, HOME=str(home), SHELL=shell, **over),
    )


# --- the safety property ----------------------------------------------------
shutil.rmtree(WRAPPER_DIR, ignore_errors=True)
WRAPPER_DIR.mkdir(parents=True, exist_ok=True)
zshrc = FAKE_HOME / ".zshrc"
zshrc.write_text("# the user's own file\nexport EDITOR=vim\n")
before = zshrc.read_text()

got = init_with_home("--yes", "--workspace", str(WS), "--wrap-clients")
check("a bare --yes --wrap-clients does NOT touch the shell rc",
      zshrc.read_text() == before,
      "the rc was edited without --path-line:\n" + zshrc.read_text())
check("...it offers, and says which file and which line",
      str(zshrc) in got.stdout and "export PATH=" in got.stdout, got.stdout[-900:])
check("...and declining leaves the manual instruction",
      "Declined" in got.stdout and "shell-init" in got.stdout, got.stdout[-700:])

# --- the offer, accepted ----------------------------------------------------
got = init_with_home("--yes", "--workspace", str(WS), "--wrap-clients", "--path-line")
text = zshrc.read_text()
check("--path-line appends it", str(launcher.wrapper_dir()) in text, text)
check("...keeping everything that was already in the file",
      "export EDITOR=vim" in text and "# the user's own file" in text, text)
check("...under a marker naming what wrote it",
      launcher.PATH_MARKER in text, text)
check("...as an export that puts the wrapper dir FIRST",
      f'export PATH="{launcher.wrapper_dir()}:$PATH"' in text, text)
check("...after backing the file up",
      "backed up to" in got.stdout, got.stdout[-800:])
check("...and says it needs a new shell to take effect",
      "NEW shell" in got.stdout or "new shell" in got.stdout, got.stdout[-600:])
check("...and that uninstall will not remove it",
      "uninstall" in got.stdout and "NOT remove" in got.stdout, got.stdout[-800:])

# --- never twice ------------------------------------------------------------
after_first = zshrc.read_text()
got = init_with_home("--yes", "--workspace", str(WS), "--wrap-clients", "--path-line")
check("a second run does not append it again",
      zshrc.read_text() == after_first,
      f"the line was written twice:\n{zshrc.read_text()}")
check("...and says so rather than staying silent",
      "already named in" in got.stdout, got.stdout[-600:])

# A hand-written export counts too: this is checked by DIRECTORY, not by
# matching Aegis's own line, so a user who did it themselves is left alone.
hand = LAB / "handhome"
hand.mkdir(exist_ok=True)
(hand / ".zshrc").write_text(f'export PATH="{launcher.wrapper_dir()}:$PATH"  # mine\n')
check("a hand-written PATH entry is recognised, not duplicated",
      launcher.path_line_present(hand / ".zshrc"))

# --- the right file for the shell ------------------------------------------
import os as _os  # noqa: E402

_real_home = _os.environ.get("HOME")
_os.environ["HOME"] = str(FAKE_HOME)
try:
    cases = [("zsh", ".zshrc"), ("fish", "config.fish"), ("sh", ".profile")]
    for shell, expected in cases:
        _os.environ["SHELL"] = f"/bin/{shell}"
        check(f"{shell} -> {expected}",
              launcher.shell_rc().name == expected, str(launcher.shell_rc()))
    _os.environ["SHELL"] = "/bin/bash"
    check("bash -> a file bash actually reads",
          launcher.shell_rc().name in (".bashrc", ".bash_profile"),
          str(launcher.shell_rc()))
    _os.environ["SHELL"] = "/usr/local/bin/fish"
    check("fish gets fish syntax, not an export it cannot parse",
          launcher.path_line().startswith("set -gx PATH"), launcher.path_line())
    check("...putting the wrapper dir before the rest of PATH",
          launcher.path_line().endswith("$PATH"), launcher.path_line())
    _os.environ["SHELL"] = "/bin/zsh"
    check("an unknown shell falls back to ~/.profile, which every shell reads",
          (lambda: (_os.environ.__setitem__("SHELL", "/bin/weirdsh"),
                    launcher.shell_rc().name)[1])() == ".profile")
finally:
    _os.environ["SHELL"] = "/bin/zsh"
    if _real_home is not None:
        _os.environ["HOME"] = _real_home

check("the operator's OWN shell rc was never touched by any of this",
      not any(labguard.assert_untouched()[1]), str(labguard.assert_untouched()[1]))


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
rule("6b. NO MCP SERVER IS NOT A FAILURE")
# ---------------------------------------------------------------------------

# `aegis doctor` reported FAIL for "MCP configuration points at the proxy" when
# no MCP server was configured at all. That is an ordinary state — somebody who
# wants the kernel sandbox and no MCP mediation has nothing to route — and a red
# FAIL on a clean install reads as broken software, which is how people learn to
# ignore the report.
#
# The distinction that matters is between HAVING NOTHING and HAVING SOMETHING
# UNPROTECTED. The second one stays a FAIL: a configured server that does not go
# through Aegis receives tool calls that are unmediated and unrecorded.

from aegis import clients  # noqa: E402
from aegis import doctor as doctor_mod  # noqa: E402


def wiring_status(project: Path):
    report = doctor_mod.Report()
    doctor_mod._check_wiring(report, project)
    return report.checks[0]


EMPTY_PROJECT = LAB / "no-mcp-here"
EMPTY_PROJECT.mkdir(exist_ok=True)
status = wiring_status(EMPTY_PROJECT)
check("with no MCP server anywhere, the wiring check does not FAIL",
      status.status != doctor_mod.FAIL, f"{status.status}: {status.lines}")
check("...it skips, because there was nothing to check",
      status.status == doctor_mod.SKIP, status.status)
check("...saying in one sentence that the sandbox still applies",
      any("sandbox" in l and "still applies" in l for l in status.lines),
      str(status.lines))
check("...and that this is not a problem",
      any("not a problem" in l for l in status.lines), str(status.lines))
check("...while still naming where it looked",
      any("Looked in" in l for l in status.lines), str(status.lines))

# A config file that exists but names no servers is the same state.
EMPTY_CONFIG = LAB / "empty-mcp"
EMPTY_CONFIG.mkdir(exist_ok=True)
(EMPTY_CONFIG / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))
status = wiring_status(EMPTY_CONFIG)
check("a config file with no servers in it is also 'nothing to route'",
      status.status == doctor_mod.SKIP, f"{status.status}: {status.lines}")

# And the case that must stay red.
LOOSE = LAB / "unwrapped-mcp"
LOOSE.mkdir(exist_ok=True)
(LOOSE / ".mcp.json").write_text(json.dumps({
    "mcpServers": {"files": {"command": "npx", "args": ["-y", "@mcp/files"]}}}))
status = wiring_status(LOOSE)
check("a server that exists but is NOT routed through Aegis is still a FAIL",
      status.status == doctor_mod.FAIL, f"{status.status}: {status.lines}")
check("...saying its tool calls are unmediated and unrecorded",
      any("unmediated and unrecorded" in l for l in status.lines), str(status.lines))

# The PROOF check follows the same distinction.
def proof_status(configured):
    report = doctor_mod.Report()
    doctor_mod._check_live(report, None, LAB / "x.db", [], LAB, 5.0,
                           configured=configured)
    return report.checks[0]


status = proof_status(0)
check("PROOF skips when there is no server to send a probe through",
      status.status == doctor_mod.SKIP, f"{status.status}: {status.lines}")
check("...and says so without implying the sandbox is unproven",
      any("does not depend on MCP" in l for l in status.lines), str(status.lines))
status = proof_status(1)
check("PROOF still FAILS when a server exists and is not wrapped",
      status.status == doctor_mod.FAIL, f"{status.status}: {status.lines}")

# End to end, through the real command, on a project with no MCP config.
got = subprocess.run(
    [sys.executable, "-m", "aegis.cli", "doctor", "--no-probe"],
    capture_output=True, text=True, timeout=300, cwd=str(EMPTY_PROJECT),
    env=env_with(BASE_PATH))
wiring_lines = [l for l in got.stdout.splitlines()
                if "MCP configuration points at the proxy" in l]
check("`aegis doctor` on a project with no MCP config does not print FAIL for it",
      wiring_lines and "FAIL" not in wiring_lines[0], str(wiring_lines))
check("...and does not count it among the failures at the end",
      "MCP configuration points at the proxy" not in
      got.stdout.split("check(s) FAILED")[-1] if "check(s) FAILED" in got.stdout
      else True, got.stdout[-500:])


# ---------------------------------------------------------------------------
rule("6c. ROUTED IS NOT THE SAME AS CONNECTED")
# ---------------------------------------------------------------------------

# Found by the first end-to-end verification of the MCP layer on a real
# install. Every check was green — configuration points at the proxy, no client
# is running the old wiring, PROOF passes — while `claude mcp list` said the
# server was "Pending approval" and the client had never connected to it.
# Nothing was mediated at all.
#
# Both green checks were green for the wrong reason. PROOF launches the server
# ITSELF, so it proves the proxy works, not that the client uses it. And the
# stale-wiring check looks for the UNWRAPPED command, so a server nobody
# launched passes it vacuously.

WRAPPED_ENTRY = clients.wrap_entry(
    {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem",
                                str(WS)]})
ROUTED = clients.Detected(
    client="Claude Code (project)", path=LAB / "proof" / ".mcp.json",
    container=("mcpServers",), servers={"filesystem": WRAPPED_ENTRY})

PROXY_CMD = (f"/usr/bin/python3 -m aegis.proxy -- npx -y "
             f"@modelcontextprotocol/server-filesystem {WS}")
CLIENT_CMD = "/Applications/Claude.app/Contents/MacOS/Claude"
APPLE_CMD = ("/System/Library/PrivateFrameworks/UIFoundation.framework/Versions/"
             "A/XPCServices/CursorUIViewService.xpc/Contents/MacOS/CursorUIViewService")


def live_status(table):
    real = doctor_mod._process_table
    doctor_mod._process_table = lambda: table
    try:
        report = doctor_mod.Report()
        doctor_mod._check_server_live(report, [ROUTED])
        return report.checks[0]
    finally:
        doctor_mod._process_table = real


# --- the reported state: routed, a client running, server never launched ----
status = live_status([(900, 1, CLIENT_CMD), (901, 900, "/bin/zsh")])
check("a routed server that nothing has launched is not reported as fine",
      status.status != doctor_mod.PASS, f"{status.status}: {status.lines}")
check("...it warns", status.status == doctor_mod.WARN, status.status)
check("...naming the client that IS running",
      any("Claude IS running" in l for l in status.lines), str(status.lines))
check("...and the approval case, which is what actually happened",
      any("Pending approval" in l for l in status.lines), str(status.lines))
check("...and the restart case",
      any("has not been restarted" in l for l in status.lines), str(status.lines))
check("...and says PROOF alone does not cover this",
      any("not that anything is running it" in l for l in status.lines),
      str(status.lines))
check("...while allowing that a different project open is innocent",
      any("different project open" in l for l in status.lines), str(status.lines))

# --- the state that is actually proven --------------------------------------
status = live_status([(900, 1, CLIENT_CMD), (950, 900, PROXY_CMD)])
check("a server running behind the proxy is a PASS",
      status.status == doctor_mod.PASS, f"{status.status}: {status.lines}")
check("...naming the pid, so the claim is checkable",
      any("pid 950" in l for l in status.lines), str(status.lines))

# The downstream child counts too: the proxy execs the real server, and it is
# the child that carries the server's own command line.
CHILD_CMD = (f"node /Users/x/.npm/_npx/abc/node_modules/"
             f"@modelcontextprotocol/server-filesystem/dist/index.js {WS}")
status = live_status([(900, 1, CLIENT_CMD), (950, 900, PROXY_CMD),
                      (951, 950, CHILD_CMD)])
check("...and a server process BEHIND a proxy counts, not just the proxy itself",
      status.status == doctor_mod.PASS, f"{status.status}: {status.lines}")

# --- no client running at all is not a finding ------------------------------
status = live_status([(700, 1, "/usr/sbin/cfprefsd"), (701, 1, "/bin/zsh")])
check("with no client running, this is a SKIP, not a warning",
      status.status == doctor_mod.SKIP, f"{status.status}: {status.lines}")
check("...saying there is nothing that could have connected",
      any("could have connected" in l for l in status.lines), str(status.lines))

# --- nothing routed here ----------------------------------------------------
UNROUTED = clients.Detected(
    client="Claude Code (project)", path=LAB / "proof" / ".mcp.json",
    container=("mcpServers",),
    servers={"filesystem": {"command": "npx", "args": ["-y", "server"]}})
report = doctor_mod.Report()
doctor_mod._check_server_live(report, [UNROUTED])
check("a server that is not routed through Aegis is not this check's business",
      report.checks[0].status == doctor_mod.SKIP, report.checks[0].status)

# --- and the process table may be unreadable --------------------------------
status = live_status(None)
check("an unreadable process table warns rather than claiming either way",
      status.status == doctor_mod.WARN
      and any("could not read" in l for l in status.lines), str(status.lines))

# --- client detection is strict ---------------------------------------------
#
# The first version of this check used CLIENT_HINTS, a substring match, against
# the whole process table — and reported macOS's own CursorUIViewService as the
# user's MCP client. Measured on this machine.
check("an Apple XPC service is NOT mistaken for the user's editor",
      doctor_mod._running_client([(1, 0, APPLE_CMD)], set()) == "",
      doctor_mod._running_client([(1, 0, APPLE_CMD)], set()))
for shape, cmd in (
    ("a macOS app bundle", CLIENT_CMD),
    ("a binary on PATH", "/Users/x/.local/bin/claude"),
    ("the CLI's VERSION-numbered binary", "/Users/x/.local/share/claude/versions/2.1.258"),
):
    check(f"...but a real client is found as {shape}",
          doctor_mod._running_client([(1, 0, cmd)], set()) != "", cmd)
check("...and doctor's own processes are never counted as a client",
      doctor_mod._running_client([(1, 0, CLIENT_CMD)], {1}) == "")


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
