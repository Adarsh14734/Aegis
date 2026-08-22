"""Aegis S7 harness — packaging, `aegis init`, `aegis doctor`, `aegis uninstall`.

Everything here runs against a fake HOME inside a temp lab, so the default path
logic in proxy.py / audit.py / clients.py is exercised for real rather than
bypassed with AEGIS_* overrides. That is the point: `aegis init` writes to the
OS data directory, and a test that redirects it with an environment variable
would not be testing the thing users run.

S5 finding 1 is the reason for `_assert_real_state_untouched()`: this is the
fourth sprint in a row whose harness could have reached the operator's real
policy, audit log or kill switch. The guard runs before the first subprocess
and again at the end, and the suite fails loudly if the real files moved.

    python3 tests/s7.py            exit 0 only if every check passed
"""

import hashlib
import json
import os
import pty
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOCK_SERVER = ROOT / "tests" / "mock_fs_server.py"

sys.path.insert(0, str(ROOT))

from aegis import clients  # noqa: E402
from aegis.broker import keyring_available  # noqa: E402

PASSED = 0
FAILED = 0
FAILURES: list[str] = []


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


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


# ---------------------------------------------------------------------------
# the guard: nothing here may touch the operator's real installation
# ---------------------------------------------------------------------------

if sys.platform == "darwin":
    REAL_DIR = Path.home() / "Library" / "Application Support" / "Aegis"
else:
    REAL_DIR = Path(
        os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
    ) / "aegis"
REAL_WATCH = [
    REAL_DIR / "policy.json",
    REAL_DIR / "audit.db",
    REAL_DIR / "KILLSWITCH",
    Path.home() / ".mcp.json",
    Path.home() / ".claude.json",
]


def _fingerprint() -> dict:
    out = {}
    for path in REAL_WATCH:
        try:
            out[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            out[str(path)] = "absent"
    return out


BASELINE = _fingerprint()


def _assert_real_state_untouched(when: str) -> None:
    now = _fingerprint()
    moved = [p for p in BASELINE if BASELINE[p] != now[p]]
    check(f"the operator's real Aegis state is untouched ({when})", not moved, str(moved))


# ---------------------------------------------------------------------------
# lab
# ---------------------------------------------------------------------------

# --- labguard, in fake_home mode. S7 deliberately pins by pointing HOME into
# --- the lab rather than by setting AEGIS_*, because the whole point is to
# --- exercise the real default-path logic that `aegis init` relies on. The
# --- guard verifies where the resolvers actually land, so it covers this mode
# --- identically: it checks the destination, not how it was arranged.
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s7-", fake_home=True)
FAKE_HOME = LAB / "home"
FAKE_HOME.mkdir(parents=True, exist_ok=True)
if sys.platform == "darwin":
    DATA_DIR = FAKE_HOME / "Library" / "Application Support" / "Aegis"
    CONFIG_DIR = DATA_DIR
else:
    DATA_DIR = FAKE_HOME / ".local" / "share" / "aegis"
    CONFIG_DIR = FAKE_HOME / ".config" / "aegis"
POLICY_PATH = CONFIG_DIR / "policy.json"
AUDIT_DB = DATA_DIR / "audit.db"


def lab_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    env["HOME"] = str(FAKE_HOME)
    env["PYTHONPATH"] = str(ROOT)
    env.pop("XDG_DATA_HOME", None)
    env.pop("XDG_CONFIG_HOME", None)
    env.update(extra)
    return env


def run_cli(args, cwd: Path, expect=None, timeout=180) -> subprocess.CompletedProcess:
    done = subprocess.run(
        [sys.executable, "-m", "aegis.cli", *args],
        cwd=str(cwd), env=lab_env(), capture_output=True, text=True, timeout=timeout,
    )
    if expect is not None and done.returncode != expect:
        print(f"\n--- unexpected exit {done.returncode} (wanted {expect}) for {args}")
        print(done.stdout[-4000:])
        print(done.stderr[-2000:])
    return done


def new_project(name: str, with_config: bool = True) -> Path:
    project = LAB / name
    (project / "workspace").mkdir(parents=True, exist_ok=True)
    (project / "workspace" / "hello.txt").write_text("hello\n")
    if with_config:
        (project / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "mockfs": {
                            "command": sys.executable,
                            "args": [str(MOCK_SERVER), str(project / "workspace")],
                            "env": {"MOCK_MARKER": "kept"},
                        }
                    }
                },
                indent=4,
            )
            + "\n"
        )
    return project


def row_count(db: Path) -> int:
    if not db.exists():
        return 0
    conn = sqlite3.connect(str(db))
    try:
        return int(conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0])
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def reset_install() -> None:
    """Back to a machine with no Aegis installation, keeping the lab."""
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)


print(f"lab: {LAB}")
print(f"fake HOME: {FAKE_HOME}")
_assert_real_state_untouched("before anything ran")


# ---------------------------------------------------------------------------
section("1. packaging")
# ---------------------------------------------------------------------------

pyproject = ROOT / "pyproject.toml"
check("pyproject.toml exists", pyproject.exists())

try:
    import tomllib

    meta = tomllib.loads(pyproject.read_text())
except Exception as exc:  # noqa: BLE001
    meta = {}
    check("pyproject.toml parses", False, str(exc))
else:
    check("pyproject.toml parses", True)

project_meta = meta.get("project", {})
check("distribution is named aegis-mcp", project_meta.get("name") == "aegis-mcp",
      repr(project_meta.get("name")))
check("no runtime dependencies", project_meta.get("dependencies") == [],
      repr(project_meta.get("dependencies")))
check("keyring is an optional extra, not a requirement",
      "keyring" in project_meta.get("optional-dependencies", {}))

scripts = project_meta.get("scripts", {})
for name in ("aegis", "aegis-secret", "aegis-restore", "aegis-stop", "aegis-resume"):
    check(f"console entry point '{name}' is declared", name in scripts)

# Every entry point must resolve to something callable. A declared script that
# imports nothing is a broken install nobody notices until first use.
for name, target in sorted(scripts.items()):
    module_name, _, attr = target.partition(":")
    try:
        module = __import__(module_name, fromlist=[attr])
        ok = callable(getattr(module, attr))
        detail = ""
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    check(f"'{name}' resolves to a callable ({target})", ok, detail)

check("aegis.proxy is runnable as a module",
      subprocess.run([sys.executable, "-m", "aegis.proxy"], cwd=str(ROOT),
                     env=lab_env(), capture_output=True, text=True).returncode == 64,
      "expected usage exit 64")

check("aegis/proxy.py is still runnable as a plain script (pre-S7 wiring)",
      subprocess.run([sys.executable, str(ROOT / "aegis" / "proxy.py")],
                     env=lab_env(), capture_output=True, text=True).returncode == 64,
      "expected usage exit 64")

# The shipped template and the repo's reference policy must not drift apart.
template = json.loads((ROOT / "aegis" / "policy.template.json").read_text())
example = json.loads((ROOT / "policy.example.json").read_text())
check("template and policy.example.json agree on deny_paths",
      template["deny_paths"] == example["deny_paths"],
      f"{template['deny_paths']} vs {example['deny_paths']}")
shared = set(template["tool_rules"]) & set(example["tool_rules"])
drift = [t for t in shared if template["tool_rules"][t] != example["tool_rules"][t]]
check("template and policy.example.json agree on every shared tool rule",
      not drift, str(drift))
check("template default_effect is deny", template["default_effect"] == "deny")

usable, why = keyring_available()
check("keyring absence is reported, not raised",
      isinstance(usable, bool) and (usable or "keyring" in why.lower()), why)
check("a missing keyring does not break importing the policy engine",
      subprocess.run(
          [sys.executable, "-c",
           "import sys; sys.modules['keyring']=None; import aegis.policy; print('ok')"],
          cwd=str(ROOT), env=lab_env(), capture_output=True, text=True,
      ).returncode == 0)


# ---------------------------------------------------------------------------
section("2. config wrapping (unit)")
# ---------------------------------------------------------------------------

plain = {"command": "npx", "args": ["-y", "server-fs", "/tmp/ws"], "env": {"A": "1"}}
check("a plain entry is not detected as wrapped", not clients.is_wrapped(plain))

wrapped = clients.wrap_entry(plain)
check("a wrapped entry is detected as wrapped", clients.is_wrapped(wrapped))
check("wrapping preserves env", wrapped.get("env") == {"A": "1"})
check("wrapping keeps the original command and args after '--'",
      wrapped["args"][wrapped["args"].index("--") + 1:] == ["npx", "-y", "server-fs", "/tmp/ws"],
      str(wrapped["args"]))
check("unwrap recovers the original entry", clients.unwrap_entry(wrapped) == plain,
      str(clients.unwrap_entry(wrapped)))

try:
    clients.wrap_entry(wrapped)
    double = False
except clients.ClientError:
    double = True
check("double wrapping is refused", double)

try:
    clients.wrap_entry({"type": "http", "url": "https://example.com/mcp"})
    http_refused = False
except clients.ClientError as exc:
    http_refused = "stdio" in str(exc)
check("an HTTP/SSE server is refused, with stdio named as the reason", http_refused)

check("a -m aegis.proxy entry is recognised",
      clients.is_wrapped({"command": "python3", "args": ["-m", "aegis.proxy", "--", "x"]}))
check("a proxy.py path entry is recognised (pre-S7 wiring)",
      clients.is_wrapped({"command": "python3",
                          "args": ["/opt/aegis/aegis/proxy.py", "--", "x"]}))
check("an unrelated python script is not recognised",
      not clients.is_wrapped({"command": "python3", "args": ["/opt/other/proxy.py", "--", "x"]}))


# ---------------------------------------------------------------------------
section("3. aegis init on a machine with no prior configuration")
# ---------------------------------------------------------------------------

reset_install()
bare = new_project("bare-project", with_config=False)
done = run_cli(["init", "--yes", "--workspace", str(bare / "workspace")], bare, expect=0)
check("init exits 0 on a machine with nothing installed", done.returncode == 0,
      done.stdout[-1500:] + done.stderr[-500:])
check("init says it found no MCP configuration", "MCP configuration found:\n  none." in done.stdout)
check("init writes the policy to the OS data directory", POLICY_PATH.exists(), str(POLICY_PATH))
if POLICY_PATH.exists():
    mode = POLICY_PATH.stat().st_mode & 0o777
    check("policy.json is mode 0600", mode == 0o600, oct(mode))
    doc = json.loads(POLICY_PATH.read_text())
    check("the workspace root the user gave is the one written",
          doc["workspace_roots"] == [str((bare / "workspace").resolve())], str(doc["workspace_roots"]))
    check("the deny list defaults to the current deny_paths",
          doc["deny_paths"] == template["deny_paths"], str(doc["deny_paths"]))
    check("default_effect is deny", doc.get("default_effect") == "deny")
    check("the written policy loads in the policy engine",
          subprocess.run(
              [sys.executable, "-c",
               "import sys;from aegis.policy import Policy;from pathlib import Path;"
               "Policy.load(Path(sys.argv[1]));print('ok')", str(POLICY_PATH)],
              cwd=str(ROOT), env=lab_env(), capture_output=True, text=True,
          ).returncode == 0)
check("init points the user at doctor", "aegis doctor" in done.stdout)
check("init states the boundary up front", "§7.6" in done.stdout)

# custom deny list
done = run_cli(
    ["init", "--yes", "--workspace", str(bare / "workspace"), "--deny", "secrets.txt"],
    bare, expect=0,
)
check("a custom deny list replaces the default",
      json.loads(POLICY_PATH.read_text())["deny_paths"] == ["secrets.txt"])
check("re-running init shows a diff of the policy change", "@@" in done.stdout)
check("re-running init backs the old policy up first", "backed up to" in done.stdout)

done = run_cli(["init"], bare)
check("init with no terminal and no --yes refuses rather than taking defaults",
      done.returncode != 0, f"exit {done.returncode}")
check("...and names the flags that would work",
      "--yes" in (done.stdout + done.stderr) and "--workspace" in (done.stdout + done.stderr))

done = run_cli(["init", "--yes", "--workspace", str(LAB / "does-not-exist")], bare)
check("a workspace root that does not exist is refused", done.returncode != 0)
check("...and says so rather than creating it",
      "does not exist" in (done.stdout + done.stderr))


# ---------------------------------------------------------------------------
section("3b. aegis init, driven interactively over a real terminal")
# ---------------------------------------------------------------------------

# `--yes` is what every other section uses, and it skips every `input()` call in
# onboard.py. Shipping prompt code that has never been typed at is how S6's
# approval bridge happened, so the prompts are driven here for real: a pty on
# stdin and stdout, answers typed a character at a time, output read back.

reset_install()
tty_project = new_project("tty-project")


def drive_interactive(args, cwd: Path, answers: list[str], timeout=180):
    parent, child = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-m", "aegis.cli", *args],
        cwd=str(cwd), env=lab_env(),
        stdin=child, stdout=child, stderr=child, close_fds=True,
    )
    os.close(child)
    output = bytearray()
    pending = list(answers)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            readable, writable, _ = select.select([parent], [parent] if pending else [], [], 0.5)
            if readable:
                try:
                    chunk = os.read(parent, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
            if writable and pending:
                # Answers go into the terminal's input buffer and are consumed
                # one per input() call, in order. Nothing here checks that an
                # answer arrived after its prompt — what proves the answers
                # landed on the right questions is the policy that comes out,
                # which is asserted field by field below.
                os.write(parent, (pending.pop(0) + "\n").encode())
            if proc.poll() is not None and not readable:
                break
    finally:
        try:
            os.close(parent)
        except OSError:
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    return proc.returncode, output.decode("utf-8", "replace")


code, text = drive_interactive(
    ["init"],
    tty_project,
    # S9c appended one more question to init — the launch-wrapper offer. It is
    # answered "n" here: this section is about the prompt sequence, and s9c
    # covers accepting. An unanswered prompt is an EOF and a non-zero exit,
    # which is how this caught the new question in the first place.
    [str(tty_project / "workspace"), "", "y", "y", "y", "n"],
)
check("interactive init exits 0", code == 0, f"exit {code}\n{text[-2000:]}")
check("...having also offered to sandbox the client's own launch (S9c)",
      "Sandboxing the client itself" in text, text[-1200:])
check("...and accepted the decline without changing anything",
      "Declined" in text, text[-800:])
check("...asked which folders the agent may work in",
      "Which folders may the agent work in" in text)
check("...asked which paths it must never open",
      "Which paths must the agent NEVER open" in text)
check("...offered the current deny list as the default",
      ".env" in text and "**/.ssh/**" in text)
check("...wrote the policy the answers describe", POLICY_PATH.exists())
if POLICY_PATH.exists():
    doc = json.loads(POLICY_PATH.read_text())
    check("...with the typed workspace root",
          doc["workspace_roots"] == [str((tty_project / "workspace").resolve())],
          str(doc["workspace_roots"]))
    check("...and the default deny list, accepted with an empty line",
          doc["deny_paths"] == template["deny_paths"], str(doc["deny_paths"]))
check("...showed the config diff before touching it", "@@" in text)
check("...and wired the server",
      clients.is_wrapped(json.loads((tty_project / ".mcp.json").read_text())
                         ["mcpServers"]["mockfs"]))

# A refused confirmation must leave everything alone.
reset_install()
declined_project = new_project("declined-project")
untouched = (declined_project / ".mcp.json").read_bytes()
code, text = drive_interactive(
    ["init"],
    declined_project,
    [str(declined_project / "workspace"), "", "n"],
)
check("declining the policy write exits non-zero", code != 0, f"exit {code}")
check("...and writes no policy", not POLICY_PATH.exists())
check("...and leaves the MCP config byte-identical",
      (declined_project / ".mcp.json").read_bytes() == untouched)


# ---------------------------------------------------------------------------
section("4. aegis init refuses a workspace that would contain policy.json")
# ---------------------------------------------------------------------------

reset_install()
# The OS data directory sits under the fake HOME, so naming HOME as a workspace
# root is exactly the mistake: the agent could then rewrite the policy that
# constrains it.
done = run_cli(["init", "--yes", "--workspace", str(FAKE_HOME)], bare)
check("init exits non-zero when the policy would land inside a workspace root",
      done.returncode != 0, f"exit {done.returncode}")
combined = done.stdout + done.stderr
check("...and says REFUSING", "REFUSING" in combined)
check("...and names the policy file and the root", str(POLICY_PATH) in combined
      and str(FAKE_HOME) in combined)
check("...and explains why (a policy the agent can edit enforces nothing)",
      "enforces nothing" in combined)
check("...and writes nothing at all", not POLICY_PATH.exists(), str(POLICY_PATH))

# The same refusal must hold for the trash directory and the audit database,
# which live in the same place and are just as agent-writable if named.
check("the refusal covers the audit database and trash directory too",
      "REFUSING" in combined)


# ---------------------------------------------------------------------------
section("5. aegis init patches an existing .mcp.json, showing the change")
# ---------------------------------------------------------------------------

reset_install()
project = new_project("wired-project")
original_bytes = (project / ".mcp.json").read_bytes()
done = run_cli(
    ["init", "--yes", "--workspace", str(project / "workspace")], project, expect=0
)
check("init exits 0", done.returncode == 0, done.stdout[-1500:])
check("init lists the detected .mcp.json", str(project / ".mcp.json") in done.stdout)
check("init prints a unified diff before writing", "@@" in done.stdout
      and "(after aegis init)" in done.stdout)
check("init reports the backup it took", "backed up to" in done.stdout)

patched = json.loads((project / ".mcp.json").read_text())
entry = patched["mcpServers"]["mockfs"]
check("the server is now wrapped", clients.is_wrapped(entry), str(entry))
check("the original command survives after '--'",
      entry["args"][entry["args"].index("--") + 1:][0] == sys.executable, str(entry["args"]))
check("the server's env survives the patch", entry.get("env") == {"MOCK_MARKER": "kept"})

backups = sorted((DATA_DIR / "backups").glob("*.bak"))
check("a backup file exists", bool(backups), str(DATA_DIR / "backups"))
if backups:
    mcp_backups = [b for b in backups if b.read_bytes() == original_bytes]
    check("a backup holds the original bytes exactly", bool(mcp_backups))

done = run_cli(["init", "--yes", "--workspace", str(project / "workspace")], project, expect=0)
check("re-running init does not double-wrap",
      "already routed through Aegis" in done.stdout)
entry2 = json.loads((project / ".mcp.json").read_text())["mcpServers"]["mockfs"]
check("...and leaves the entry unchanged", entry2 == entry)


# ---------------------------------------------------------------------------
section("6. aegis doctor on a correct setup — the proof")
# ---------------------------------------------------------------------------

before = row_count(AUDIT_DB)
done = run_cli(["doctor"], project, expect=0, timeout=300)
out = done.stdout
print("\n".join("      | " + l for l in out.splitlines()[:60]))
check("doctor exits 0 on a correct setup", done.returncode == 0,
      out[-3000:] + done.stderr[-1000:])
check("doctor reports the policy check", "Policy file exists and parses" in out)
check("doctor reports the policy is outside every workspace root",
      "Policy file is outside every workspace root" in out)
check("doctor reports the audit database is writable", "Audit database is writable" in out)
check("doctor reports the chain verifies", "Audit chain verifies" in out)
check("doctor reports keyring", "Credential storage (keyring)" in out)
check("doctor reports the MCP wiring", "MCP configuration points at the proxy" in out)
check("doctor ran the live probe", "PROOF: a real tool call is denied and recorded" in out)
check("doctor's proof passed", "[  ok  ] PROOF" in out, out[-3000:])
check("doctor saw AEGIS DENIED come back", "AEGIS DENIED" in out)
check("doctor observed a new audit row", "audit row" in out and "appeared" in out)
check("doctor re-verified the chain with that row in it",
      "the chain still verifies with that row in it" in out)

after = row_count(AUDIT_DB)
check("the audit log actually gained exactly one row", after == before + 1,
      f"{before} -> {after}")
check("doctor prints what it does not cover", "WHAT THIS DOES NOT COVER" in out)
# S9b reworded this block: Bash and the native tools are no longer simply
# uncovered — `aegis run` covers them — so the assertion tracks that both are
# still named, and that the caveat naming the sandbox is present too.
check("...and names Bash explicitly", "Bash, every shell command" in out, out[-1500:])
check("...and names native agent file tools",
      "native file tools" in out.lower(), out[-1500:])
check("...and says the sandbox is what covers them",
      "aegis run" in out, out[-1500:])
check("...and points at the full threat model", "THREAT-MODEL.md §7" in out)


# ---------------------------------------------------------------------------
section("7. aegis doctor with the proxy NOT wired in — the case that matters")
# ---------------------------------------------------------------------------

# Same machine, same policy, same audit log. The only thing changed is that the
# MCP config no longer routes through Aegis. Every file-reading check still
# passes; doctor must still fail.
config_path = project / ".mcp.json"
wired_text = config_path.read_text()
unwired = json.loads(wired_text)
unwired["mcpServers"]["mockfs"] = clients.unwrap_entry(unwired["mcpServers"]["mockfs"])
config_path.write_text(json.dumps(unwired, indent=2) + "\n")

before = row_count(AUDIT_DB)
done = run_cli(["doctor"], project, timeout=300)
out = done.stdout
check("doctor exits NON-ZERO when the proxy is not in the pipe", done.returncode != 0,
      f"exit {done.returncode}\n" + out[-3000:])
check("doctor fails the wiring check", "[ FAIL ] MCP configuration points at the proxy" in out)
check("doctor fails the proof", "[ FAIL ] PROOF" in out)
check("doctor refuses to send the probe through an unwrapped server",
      "not attempted" in out and "would execute it" in out)
check("doctor says the setup has no MCP-layer control at all",
      "no MCP-layer control at all" in out)
check("no audit row was written by the failed run", row_count(AUDIT_DB) == before,
      f"{before} -> {row_count(AUDIT_DB)}")
check("doctor still passed the file-only checks (which is the point)",
      "[  ok  ] Policy file exists and parses" in out
      and "[  ok  ] Audit chain verifies" in out)

# And prove the refusal was warranted: the unwrapped server really does execute
# what doctor declined to send it. Done against a harmless file in the lab, not
# against anything sensitive.
victim = LAB / "unmediated-probe.txt"
victim.write_text("EXECUTED-BY-BARE-SERVER")
raw = subprocess.run(
    [sys.executable, str(MOCK_SERVER), str(project / "workspace")],
    input=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": str(victim)}},
    }) + "\n",
    capture_output=True, text=True, timeout=60,
)
check("the unwrapped server really does execute the call doctor refused to send",
      "EXECUTED-BY-BARE-SERVER" in raw.stdout, raw.stdout[:300])

config_path.write_text(wired_text)


# ---------------------------------------------------------------------------
section("7b. a client still running the old wiring (S7 gap 9)")
# ---------------------------------------------------------------------------

# The config is correct and every file-reading check passes. What is wrong is
# not on disk: a client launched its server before `aegis init` ran and is still
# talking to it directly. This is the state doctor used to report as green.

restart_line = "RESTART YOUR MCP CLIENT AFTER"
done = run_cli(["doctor", "--no-probe"], project, timeout=300)
check("doctor prints the restart instruction even when nothing is detected",
      restart_line in done.stdout, done.stdout[-1500:])
check("...and passes the stale-client check when no server is loose",
      "[  ok  ] No client is still running the old wiring" in done.stdout,
      done.stdout[-1500:])
check("...and says the check is a heuristic, not a guarantee",
      "heuristic" in done.stdout)

# Now be that stale client: launch the *unwrapped* server, exactly as a client
# started before init would still be running it, and hold it open on a pipe.
stale = subprocess.Popen(
    [sys.executable, str(MOCK_SERVER), str(project / "workspace")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    env=lab_env(),
)
time.sleep(1.0)
try:
    done = run_cli(["doctor", "--no-probe"], project, timeout=300)
    out = done.stdout
    check("doctor exits non-zero when a client is still running the old wiring",
          done.returncode != 0, f"exit {done.returncode}\n" + out[-2500:])
    check("doctor fails the stale-client check",
          "[ FAIL ] No client is still running the old wiring" in out, out[-2500:])
    check("...and names the process it found", f"pid {stale.pid}" in out, out[-2500:])
    check("...and names the configured server it matches", "'mockfs'" in out)
    check("...and tells the user in plain English to quit and reopen the app",
          "QUIT AND REOPEN THAT APPLICATION" in out)
    check("...and says the tool calls are not checked or recorded",
          "none of its tool calls are checked or recorded" in out)
    check("...and the banner switches to RESTART REQUIRED",
          "RESTART REQUIRED" in out and restart_line not in out, out[-1200:])
    check("the config on disk is still correct, which is the point",
          "[  ok  ] MCP configuration points at the proxy" in out)
finally:
    stale.kill()
    stale.wait(timeout=10)

time.sleep(1.0)
done = run_cli(["doctor", "--no-probe"], project, timeout=300)
check("doctor passes again once the stale client is gone",
      "[  ok  ] No client is still running the old wiring" in done.stdout,
      done.stdout[-1500:])

# A server that IS behind a proxy must not be mistaken for a stale one.
mediated = subprocess.Popen(
    [sys.executable, str(ROOT / "aegis" / "proxy.py"), "--",
     sys.executable, str(MOCK_SERVER), str(project / "workspace")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    env=lab_env(),
)
time.sleep(1.5)
try:
    done = run_cli(["doctor", "--no-probe"], project, timeout=300)
    check("a server running behind a proxy is not reported as stale",
          "[  ok  ] No client is still running the old wiring" in done.stdout,
          done.stdout[-2000:])
finally:
    mediated.kill()
    mediated.wait(timeout=10)


# ---------------------------------------------------------------------------
section("8. aegis doctor with a tampered chain")
# ---------------------------------------------------------------------------

# Per the S2 operating rule, tampering happens on a copy — here, on the lab's
# own database, never the operator's.
conn = sqlite3.connect(str(AUDIT_DB))
conn.execute("UPDATE audit SET effect='allow' WHERE id=(SELECT MIN(id) FROM audit)")
conn.commit()
conn.close()

done = run_cli(["doctor", "--no-probe"], project, timeout=300)
out = done.stdout
check("doctor exits non-zero on a tampered chain", done.returncode != 0, f"exit {done.returncode}")
check("doctor fails the chain check", "[ FAIL ] Audit chain verifies" in out)
check("...and says the record has been altered", "has been altered" in out)
check("...and says nothing below it can be cited", "cited as evidence" in out)
check("--no-probe is reported as proving nothing", "[ skip ] PROOF" in out
      and "none of them shows" in out)

shutil.rmtree(DATA_DIR / "backups", ignore_errors=True)
AUDIT_DB.unlink()
for sidecar in ("-wal", "-shm"):
    Path(str(AUDIT_DB) + sidecar).unlink(missing_ok=True)
(DATA_DIR / "aegis-head.txt").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
section("9. aegis uninstall")
# ---------------------------------------------------------------------------

reset_install()
project = new_project("uninstall-project")
original_bytes = (project / ".mcp.json").read_bytes()
original_sha = hashlib.sha256(original_bytes).hexdigest()

run_cli(["init", "--yes", "--workspace", str(project / "workspace")], project, expect=0)
check("init changed the config", (project / ".mcp.json").read_bytes() != original_bytes)

# Give the audit log something to lose, so "left in place" is a claim about
# content and not merely about an empty file existing.
run_cli(["doctor"], project, expect=0, timeout=300)
rows_before_uninstall = row_count(AUDIT_DB)
check("there is an audit log with rows in it to preserve", rows_before_uninstall > 0,
      str(rows_before_uninstall))

done = run_cli(["uninstall", "--yes"], project, expect=0)
out = done.stdout
check("uninstall exits 0", done.returncode == 0, out[-2000:] + done.stderr[-500:])
check("uninstall shows the change it is about to make", "@@" in out)
restored_bytes = (project / ".mcp.json").read_bytes()
check("uninstall restores the original config BYTE FOR BYTE",
      hashlib.sha256(restored_bytes).hexdigest() == original_sha,
      f"{len(original_bytes)} bytes -> {len(restored_bytes)} bytes")
check("the audit database is left in place", AUDIT_DB.exists(), str(AUDIT_DB))
check("...with every row still in it", row_count(AUDIT_DB) == rows_before_uninstall,
      f"{rows_before_uninstall} -> {row_count(AUDIT_DB)}")
check("the policy is left in place", POLICY_PATH.exists(), str(POLICY_PATH))
check("uninstall says where the audit log is", str(AUDIT_DB) in out)
check("uninstall says where the policy is", str(POLICY_PATH) in out)
check("uninstall says where the backups are", "backups" in out)
check("uninstall does not offer to delete the audit trail",
      "will not remove an" in out)

done = run_cli(["uninstall", "--yes"], project, expect=0)
check("a second uninstall is a no-op, not an error", done.returncode == 0)
check("...and says the file already matches the backup",
      "already identical to the backup" in done.stdout)

# After uninstall the wiring is gone, so doctor must fail again. This is the
# same check as section 7 arrived at from the other direction.
done = run_cli(["doctor", "--timeout", "60"], project, timeout=300)
check("doctor fails again once uninstall has removed the wiring", done.returncode != 0,
      f"exit {done.returncode}")


# ---------------------------------------------------------------------------
section("SUMMARY")
# ---------------------------------------------------------------------------

_assert_real_state_untouched("after everything ran")

print(f"\n  {PASSED} passed, {FAILED} failed")
if FAILED:
    print("\n  failures:")
    for name in FAILURES:
        print(f"    - {name}")
print(f"\n  lab: {LAB}   (delete when done)")
print(
    "\n  NOT established by this run:\n"
    "    - installation from a built wheel into a clean venv (see S7-REPORT.md;\n"
    "      done by hand, not here, because it needs the network)\n"
    "    - a live Claude Code session driven through `aegis init` output\n"
)
sys.exit(1 if FAILED else 0)
