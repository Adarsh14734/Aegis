"""Aegis S9c — making C11 the default instead of an opt-in.

S9 gave Aegis a kernel boundary and S9b made it audible, but both only apply to
an agent started with `aegis run`. A user who installs Aegis and then opens
Claude Code the way they always have gets **no sandbox at all**. `aegis doctor`
says so on every run, which is honest and leaves the protection unused.

This module routes the client's own launch through `aegis run`, so the sandbox
is what happens by default and everything the client spawns — its Bash tool, its
MCP servers, `npm install`, every subprocess — inherits it.

TWO MECHANISMS, AND THEY ARE NOT EQUALLY STRONG

  **The wrapper** (`aegis init` offers it). A small script in Aegis's own
  `bin` directory, named after the client, that execs `aegis run -- <the real
  binary>`. It works in every shell, in scripts, and in anything that resolves
  the client through PATH — not only in an interactive session.

  **The shim** (`aegis shell-init`). A shell function. It exists because a
  function needs no PATH surgery, and it is strictly weaker: it applies only to
  interactive shells that sourced it.

Both are **advice, not enforcement**, and the report says so in those words.
Either is bypassed by invoking the real binary path directly, and neither can
do anything about a client already running.

WHY THE WRAPPER GETS ITS OWN DIRECTORY

On this machine `claude` lives in `~/.local/bin`. Writing a wrapper called
`claude` into the directory the real `claude` occupies would **overwrite the
user's client**, and an Aegis uninstall would then have to restore a binary it
had destroyed. So wrappers live in `<aegis data dir>/bin`, which contains
nothing else, and effectiveness depends on that directory coming first on PATH.

That split is deliberate and it is why `effective_status()` resolves the name
through PATH rather than checking that a file exists: a wrapper nobody's PATH
reaches is a file, not a control. Same reasoning as S7's doctor — the structural
check is a precondition, the resolution is the evidence.

WHAT REMAINS IMPOSSIBLE

Forcing an **already-running** process into a sandbox is not something this or
any other user-space code can do. On macOS, attaching to and constraining an
arbitrary running process requires an Endpoint Security entitlement, which Apple
grants to registered organizations and which a `pip install` cannot conjure. So
a client that was already open when Aegis was set up stays unconfined until it
is restarted, and a user who types the real binary's full path is not sandboxed.
THREAT-MODEL.md §7.6 stays; S9c narrows it from "any agent you start yourself"
to "direct invocation of the real binary, and processes already running".
"""

import os
import shutil
import sys
import stat
from dataclasses import dataclass
from pathlib import Path

try:  # S7 import plumbing
    from .audit import default_db_path
except ImportError:  # pragma: no cover
    from audit import default_db_path

# Set by `aegis run` in the environment it launches. A wrapper or shim that
# sees it does NOT wrap again: without this, a client launched through the
# wrapper that itself shells out to `claude` would nest one sandbox inside
# another, and the inner profile would be applied to a process already confined
# by the outer one.
SANDBOX_MARKER = "AEGIS_SANDBOXED"

# Clients worth offering to wrap. Name on PATH, and how to say it out loud.
KNOWN_CLIENTS = (
    ("claude", "Claude Code"),
    ("cursor", "Cursor"),
    ("windsurf", "Windsurf"),
    ("cline", "Cline"),
)

MARKER_LINE = "# installed by `aegis init` — remove with `aegis uninstall`"

# The hosts a wrapped client needs in order to work at all.
#
# WHY THIS TABLE EXISTS
#
# S9c made the wrapper the recommended path, and the sandbox starts with zero
# reachable domains. So accepting the recommendation made Claude Code stop
# working: the session never starts, because the client cannot reach its own
# API. A control that breaks the thing it protects is a control that gets
# uninstalled, and it takes C1..C11 with it.
#
# WHERE THESE COME FROM
#
# Measured, not read off a documentation page and not guessed from strings in
# the binary. Each host below was observed being refused by the sandbox
# runtime's own proxy while Claude Code started inside it:
#
#     srt -d -s <profile with allowedDomains: []> -c claude
#     [SandboxDebug] No matching config rule, denying: api.anthropic.com:443
#     [SandboxDebug] Connection blocked to api.anthropic.com:443    (x20)
#
# and the visible result was the reported one: "Remote Control disconnected —
# Session creation failed". Granting the first two turns that line into
# "/rc active" with no api.anthropic.com refusal left, which is how this list
# was closed rather than guessed at: the third host only appears once a session
# gets far enough to reach hosted MCP connectors, and the session works without
# it. The full capture is in evidence/S9d-client-endpoints.txt.
#
# WHAT IS DELIBERATELY NOT HERE
#
#   http-intake.logs.us5.datadoghq.com — the client's telemetry sink. It is
#   refused during startup and the session works anyway, so it is not needed to
#   function. It is also a third-party host, and quietly opening a route for
#   diagnostics out of a sandbox somebody installed to reduce their exposure is
#   not a default anyone asked for. A user who wants it can add it by hand; the
#   init output names it so the denial is not a mystery.
#
#   Every host for cursor, windsurf and cline. They have not been measured on
#   this machine, and inventing plausible hostnames for a security allowlist is
#   how an allowlist stops meaning anything. An unmeasured client gets an empty
#   list and a sentence saying so.
#
# Each entry is (host, what it is for, required-to-function).
CLIENT_ENDPOINTS: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "claude": (
        ("api.anthropic.com",
         "the API the client talks to — without it no session starts", True),
        ("downloads.claude.ai",
         "version checks and auto-update", False),
        ("mcp-proxy.anthropic.com",
         "hosted MCP connectors — only needed if you use them", False),
    ),
    "cursor": (),
    "windsurf": (),
    "cline": (),
}


# Where a wrapped client keeps its own state, and what must stay unwritable
# inside it.
#
# WHY THIS TABLE EXISTS
#
# The sandbox grants write access to the workspace, the Aegis data directory
# and /tmp. A client's own state directory is none of those, so a client
# launched through the wrapper started and then could not work:
#
#     API Error: 401 OAuth access token has expired
#     Transcript writes are failing (permission denied — EPERM)
#     /rc failed
#
# WHERE THESE COME FROM
#
# Measured the way S9d measured endpoints: the client was run inside the real
# profile and the kernel's own refusals were read out of the macOS unified log
# (the same source aegis/violations.py uses). Every path below appeared there.
# The process is named by its version, which is why an obvious filter on
# "claude" finds nothing:
#
#     2.1.258  file-write-create  ~/.claude/.oauth_refresh.lock
#     2.1.258  file-write-create  ~/.claude/projects/<slug>
#     2.1.258  file-write-mode    ~/.claude/sessions
#
# Granting ~/.claude alone clears all three symptoms; verified against an
# unsandboxed control run in the same directory. Full capture in
# evidence/S9f-client-state.txt.
#
# WHAT IS DELIBERATELY NOT HERE
#
#   ~/.claude.json and its .lock/.tmp.* siblings. They sit directly in the HOME
#   directory, so granting them means granting a pattern in $HOME, and the
#   client works without them — measured. What it costs is that whatever the
#   client stores in that file does not persist between sandboxed launches.
#   Naming the cost is better than widening the grant to remove it.
#
#   Every path for cursor, windsurf and cline. Not measured here. Same rule as
#   the endpoint table: an unmeasured client gets an empty list and a sentence.
#
# Each entry is (path, what it is for, required-to-function).
CLIENT_STATE_PATHS: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "claude": (
        ("~/.claude",
         "OAuth token refresh, transcripts and session state — without it "
         "every request fails with 401", True),
        ("~/.local/state/claude",
         "instance and update locks", False),
        ("~/Library/Caches/claude-cli-nodejs",
         "logs from MCP servers the client starts", False),
    ),
    "cursor": (),
    "windsurf": (),
    "cline": (),
}

# The files inside a granted state directory that must NOT become writable.
#
# This is the half that makes the grant defensible. A state directory holds
# state, but it also holds two things that are not state at all:
#
#   settings.json      can define hooks — shell commands the client runs. Write
#                      access to it is arbitrary code execution OUTSIDE the
#                      sandbox at the next launch, which is a sandbox escape
#                      with extra steps.
#   plugins/           executable plugin code, for the same reason.
#   .credentials.json  the OAuth token itself on installs that do not use the
#                      macOS Keychain. Absent on a Keychain machine; denied
#                      anyway, because a policy that is only correct on one
#                      platform is not correct.
#
# denyWrite beats allowWrite in the runtime, and it was verified rather than
# assumed: with these listed, a shell inside the sandbox cannot create, append
# to, truncate, delete or rename any of them, while ordinary state files in the
# same directory stay writable.
#
# Reading them is NOT prevented, and could not be: the client has to read its
# own settings to start. See THREAT-MODEL.md §7.11.
CLIENT_STATE_PROTECT: dict[str, tuple[str, ...]] = {
    "claude": (
        "~/.claude/settings.json",
        "~/.claude/plugins",
        "~/.claude/.credentials.json",
    ),
    "cursor": (),
    "windsurf": (),
    "cline": (),
}


def client_state_paths(name: str, required_only: bool = False):
    """[(path, purpose, required)] for a client, or [] if it was never measured."""
    entries = CLIENT_STATE_PATHS.get(name, ())
    return [e for e in entries if e[2]] if required_only else list(entries)


def client_state_protect(name: str) -> list[str]:
    """Paths inside this client's state that must stay unwritable."""
    return list(CLIENT_STATE_PROTECT.get(name, ()))


def client_endpoints(name: str, required_only: bool = False):
    """[(host, purpose, required)] for a client, or [] if it was never measured."""
    entries = CLIENT_ENDPOINTS.get(name, ())
    return [e for e in entries if e[2]] if required_only else list(entries)


def wrapper_dir() -> Path:
    """Aegis's own bin directory. Deliberately not a directory anyone else owns."""
    if override := os.environ.get("AEGIS_WRAPPER_DIR"):
        return Path(override).expanduser()
    return default_db_path().parent / "bin"


def wrapper_path(name: str) -> Path:
    return wrapper_dir() / name


def _path_entries() -> list[str]:
    return [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]


def real_binary(name: str) -> str | None:
    """The client's actual binary, resolved with Aegis's wrapper dir excluded.

    Excluding it is what stops a wrapper from pointing at itself. Resolving
    `claude` from inside a script called `claude` is a fork bomb with good
    intentions.
    """
    ours = str(wrapper_dir().resolve()) if wrapper_dir().exists() else str(wrapper_dir())
    entries = [
        p for p in _path_entries()
        if str(Path(p).expanduser().resolve() if Path(p).exists() else p) != ours
    ]
    return shutil.which(name, path=os.pathsep.join(entries))


def detect_clients() -> list[tuple[str, str, str]]:
    """[(name, label, real path)] for every known client on PATH."""
    found = []
    for name, label in KNOWN_CLIENTS:
        real = real_binary(name)
        if real:
            found.append((name, label, real))
    return found


# ---------------------------------------------------------------------------
# the wrapper
# ---------------------------------------------------------------------------


def aegis_command() -> str:
    """How the wrapper should invoke Aegis, resolved once at install time.

    `aegis run` in the script would be a SECOND PATH dependency: the wrapper
    already depends on its own directory being early on PATH, and depending on
    `aegis` being there too means a PATH the user reorders can turn the wrapper
    into "command not found" instead of a sandbox. Resolve it now and bake it
    in, the same reason the real binary is baked in.
    """
    found = shutil.which("aegis")
    if found and not is_aegis_wrapper(found):
        return found
    return f"{sys.executable} -m aegis.cli"


def render_wrapper(name: str, real: str, aegis: str | None = None) -> str:
    """The wrapper script.

    `exec` rather than a call, so the client keeps this process's pid, signals
    and exit code — a wrapper that changed how Ctrl-C behaves would be removed
    within a day.

    The real path is baked in rather than re-resolved at run time: re-resolving
    would find this script again if PATH changed underneath it.
    """
    aegis = aegis or aegis_command()
    return f"""#!/bin/sh
{MARKER_LINE}
# Routes {name} through `aegis run`, so the client and everything it spawns
# start inside the OS sandbox (C11). Without this the sandbox applies only to
# commands you explicitly run with `aegis run`.
#
# This is advice, not enforcement: running {real} directly bypasses it, and a
# {name} that is already running is not affected.

if [ -n "${SANDBOX_MARKER}" ]; then
    # Already inside an Aegis sandbox — nesting a second one would apply this
    # profile to a process the outer sandbox has already confined.
    exec {real} "$@"
fi

exec {aegis} run -- {real} "$@"
"""


def install_wrapper(name: str, real: str, aegis: str | None = None) -> Path:
    path = wrapper_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_wrapper(name, real, aegis))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def is_aegis_wrapper(path) -> bool:
    try:
        return MARKER_LINE in Path(path).read_text()
    except (OSError, UnicodeDecodeError):
        return False


@dataclass(frozen=True)
class Status:
    name: str
    label: str
    real: str | None
    wrapper: Path
    wrapper_exists: bool
    resolves_to: str | None
    effective: bool
    reason: str


def effective_status(name: str, label: str = "") -> Status:
    """Whether launching `name` today would actually go through the sandbox.

    Resolution, not existence. A wrapper that PATH never reaches is a file.
    """
    wrapper = wrapper_path(name)
    exists = wrapper.exists() and is_aegis_wrapper(wrapper)
    resolved = shutil.which(name)
    real = real_binary(name)

    if resolved is None:
        return Status(name, label, real, wrapper, exists, None, False,
                      f"{name} is not on PATH at all")
    if is_aegis_wrapper(resolved):
        return Status(name, label, real, wrapper, exists, resolved, True,
                      f"{name} resolves to the Aegis wrapper at {resolved}")
    if exists:
        return Status(
            name, label, real, wrapper, exists, resolved, False,
            f"a wrapper exists at {wrapper} but {name} still resolves to "
            f"{resolved}. {wrapper.parent} is not early enough on PATH, so the "
            f"wrapper is never reached.",
        )
    return Status(name, label, real, wrapper, exists, resolved, False,
                  f"{name} resolves to {resolved}, which is not wrapped")


def path_hint() -> str:
    return f'export PATH="{wrapper_dir()}:$PATH"'


# S9h. Putting the wrapper directory on PATH, in the file that would do it.
#
# `aegis init` used to write the wrappers and then print "add this line to your
# shell rc". Most people do not, and `aegis doctor` then reports the client as
# unsandboxed — which is accurate and useless: the work was done and the last
# step, the one that makes any of it take effect, was left to a manual edit.
#
# So it is offered, with the same shape every other write in this codebase has:
# show the exact line, show the exact file, ask, back up first.
PATH_MARKER = "# added by `aegis init` — puts the Aegis launch wrappers on PATH"


def login_shell() -> str:
    """The user's shell name, from $SHELL. Falls back to sh."""
    return Path(os.environ.get("SHELL", "sh")).name or "sh"


def shell_rc(shell: str | None = None) -> Path:
    """The file that shell reads on login, for the PATH line.

    Not a guess dressed as a fact: each branch is the file that shell actually
    sources, and the fallback is ~/.profile, which every POSIX shell reads.

      zsh   ~/.zshrc
      bash  ~/.bash_profile on macOS if it exists — a macOS Terminal tab is a
            LOGIN shell, which reads .bash_profile and not .bashrc, and writing
            to .bashrc there produces a line that is never executed. Otherwise
            ~/.bashrc, which is right everywhere else.
      fish  ~/.config/fish/config.fish, and a different syntax — see path_line.
    """
    shell = shell or login_shell()
    home = Path.home()
    if shell == "zsh":
        return home / ".zshrc"
    if shell == "fish":
        return home / ".config" / "fish" / "config.fish"
    if shell == "bash":
        profile = home / ".bash_profile"
        if sys.platform == "darwin" and profile.exists():
            return profile
        return home / ".bashrc"
    return home / ".profile"


def path_line(shell: str | None = None) -> str:
    """The one line that puts the wrapper directory first on PATH."""
    shell = shell or login_shell()
    if shell == "fish":
        # `set -gx PATH` rather than fish_add_path: fish_add_path appends by
        # default on some versions, and the wrapper only works if it is found
        # BEFORE the real client.
        return f'set -gx PATH "{wrapper_dir()}" $PATH'
    return f'export PATH="{wrapper_dir()}:$PATH"'


def path_line_present(rc: Path | None = None, shell: str | None = None) -> bool:
    """Whether that rc file already puts the wrapper directory on PATH.

    Checked by the DIRECTORY, not by the exact line: a user who wrote their own
    export, or who ran `aegis shell-init` (which emits the same PATH line
    inside its shim), has already done this, and appending a second copy would
    be Aegis adding noise to a file it does not own.
    """
    rc = rc or shell_rc(shell)
    try:
        text = rc.read_text()
    except (OSError, UnicodeDecodeError):
        return False
    return str(wrapper_dir()) in text


def render_path_line(shell: str | None = None) -> str:
    """The exact bytes that would be appended, marker included."""
    return f"\n{PATH_MARKER}\n{path_line(shell)}\n"


def wrapper_dir_on_path() -> bool:
    target = str(wrapper_dir())
    return any(
        str(Path(p).expanduser()) == target
        or (Path(p).exists() and wrapper_dir().exists()
            and Path(p).expanduser().resolve() == wrapper_dir().resolve())
        for p in _path_entries()
    )


# ---------------------------------------------------------------------------
# the shim
# ---------------------------------------------------------------------------


SHIM_BEGIN = "# >>> aegis shell-init >>>"
SHIM_END = "# <<< aegis shell-init <<<"


def shell_snippet(clients=None) -> str:
    """A shell function per detected client, plus the wrapper dir on PATH.

    The real path is embedded rather than looked up, for the same reason the
    wrapper bakes it in: `command claude` inside a function called `claude`
    finds whatever PATH offers, which may be the Aegis wrapper, which calls
    `aegis run`, which... The absolute path cannot recurse.
    """
    clients = clients if clients is not None else detect_clients()
    lines = [
        SHIM_BEGIN,
        "# Routes your agent clients through `aegis run` so they start inside",
        "# the OS sandbox. ADVICE, NOT ENFORCEMENT: invoking the real binary",
        "# path directly bypasses this entirely, and it only applies to shells",
        "# that sourced it. `aegis doctor` reports which clients are actually",
        "# wrapped when it runs.",
        f'export PATH="{wrapper_dir()}:$PATH"',
    ]
    for name, label, real in clients:
        lines += [
            "",
            f"# {label}",
            f"{name}() {{",
            f'    if [ -n "${SANDBOX_MARKER}" ]; then',
            f'        command {real} "$@"',
            "        return $?",
            "    fi",
            f'    command {aegis_command()} run -- {real} "$@"',
            "}",
        ]
    if not clients:
        lines += ["", "# No known agent client was found on PATH when this was generated."]
    lines.append(SHIM_END)
    return "\n".join(lines) + "\n"


def rc_candidates() -> list[Path]:
    home = Path.home()
    return [home / ".zshrc", home / ".bashrc", home / ".bash_profile", home / ".profile"]


def shim_installed() -> Path | None:
    """The rc file carrying the shim, if any. Advisory: we do not source shells."""
    for path in rc_candidates():
        try:
            if path.exists() and SHIM_BEGIN in path.read_text():
                return path
        except (OSError, UnicodeDecodeError):
            continue
    return None
