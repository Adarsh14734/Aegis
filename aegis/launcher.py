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
    import sys

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
