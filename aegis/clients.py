"""Aegis S7 — MCP client discovery, config patching, backup and restore.

No policy decisions are made in this file and nothing here is a security
control. It reads and writes the *client's* configuration, which is the piece a
new user would otherwise edit by hand and get wrong.

Two rules the rest of S7 leans on:

  - **Nothing is overwritten without the change being shown first.** Every
    write goes through `plan_write()`, which returns a unified diff, and a
    backup is taken before the new bytes land.
  - **Wrapping is detected structurally, never by a marker we wrote.** A marker
    is a claim the config makes about itself; `is_wrapped()` looks at the actual
    command and argv. `aegis doctor` then goes further and proves it by running
    the thing (see doctor.py) — this file's answer is a precondition for that
    probe, not evidence on its own.
"""

import difflib
import hashlib
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

BACKUP_DIR_NAME = "backups"
MANIFEST_NAME = "manifest.json"


class ClientError(Exception):
    """Anything that stops us reading or writing a client config."""


# ---------------------------------------------------------------------------
# where the proxy lives
# ---------------------------------------------------------------------------


def data_dir() -> Path:
    """The Aegis data directory — the one holding audit.db and KILLSWITCH.

    Derived from audit.py so that AEGIS_AUDIT_DB moves everything S7 writes
    too. A test that cannot be pinned away from the operator's real directory
    is a test that will eventually damage it (S5 finding 1).
    """
    from .audit import default_db_path

    return default_db_path().parent


def proxy_command() -> list[str]:
    """The argv prefix that runs the Aegis proxy, ending before `--`.

    Preference order, and the reason for it:

    1. ``<python> -m aegis.proxy`` when this interpreter can import the package
       from a neutral working directory. Pinning `sys.executable` matters: the
       MCP client launches this command with its own PATH and its own cwd, and
       a bare `python3` there may be a different interpreter with no Aegis in
       it. Verified by actually running the import, not assumed from
       ``aegis.__file__``, because a source checkout only imports when the cwd
       happens to be the repository root.
    2. The absolute path to ``proxy.py``. Works from a source checkout with no
       install at all, which is how every pre-S7 ``.mcp.json`` is written.
    """
    from . import proxy as proxy_mod

    if _interpreter_can_import(sys.executable):
        return [sys.executable, "-m", "aegis.proxy"]
    return [sys.executable, str(Path(proxy_mod.__file__).resolve())]


def _interpreter_can_import(python: str) -> bool:
    """Whether `python -m aegis.proxy` will work when the MCP client runs it.

    Run with a neutral cwd and with PYTHONPATH removed, because the client will
    have neither. A shell that happens to export PYTHONPATH would otherwise
    make this say yes and write a command into `.mcp.json` that only starts
    inside that shell — the exact class of "works on my machine" wiring bug
    `aegis doctor` exists to catch, and better not to write it in the first
    place.
    """
    import subprocess

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    try:
        done = subprocess.run(
            [python, "-c", "import aegis.proxy"],
            cwd=os.path.sep,
            env=env,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def is_wrapped(entry: dict) -> bool:
    """True if this server entry already runs through the Aegis proxy.

    Structural, and deliberately generous about *how* the proxy is invoked:
    `-m aegis.proxy`, a path to `proxy.py`, or the `aegis proxy` subcommand.
    Being generous here only risks declining to wrap something twice; the
    expensive mistake would be double-wrapping, or reporting "wired" for a
    chain doctor never actually exercises.
    """
    if not isinstance(entry, dict):
        return False
    argv = [entry.get("command") or ""] + [
        a for a in (entry.get("args") or []) if isinstance(a, str)
    ]
    for i, token in enumerate(argv):
        if token == "-m" and i + 1 < len(argv) and argv[i + 1] == "aegis.proxy":
            return True
        tail = token.replace("\\", "/").rsplit("/", 2)[-2:]
        if tail == ["aegis", "proxy.py"]:
            return True
        if Path(token).name == "aegis" and i + 1 < len(argv) and argv[i + 1] == "proxy":
            return True
    return False


def wrap_entry(entry: dict) -> dict:
    """Route an existing stdio server entry through the proxy.

    Every other key (`env`, `cwd`, client-specific extras) is carried across
    untouched: they belong to the downstream server and Aegis has no business
    editing them.
    """
    if not isinstance(entry, dict):
        raise ClientError("server entry is not an object")
    if entry.get("url") or entry.get("type") in ("http", "sse"):
        raise ClientError(
            "this server is HTTP/SSE, not stdio. The Aegis proxy intercepts a "
            "stdio pipe only, so it cannot be put in front of this one"
        )
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        raise ClientError("server entry has no 'command' to wrap")
    if is_wrapped(entry):
        raise ClientError("this server already runs through the Aegis proxy")

    args = [a for a in (entry.get("args") or []) if isinstance(a, str)]
    prefix = proxy_command()
    wrapped = dict(entry)
    wrapped["command"] = prefix[0]
    wrapped["args"] = prefix[1:] + ["--", command] + args
    return wrapped


def unwrap_entry(entry: dict) -> dict | None:
    """The original entry, recovered from a wrapped one. None if not wrapped.

    Used only to *describe* what uninstall would undo. Uninstall itself
    restores the backup file byte for byte rather than reconstructing, because
    a reconstruction can only ever return what this function knows about.
    """
    if not is_wrapped(entry):
        return None
    args = [a for a in (entry.get("args") or []) if isinstance(a, str)]
    if "--" not in args:
        return None
    rest = args[args.index("--") + 1:]
    if not rest:
        return None
    original = dict(entry)
    original["command"] = rest[0]
    if len(rest) > 1:
        original["args"] = rest[1:]
    else:
        original.pop("args", None)
    return original


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


@dataclass
class Detected:
    client: str
    path: Path
    container: tuple[str, ...]  # where mcpServers lives in the document
    servers: dict = field(default_factory=dict)
    patchable: bool = True
    note: str = ""

    @property
    def label(self) -> str:
        return f"{self.client} — {self.path}"

    def wrapped_servers(self) -> list[str]:
        return sorted(n for n, e in self.servers.items() if is_wrapped(e))

    def unwrapped_servers(self) -> list[str]:
        return sorted(n for n, e in self.servers.items() if not is_wrapped(e))


def _load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ClientError(f"{path} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ClientError(f"cannot read {path}: {exc}") from exc


def _dig(doc, container: tuple[str, ...]):
    node = doc
    for key in container:
        if not isinstance(node, dict):
            return {}
        node = node.get(key)
        if node is None:
            return {}
    return node if isinstance(node, dict) else {}


def candidate_locations(project: Path) -> list[tuple[str, Path, tuple[str, ...]]]:
    """Every place we know an MCP client keeps stdio server definitions.

    Listed whether or not the file exists, so `aegis init` can say "looked
    here, found nothing" rather than silently searching. Claude Code's
    `~/.claude.json` keys its per-project servers by absolute project path, so
    that container is computed from `project` rather than fixed.
    """
    home = Path.home()
    locations = [
        ("Claude Code (project)", project / ".mcp.json", ("mcpServers",)),
        ("Cursor (project)", project / ".cursor" / "mcp.json", ("mcpServers",)),
        ("Cursor (user)", home / ".cursor" / "mcp.json", ("mcpServers",)),
        ("Claude Code (user)", home / ".claude.json", ("mcpServers",)),
        (
            "Claude Code (user, this project)",
            home / ".claude.json",
            ("projects", str(project), "mcpServers"),
        ),
    ]
    if sys.platform == "darwin":
        desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        desktop = Path(
            os.environ.get("XDG_CONFIG_HOME", home / ".config")
        ) / "Claude" / "claude_desktop_config.json"
    locations.append(("Claude Desktop", desktop, ("mcpServers",)))
    return locations


def detect(project: Path) -> list[Detected]:
    """Configs that exist and define at least one MCP server.

    A file that exists but defines no servers is dropped: there is nothing to
    route through the proxy, and offering to patch it would invite a user to
    create a server definition Aegis invented.
    """
    out: list[Detected] = []
    for client, path, container in candidate_locations(project):
        if not path.exists():
            continue
        try:
            doc = _load_json(path)
        except ClientError as exc:
            out.append(
                Detected(client, path, container, {}, patchable=False, note=str(exc))
            )
            continue
        servers = _dig(doc, container)
        if not servers:
            continue
        out.append(Detected(client, path, container, servers))
    return out


def other_evidence(project: Path) -> list[str]:
    """Signs a client is installed even where no MCP server is configured.

    `aegis init` prints these so "no MCP configuration found" does not read as
    "no MCP client installed" — they are very different situations and only one
    of them is a problem.
    """
    home = Path.home()
    found = []
    for label, path in (
        ("Claude Code settings", home / ".claude" / "settings.json"),
        ("Claude Code settings (project)", project / ".claude" / "settings.json"),
        ("Claude Code state", home / ".claude.json"),
        ("Cursor", home / ".cursor"),
    ):
        if path.exists():
            found.append(f"{label}: {path}")
    return found


# ---------------------------------------------------------------------------
# writing, with the change shown first
# ---------------------------------------------------------------------------


def render(doc) -> str:
    return json.dumps(doc, indent=2) + "\n"


def plan_write(path: Path, new_doc) -> tuple[str, str]:
    """(new text, unified diff against what is on disk now).

    The diff is against the file's actual bytes, not against a re-serialized
    copy of them, so a whitespace-only reformat still shows up as a change. It
    is a change — the user asked to see what would happen to their file, not to
    the parse of it.
    """
    old_text = path.read_text() if path.exists() else ""
    new_text = render(new_doc)
    diff = "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"{path} (now)",
            tofile=f"{path} (after aegis init)",
        )
    )
    return new_text, diff


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_path() -> Path:
    return data_dir() / BACKUP_DIR_NAME / MANIFEST_NAME


def read_manifest() -> dict:
    path = manifest_path()
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _write_manifest(doc: dict) -> None:
    path = manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def backup(path: Path, kind: str = "mcp_config") -> Path:
    """Copy a config aside and record it, before anything is written.

    `shutil.copy2` rather than a re-serialize: uninstall has to be able to put
    back exactly what was there, including the formatting and any key Aegis
    does not understand.
    """
    target_dir = data_dir() / BACKUP_DIR_NAME
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = str(path).strip("/").replace("/", "_").replace("\\", "_")
    dest = target_dir / f"{safe}.{stamp}.bak"
    n = 0
    while dest.exists():
        n += 1
        dest = target_dir / f"{safe}.{stamp}-{n}.bak"
    shutil.copy2(path, dest)
    os.chmod(dest, 0o600)

    entries = read_manifest()
    record = entries.setdefault(str(path), {"backups": []})
    record["kind"] = kind
    record["backups"].append(
        {
            "backup": str(dest),
            "taken_at": stamp,
            "sha256": _sha256(dest),
            "existed": True,
        }
    )
    _write_manifest(entries)
    return dest


def record_created(path: Path, kind: str = "mcp_config") -> None:
    """Note that `path` did not exist before Aegis wrote it.

    Uninstall then removes it rather than restoring, because there is nothing to
    restore to — and leaving behind a file the user never had is its own small
    lie about what was changed. Removed in S7 when nothing used it; back in S9c,
    which creates launch wrappers.
    """
    entries = read_manifest()
    record = entries.setdefault(str(path), {"backups": []})
    record["kind"] = kind
    record["backups"].append(
        {"backup": None, "taken_at": time.strftime("%Y%m%d-%H%M%S"),
         "sha256": None, "existed": False}
    )
    _write_manifest(entries)


def write_config(path: Path, text: str) -> None:
    """Atomic replace, mode preserved when the file already existed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_name(path.name + f".aegis-tmp{os.getpid()}")
    try:
        tmp.write_text(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def backed_up_paths(kind: str = "mcp_config") -> list[Path]:
    """Files of this kind that Aegis has a backup for, oldest record first."""
    return [
        Path(p)
        for p, record in read_manifest().items()
        if record.get("kind", "mcp_config") == kind and record.get("backups")
    ]


def latest_backup(path: Path) -> Path | None:
    record = read_manifest().get(str(path))
    if not record or not record.get("backups"):
        return None
    stored = record["backups"][-1].get("backup")
    # None means Aegis created the file and there is nothing to restore FROM;
    # uninstall removes it instead. Returning Path(None) crashed here.
    return Path(stored) if stored else None


def restore(path: Path) -> tuple[bool, str]:
    """Put back the most recent backup of `path`. (ok, message).

    Verifies the backup's digest before copying: restoring a corrupted backup
    over a working config would turn uninstall into the incident.
    """
    entries = read_manifest()
    record = entries.get(str(path))
    if not record or not record.get("backups"):
        return False, f"no Aegis backup recorded for {path}"

    latest = record["backups"][-1]
    if not latest.get("existed", True):
        if path.exists():
            path.unlink()
            return True, f"removed {path} — Aegis created it; there was no earlier file"
        return True, f"{path} is already absent, as it was before Aegis ran"

    src = Path(latest["backup"])
    if not src.exists():
        return False, f"backup {src} is missing; {path} left untouched"
    if latest.get("sha256") and _sha256(src) != latest["sha256"]:
        return False, (
            f"backup {src} does not match the digest recorded when it was taken; "
            f"refusing to restore it over {path}"
        )
    shutil.copy2(src, path)
    return True, f"restored {path} from {src}"
