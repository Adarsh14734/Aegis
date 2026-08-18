"""Aegis S5 kill switch — control C10.

A file named KILLSWITCH in the Aegis data directory. While it exists, every
tool call is denied before any other rule is consulted.

Design notes worth keeping:

  - **A file, not a flag in policy.json.** The policy file is parsed, validated
    and cached at startup; a running proxy would not notice an edit. The kill
    switch has to work on an agent that is *already misbehaving*, which means
    it must take effect on the very next call without restarting anything.
  - **Presence is the signal.** Not contents, not a value inside the file. A
    truncated, empty or corrupt file still stops the agent. The only failure
    mode that matters here is failing to stop.
  - **Checked with one stat() per call**, no caching. Caching would create a
    window in which the switch is thrown and calls still run, which is the one
    thing this control exists to prevent. See S5-REPORT.md for the measured
    cost.

Scope, stated plainly: this stops tool calls crossing *this proxy*. It does not
kill the agent process, does not revoke a credential already handed to an MCP
server, and does not stop anything the agent does outside the MCP channel —
THREAT-MODEL.md §7.6. It is a stop button on one pipe, not on the machine.
"""

import os
import sys
import time
from pathlib import Path

KILLSWITCH_NAME = "KILLSWITCH"


def data_dir() -> Path:
    """The Aegis data directory — the same one holding audit.db.

    Derived from the audit database path so that AEGIS_AUDIT_DB moves the kill
    switch too. That matters for tests: a suite pointed at a temp database must
    not be able to stop the operator's real agent, or read a stale KILLSWITCH
    from their real data directory.
    """
    try:  # noqa: PLC0415 - function-level to avoid an import cycle
        from .audit import default_db_path
    except ImportError:  # pragma: no cover - flat import when run as a script
        from audit import default_db_path

    return default_db_path().parent


def killswitch_path() -> Path:
    if override := os.environ.get("AEGIS_KILLSWITCH"):
        return Path(override).expanduser()
    return data_dir() / KILLSWITCH_NAME


def is_engaged(path: Path | None = None) -> bool:
    """One stat(). Never raises: an error checking the switch is treated as
    engaged, because the alternative is running unchecked when we cannot tell."""
    try:
        return (path or killswitch_path()).exists()
    except OSError:
        return True


def reason(path: Path | None = None) -> str:
    try:
        text = (path or killswitch_path()).read_text().strip()
    except OSError:
        return ""
    for line in text.splitlines():
        if line.startswith("reason="):
            return line[len("reason="):].strip()
    return text.splitlines()[0] if text.splitlines() else ""


def engage(why: str = "") -> Path:
    path = killswitch_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "# Aegis kill switch. While this file exists every tool call is denied.\n"
        "# Remove it with: aegis-resume\n"
        f"engaged_at={time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"engaged_by={os.environ.get('USER', '?')}\n"
        f"reason={why}\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def release() -> bool:
    try:
        killswitch_path().unlink()
        return True
    except FileNotFoundError:
        return False


def main(argv=None) -> int:
    """Backs both `aegis-stop` and `aegis-resume`; the wrapper's name decides."""
    argv = list(sys.argv[1:] if argv is None else argv)
    invoked = Path(sys.argv[0]).name

    if invoked.endswith("resume") or (argv and argv[0] == "resume"):
        path = killswitch_path()
        if release():
            print(f"kill switch released: {path}")
            print("tool calls will be evaluated normally from the next call onward.")
            return 0
        print(f"no kill switch was engaged ({path})")
        return 0

    if argv and argv[0] == "status":
        path = killswitch_path()
        if is_engaged(path):
            print(f"ENGAGED  {path}")
            if r := reason(path):
                print(f"reason: {r}")
            return 0
        print(f"not engaged ({path})")
        return 0

    why = " ".join(a for a in argv if a not in ("stop",))
    path = engage(why)
    print(f"kill switch ENGAGED: {path}")
    print("every tool call through Aegis is now denied, starting with the next one.")
    print("release it with: aegis-resume")
    return 0


if __name__ == "__main__":
    sys.exit(main())
