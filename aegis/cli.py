"""Aegis S7 — the `aegis` command.

    aegis init        set up policy and wiring, interactively
    aegis doctor      prove the proxy is in the pipe, or say why not
    aegis uninstall   put the MCP configuration back
    aegis proxy -- …  run the proxy (what init writes into .mcp.json)
    aegis version

`proxy` is here so that a pip install has a stable command to put in a client
config. It is the same entry point as `python -m aegis.proxy` and the same code
S1 shipped; this file adds no behaviour to it.
"""

import argparse
import difflib
import sys
from pathlib import Path

from . import __version__

USAGE = """usage: aegis <command> [options]

  init        write a policy and route an MCP server through Aegis
  doctor      check the installation, and prove the proxy is actually in the pipe
  uninstall   restore the MCP configuration Aegis changed
  proxy       run the policy proxy: aegis proxy -- <mcp-server-command>
  version     print the version

Also installed: aegis-secret, aegis-restore, aegis-stop, aegis-resume.
"""


def _uninstall(argv: list[str]) -> int:
    from . import clients
    from .audit import default_db_path
    from .proxy import default_policy_path

    parser = argparse.ArgumentParser(
        prog="aegis uninstall",
        description="Restore the MCP configuration Aegis changed. Keeps the audit log and policy.",
    )
    parser.add_argument(
        "--yes", action="store_true", help="restore without asking for confirmation"
    )
    args = parser.parse_args(argv)

    targets = clients.backed_up_paths("mcp_config")
    if not targets:
        print("Aegis has no MCP configuration backup recorded.")
        print(f"(manifest: {clients.manifest_path()})")
    restored = 0
    failures = 0

    for path in targets:
        src = clients.latest_backup(path)
        print(f"\n{path}")
        print(f"  backup: {src}")
        if src is None or not src.exists():
            print("  FAILED: the backup file is gone; leaving the config alone")
            failures += 1
            continue

        current = path.read_text() if path.exists() else ""
        original = src.read_text()
        if current == original:
            print("  already identical to the backup. Nothing to do.")
            continue
        diff = "".join(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                original.splitlines(keepends=True),
                fromfile=f"{path} (now)",
                tofile=f"{path} (after uninstall)",
            )
        )
        print("\n" + diff)
        if not args.yes:
            answer = input("  restore it? [Y/n] ").strip().lower()
            if answer and answer not in ("y", "yes"):
                print("  skipped")
                continue
        ok, message = clients.restore(path)
        print(f"  {message}")
        restored += 1 if ok else 0
        failures += 0 if ok else 1

    print("\n" + "=" * 60)
    print(f"restored {restored} configuration file(s).")
    print("\nDeliberately left in place — these are your records, not Aegis's:")
    print(f"  audit log  {default_db_path()}")
    print(f"  policy     {default_policy_path()}")
    print(f"  backups    {clients.data_dir() / clients.BACKUP_DIR_NAME}")
    print(
        "\nDelete them yourself if you want them gone. Aegis will not remove an\n"
        "audit trail on your behalf; that is the one action a compromised setup\n"
        "would most want to take."
    )
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if argv else 64

    command, rest = argv[0], argv[1:]

    if command == "version":
        print(f"aegis-mcp {__version__}")
        return 0
    if command == "init":
        from . import onboard

        return onboard.main(rest)
    if command == "doctor":
        from . import doctor

        return doctor.main(rest)
    if command == "uninstall":
        return _uninstall(rest)
    if command == "proxy":
        import asyncio

        from . import proxy as proxy_mod

        if "--" in rest:
            rest = rest[rest.index("--") + 1:]
        if not rest:
            print("usage: aegis proxy -- <mcp-server-command> [args...]", file=sys.stderr)
            return 64
        try:
            return asyncio.run(proxy_mod.run(rest))
        except KeyboardInterrupt:
            return 130

    print(f"aegis: unknown command {command!r}\n", file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
