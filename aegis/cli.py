"""Aegis S7 — the `aegis` command.

    aegis init        set up policy and wiring, interactively
    aegis doctor      prove the proxy is in the pipe, or say why not
    aegis uninstall   put the MCP configuration back
    aegis proxy -- …  run the proxy (what init writes into .mcp.json)
    aegis run -- …    launch an agent inside the OS sandbox (S9, C11)
    aegis version

`proxy` is here so that a pip install has a stable command to put in a client
config. It is the same entry point as `python -m aegis.proxy` and the same code
S1 shipped; this file adds no behaviour to it.
"""

import argparse
import difflib
import json
import subprocess
import sys
from pathlib import Path

from . import __version__

USAGE = """usage: aegis <command> [options]

  init        write a policy and route an MCP server through Aegis
  doctor      check the installation, and prove the proxy is actually in the pipe
  uninstall   restore the MCP configuration Aegis changed
  proxy       run the policy proxy: aegis proxy -- <mcp-server-command>
  run         launch an agent inside the OS sandbox: aegis run -- <agent-command>
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


def _run(argv: list[str]) -> int:
    """S9 / C11. Launch an agent with its whole process tree inside the sandbox.

    The order here is the control:

      1. Load the policy. No policy, no sandbox — the profile is generated from
         it and there is nothing to generate from.
      2. Establish the sandbox, which writes the profile and proves the runtime
         accepts it.
      3. Record that, with the profile digest, BEFORE anything is launched.
      4. Only then exec the agent, wrapped.

    Every failure between 1 and 3 refuses to launch and records the refusal.
    There is no flag that turns a failed sandbox into an unconfined launch: a
    silently-unsandboxed agent is worse than no sandbox, because the operator
    believes there is one and behaves accordingly.
    """
    from .audit import AuditError, AuditStore, default_db_path
    from .policy import Policy, PolicyError
    from .proxy import default_policy_path
    from . import sandbox as sandbox_mod

    parser = argparse.ArgumentParser(
        prog="aegis run",
        description="Launch an agent inside the OS sandbox, confined by policy.json.",
    )
    parser.add_argument(
        "--deny-all-network", action="store_true",
        help="allow no domains at all, not even policy's allowed_domains. "
             "Closes bash egress completely and disables the proxy's own "
             "egress (C4) with it.",
    )
    parser.add_argument(
        "--print-profile", action="store_true",
        help="write the generated profile and print it; launch nothing",
    )
    known, rest = parser.parse_known_args(argv)
    if "--" in rest:
        rest = rest[rest.index("--") + 1:]
    command = [a for a in rest if a]

    if not command and not known.print_profile:
        print("usage: aegis run [--deny-all-network] -- <agent-command> [args...]",
              file=sys.stderr)
        return 64

    policy_path = default_policy_path()
    try:
        policy = Policy.load(policy_path)
    except PolicyError as exc:
        print(f"aegis run: refusing to launch — {exc}", file=sys.stderr)
        print(f"aegis run: the sandbox profile is generated from {policy_path}; "
              f"without a loadable policy there are no rules to enforce.",
              file=sys.stderr)
        return 2

    # The audit store is opened before the sandbox so a refusal can be recorded.
    # A refusal nobody can reconstruct is the same problem as an action nobody
    # can reconstruct (C3).
    store = None
    try:
        store = AuditStore.open(default_db_path())
    except AuditError as exc:
        print(f"aegis run: refusing to launch — the audit log is unavailable "
              f"({exc}). Same posture as the proxy: a control that cannot record "
              f"is an absent control.", file=sys.stderr)
        return 2

    def record(effect: str, rule_id: str, reason: str, paths=()) -> None:
        try:
            store.record(tool="aegis run", effect=effect, rule_id=rule_id,
                         reason=reason, paths=list(paths))
        except Exception as exc:  # noqa: BLE001
            print(f"aegis run: WARNING could not record to the audit log: {exc}",
                  file=sys.stderr)

    try:
        box = sandbox_mod.establish(policy, deny_all_network=known.deny_all_network)
    except sandbox_mod.SandboxError as exc:
        record("deny", "sandbox_refused",
               f"refused to launch {' '.join(command) or '(no command)'}: {exc}")
        store.close()
        print(f"aegis run: REFUSING TO LAUNCH.\n\n{exc}\n", file=sys.stderr)
        print("Nothing was started. Aegis does not launch an agent it cannot "
              "confine — an unsandboxed agent that looks sandboxed is the "
              "failure this command exists to prevent.", file=sys.stderr)
        return 3

    record("allow", "sandbox_established", box.summary(), [str(box.profile)])

    print(f"[aegis] {box.summary()}", file=sys.stderr)
    print(f"[aegis] profile: {box.profile}", file=sys.stderr)
    if known.deny_all_network:
        print("[aegis] --deny-all-network: no domain is reachable, including "
              "the proxy's own egress path.", file=sys.stderr)
    print("[aegis] Outside this boundary: an agent you start yourself, and a "
          "kernel escape. THREAT-MODEL.md §7.6 and §7.7.", file=sys.stderr)

    if known.print_profile:
        print(json.dumps(box.document, indent=2))
        store.close()
        return 0

    wrapped = box.wrap(command)
    store.close()  # the child inherits nothing; the store belongs to this process
    try:
        return subprocess.call(wrapped)
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        print(f"aegis run: the sandboxed command could not start: {exc}",
              file=sys.stderr)
        return 3


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
    if command == "run":
        return _run(rest)
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
