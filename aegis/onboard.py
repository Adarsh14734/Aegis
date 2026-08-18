"""Aegis S7 — `aegis init`.

Interactive setup. Writes policy.json into the OS data directory and routes an
existing MCP server through the proxy, showing the change before making it.

This command adds no security control and weakens none. Everything it writes is
input to controls that already exist: `policy.py` re-validates the file it
produces at every proxy start and refuses it if it is wrong, so a bug here can
misconfigure Aegis but cannot make Aegis run misconfigured.

Two refusals are deliberate and non-overridable:

  - **A workspace root that would contain policy.json.** `policy.py` already
    refuses to start in that state (S0 decision #2); refusing at write time
    turns "the proxy mysteriously will not start" into a sentence explaining
    why, before anything is written.
  - **A workspace root that would contain the trash directory**, for the same
    reason: an agent that can delete its own undo history has no undo history.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from . import clients
from .audit import default_db_path
from .policy import Policy, PolicyError
from .proxy import default_policy_path

TEMPLATE = Path(__file__).with_name("policy.template.json")


def _load_template() -> dict:
    return json.loads(TEMPLATE.read_text())


class Prompt:
    """stdin questions, or the defaults when there is nobody to ask.

    `--yes` is not a convenience: `init` has to be runnable from a script and
    from a test, and a setup command that can only be driven by a human is a
    setup command nobody can verify. When there is no terminal and no `--yes`,
    it refuses rather than silently taking defaults — the defaults decide which
    directories an agent may read.
    """

    def __init__(self, assume_yes: bool):
        self.assume_yes = assume_yes
        self.interactive = sys.stdin.isatty() and sys.stdout.isatty()

    def require_answerable(self) -> None:
        if not self.assume_yes and not self.interactive:
            raise SystemExit(
                "aegis init: no terminal to ask on. Re-run with --yes and the\n"
                "flags for the answers, e.g.\n"
                "  aegis init --yes --workspace ~/code/myproject\n"
            )

    def text(self, question: str, default: str) -> str:
        if self.assume_yes:
            return default
        answer = input(f"{question}\n  [{default}] ").strip()
        return answer or default

    def confirm(self, question: str, default: bool = True) -> bool:
        if self.assume_yes:
            return default
        suffix = "Y/n" if default else "y/N"
        answer = input(f"{question} [{suffix}] ").strip().lower()
        if not answer:
            return default
        return answer in ("y", "yes")


def _split_paths(raw: str) -> list[str]:
    parts: list[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        chunk = chunk.strip().strip("'\"")
        if chunk:
            parts.append(chunk)
    return parts


def _resolve_roots(raw_entries: list[str]) -> list[Path]:
    roots: list[Path] = []
    for entry in raw_entries:
        path = Path(entry).expanduser()
        if not path.exists():
            raise SystemExit(
                f"aegis init: {path} does not exist.\n"
                f"Aegis will not create a workspace root for you — a typo would "
                f"silently grant access to a directory you did not mean."
            )
        if not path.is_dir():
            raise SystemExit(f"aegis init: {path} is not a directory")
        roots.append(path.resolve())
    return roots


def _assert_outside_roots(what: str, target: Path, roots: list[Path], fix: str) -> None:
    resolved = target.expanduser().resolve()
    for root in roots:
        if resolved == root or resolved.is_relative_to(root):
            raise SystemExit(
                f"aegis init: REFUSING.\n"
                f"  {what} would be {resolved}\n"
                f"  which is inside the workspace root {root}\n"
                f"\n"
                f"  The agent can write everywhere inside a workspace root. "
                f"{fix}\n"
                f"  Nothing has been written. Choose a workspace root that does "
                f"not contain it, and run aegis init again."
            )


def _build_policy(roots: list[Path], deny: list[str], trash: Path | None) -> dict:
    doc = _load_template()
    doc["workspace_roots"] = [str(r) for r in roots]
    doc["deny_paths"] = deny
    doc["trash_dir"] = str(trash) if trash else None
    if doc["trash_dir"] is None:
        # The template's only destructive tool stages copies into trash_dir, and
        # policy.py refuses to load a destructive rule with nowhere to put them.
        doc["tool_rules"] = {
            name: rule
            for name, rule in doc["tool_rules"].items()
            if not rule.get("destructive")
        }
    return doc


def _write_policy(path: Path, doc: dict, prompt: Prompt) -> bool:
    new_text, diff = clients.plan_write(path, doc)
    print(f"\npolicy file: {path}")
    if path.exists():
        if not diff:
            print("  already exactly this. Nothing to write.")
            return True
        print("  this file already exists. The change would be:\n")
        print(diff)
    else:
        print("  new file, mode 0600. Contents:\n")
        print("".join(f"    {line}\n" for line in new_text.splitlines()))

    if not prompt.confirm("Write it?"):
        print("  skipped. Nothing was written.")
        return False

    existed = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if existed:
        # kind="policy" keeps it out of `aegis uninstall`, which restores MCP
        # configuration only. Uninstall must never quietly revert a policy.
        dest = clients.backup(path, kind="policy")
        print(f"  backed up to {dest}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, new_text.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    print(f"  written, mode 0600")
    return True


def _patch_configs(
    found: list[clients.Detected], prompt: Prompt, only_servers: list[str] | None
) -> int:
    patched = 0
    for det in found:
        if not det.patchable:
            print(f"\n{det.label}\n  skipped: {det.note}")
            continue
        already = det.wrapped_servers()
        todo = [
            name
            for name in det.unwrapped_servers()
            if only_servers is None or name in only_servers
        ]
        print(f"\n{det.label}")
        for name in already:
            print(f"  {name}: already routed through Aegis")
        if not todo:
            if not already:
                print("  nothing to wrap here")
            continue

        doc = json.loads(det.path.read_text())
        node = doc
        for key in det.container[:-1]:
            node = node.setdefault(key, {})
        servers = node[det.container[-1]]

        changed: list[str] = []
        for name in todo:
            try:
                wrapped = clients.wrap_entry(servers[name])
            except clients.ClientError as exc:
                print(f"  {name}: skipped — {exc}")
                continue
            if not prompt.confirm(f"  route '{name}' through Aegis?"):
                print(f"  {name}: skipped")
                continue
            servers[name] = wrapped
            changed.append(name)

        if not changed:
            continue

        _, diff = clients.plan_write(det.path, doc)
        print(f"\n  changes to {det.path}:\n")
        print(diff)
        if not prompt.confirm("  apply this?"):
            print("  skipped. The file is unchanged.")
            continue

        dest = clients.backup(det.path)
        print(f"  backed up to {dest}")
        clients.write_config(det.path, clients.render(doc))
        print(f"  patched: {', '.join(changed)}")
        patched += len(changed)
    return patched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis init",
        description="Set up Aegis: write a policy and route an MCP server through the proxy.",
    )
    parser.add_argument("--project", default=None, help="project directory (default: cwd)")
    parser.add_argument(
        "--workspace", action="append", default=[],
        help="a directory the agent may work in (repeatable)",
    )
    parser.add_argument(
        "--deny", action="append", default=[],
        help="a path pattern the agent must never open (repeatable; replaces the defaults)",
    )
    parser.add_argument(
        "--server", action="append", default=None,
        help="only wrap this MCP server name (repeatable)",
    )
    parser.add_argument("--no-patch", action="store_true", help="write the policy only")
    parser.add_argument(
        "--yes", action="store_true",
        help="take the defaults and every confirmation without asking",
    )
    args = parser.parse_args(argv)

    project = Path(args.project).expanduser().resolve() if args.project else Path.cwd()
    prompt = Prompt(args.yes)

    print("Aegis setup")
    print("=" * 60)
    print(f"project: {project}")
    print(
        "\nAegis mediates tool calls that cross an MCP stdio pipe. It does not\n"
        "see Bash, native file edits, or anything an agent does outside that\n"
        "pipe — THREAT-MODEL.md §7.6. `aegis doctor` says this again, in full."
    )

    # --- 1. clients ------------------------------------------------------
    found = clients.detect(project)
    print("\nMCP configuration found:")
    if found:
        for det in found:
            names = ", ".join(sorted(det.servers)) or "(none)"
            print(f"  {det.label}\n    servers: {names}")
    else:
        print("  none.")
        for line in clients.other_evidence(project):
            print(f"  (a client looks installed — {line})")
        print(
            "  Aegis can still write a policy; there is just nothing to route\n"
            "  through it yet."
        )

    # --- 2. workspace roots ----------------------------------------------
    prompt.require_answerable()
    if args.workspace:
        raw_roots = args.workspace
    else:
        answer = prompt.text(
            "\nWhich folders may the agent work in? (comma separated)",
            str(project),
        )
        raw_roots = _split_paths(answer)
    roots = _resolve_roots(raw_roots)
    if not roots:
        raise SystemExit("aegis init: at least one workspace root is required")

    # --- 3. deny list ----------------------------------------------------
    default_deny = _load_template()["deny_paths"]
    if args.deny:
        deny = args.deny
    else:
        answer = prompt.text(
            "\nWhich paths must the agent NEVER open? (comma separated)\n"
            "These are checked before every rule and no allow rule can override them.",
            ", ".join(default_deny),
        )
        deny = _split_paths(answer) or list(default_deny)

    # --- 4. where things land, and the refusals --------------------------
    policy_path = default_policy_path()
    trash_dir = clients.data_dir() / "trash"
    _assert_outside_roots(
        "the policy file", policy_path, roots,
        "A policy the agent can edit enforces nothing.",
    )
    _assert_outside_roots(
        "the trash directory", trash_dir, roots,
        "An agent that can delete its own undo history has no undo history.",
    )
    _assert_outside_roots(
        "the audit database", default_db_path(), roots,
        "An audit log the agent can rewrite is not evidence of anything.",
    )

    print("\nAegis will keep its own files here, outside every workspace root:")
    print(f"  policy    {policy_path}")
    print(f"  audit log {default_db_path()}")
    print(f"  trash     {trash_dir}")

    doc = _build_policy(roots, deny, trash_dir)

    # Validate before writing rather than after. Policy() enforces far more than
    # this command checks — refusing here means a policy that would not load is
    # never written, instead of being written and discovered at the next launch.
    try:
        Policy(doc, policy_path)
    except PolicyError as exc:
        raise SystemExit(f"aegis init: the policy this would write is invalid: {exc}")

    if not _write_policy(policy_path, doc, prompt):
        return 1

    # --- 5. wire the client ----------------------------------------------
    if args.no_patch:
        print("\n--no-patch: MCP configuration left alone.")
    elif found:
        _patch_configs(found, prompt, args.server)

    print("\n" + "=" * 60)
    print("Next, and do not skip it:\n")
    print("    aegis doctor\n")
    print(
        "doctor sends a real tool call through the configuration you just wrote\n"
        "and checks the audit log gained a row for it. Until that passes, there\n"
        "is no evidence Aegis is in the pipe at all."
    )
    return 0
