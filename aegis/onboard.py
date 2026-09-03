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

from . import clients, launcher
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


def _offer_client_domains(
    prompt: Prompt, client_names: list[str], policy_path: Path, force: bool = False
) -> bool:
    """Let a wrapped client reach its own API. Asked, shown, and never blanket.

    THE BUG THIS EXISTS FOR

    `aegis init` writes `allowed_domains: []`, the sandbox profile therefore
    carries `allowedDomains: []`, and the sandbox grants **zero** reachable
    hosts. A client started through the S9c wrapper then cannot reach its own
    API, so accepting the recommended install path made Claude Code unusable:

        Remote Control disconnected — Session creation failed
        Auto-update failed

    Measured cause, not inferred: with an empty allowlist the runtime's own
    proxy refuses `api.anthropic.com:443` twenty times during a single start,
    and refuses `downloads.claude.ai:443` on every update check. With those two
    hosts granted, nothing else in a start is refused except the client's
    telemetry sink.

    WHY THIS IS A PROMPT AND NOT A SILENT DEFAULT

    It grants the sandboxed process tree a route to a real host on the
    internet, and the sandbox cannot tell the client's request from its Bash
    tool's (S9-REPORT.md §The network residual). That is a real widening, small
    and necessary but not something to do to someone's machine without showing
    it. So the hosts are printed with what each is for, the residual is stated
    in the same breath, and the policy diff is shown by `_write_policy` before
    anything is written.

    WHY sandbox_domains AND NOT allowed_domains

    `allowed_domains` is C4's egress allowlist: a host there becomes fetchable
    by the agent's own tools, through the proxy. The client's API endpoint has
    no business being reachable that way just because the client needs a
    socket. See policy.py::_load_sandbox_domains.
    """
    wanted: list[tuple[str, str, bool]] = []
    unmeasured: list[str] = []
    for name in client_names:
        entries = launcher.client_endpoints(name)
        if not entries:
            unmeasured.append(name)
        for entry in entries:
            if entry[0] not in {w[0] for w in wanted}:
                wanted.append(entry)

    if unmeasured:
        print(
            f"\n  No endpoint list for: {', '.join(sorted(set(unmeasured)))}.\n"
            f"  Aegis has not measured what these clients need, and it will not\n"
            f"  guess hostnames into a security allowlist. If one of them cannot\n"
            f"  reach its API, run it once with `aegis run` and add the hosts the\n"
            f"  sandbox refuses to `sandbox_domains` in your policy."
        )
    if not wanted:
        return False

    try:
        doc = json.loads(policy_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"\n  Could not read {policy_path} ({exc}); leaving the network "
              f"rules alone.")
        return False

    already = set(doc.get("sandbox_domains") or []) | set(doc.get("allowed_domains") or [])
    missing = [w for w in wanted if w[0] not in already]
    if not missing:
        print("\n  The client's own endpoints are already reachable. Nothing to add.")
        return False

    print(
        "\n  ONE MORE THING — the sandbox starts with NO reachable hosts, so a\n"
        "  wrapped client cannot reach its own API and will not start. These are\n"
        "  the hosts it needs:\n"
    )
    for host, purpose, required in missing:
        print(f"      {host:<28} {purpose}")
        print(f"      {'':<28} {'required' if required else 'optional'}")
    print(
        "\n  They go in `sandbox_domains`, which only the sandbox reads. They do\n"
        "  NOT go in `allowed_domains`, so this does not let the agent's own\n"
        "  fetch tool reach them.\n"
        "\n  What this costs: the sandbox cannot tell the client's request from\n"
        "  its Bash tool's, so anything in the tree can reach the hosts above.\n"
        "  Nothing else is opened — there is no wildcard and no allow-all.\n"
        "\n  You will still see the client's telemetry sink\n"
        "  (http-intake.logs.us5.datadoghq.com) refused. That is deliberate: it\n"
        "  is not needed to function and it is not ours to open for you."
    )

    if not (force or prompt.confirm("\n  Add these to sandbox_domains?", default=True)):
        print(
            "  Declined. The wrapper is installed and the client will start\n"
            "  sandboxed with no network — which for most clients means it will\n"
            "  not work. Add the hosts to `sandbox_domains` when you want it to,\n"
            "  or remove the wrapper with `aegis uninstall`."
        )
        return False

    doc["sandbox_domains"] = sorted(set(doc.get("sandbox_domains") or [])
                                    | {w[0] for w in missing})
    # Validated before it is written, exactly as the first policy write is: a
    # policy that would not load must never reach the disk.
    try:
        Policy(doc, policy_path)
    except PolicyError as exc:
        print(f"  Refusing: that policy would not load ({exc}). Nothing written.")
        return False
    return _write_policy(policy_path, doc, prompt)


def _offer_client_state(
    prompt: Prompt, client_names: list[str], policy_path: Path, force: bool = False
) -> bool:
    """Let a wrapped client write its own state. Asked, shown, and bounded.

    THE BUG THIS EXISTS FOR

    The sandbox grants write access to the workspace, the Aegis data directory
    and /tmp. A client's own state directory is none of those, so a client
    routed through the S9c wrapper started and then could not work:

        API Error: 401 OAuth access token has expired
        Transcript writes are failing (permission denied — EPERM)
        /rc failed

    Measured cause, not inferred: the kernel refused `~/.claude/.oauth_refresh.lock`,
    `~/.claude/projects/<slug>` and `~/.claude/sessions`, and an unsandboxed
    control run in the same directory had none of the three symptoms.

    WHAT IS AND IS NOT GRANTED

    The client's own state directory. Never the home directory — policy.py
    refuses that outright, and `~/.claude` is a client's state while `~` is
    every config file, shell rc and key directory the user owns.

    And inside it, the files that are not state get carved back out:
    `settings.json` (which can define hooks — shell commands the client runs),
    `plugins/`, and `.credentials.json`. Writing those is code execution or
    credential theft rather than state, and denyWrite beats allowWrite in the
    runtime.

    WHAT IT COSTS, SAID OUT LOUD

    A granted directory is writable by everything in the sandboxed tree, not
    only by the client — the sandbox cannot tell the client's write from its
    Bash tool's, exactly as it cannot tell their network requests apart (S9d).
    And reading was never restricted: anything in the tree could already read
    that directory before this change, so what is new is modification, not
    exposure. THREAT-MODEL.md §7.11.
    """
    wanted: list[tuple[str, str, bool]] = []
    protect: list[str] = []
    unmeasured: list[str] = []
    for name in client_names:
        entries = launcher.client_state_paths(name)
        if not entries:
            unmeasured.append(name)
        for entry in entries:
            if entry[0] not in {w[0] for w in wanted}:
                wanted.append(entry)
        for path in launcher.client_state_protect(name):
            if path not in protect:
                protect.append(path)

    if unmeasured:
        print(
            f"\n  No state-path list for: {', '.join(sorted(set(unmeasured)))}.\n"
            f"  Aegis has not measured what these clients write, and it will not\n"
            f"  guess directories into a write grant. If one of them misbehaves\n"
            f"  under the sandbox, run it once with `aegis run` and add the paths\n"
            f"  the kernel refuses to `sandbox_state_paths`."
        )
    if not wanted:
        return False

    try:
        doc = json.loads(policy_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"\n  Could not read {policy_path} ({exc}); leaving the write rules alone.")
        return False

    already = {str(Path(p).expanduser()) for p in (doc.get("sandbox_state_paths") or [])}
    missing = [w for w in wanted if str(Path(w[0]).expanduser()) not in already]
    if not missing:
        print("\n  The client's own state directories are already writable. "
              "Nothing to add.")
        return False

    print(
        "\n  AND ONE MORE — the sandbox lets a client write the folders you work\n"
        "  in, and nothing else. A wrapped client also needs somewhere to keep its\n"
        "  OWN state, or it starts and then cannot work:\n"
    )
    for path, purpose, required in missing:
        print(f"      {path:<34} {purpose}")
        print(f"      {'':<34} {'required' if required else 'optional'}")
    if protect:
        print("\n  These stay READ-ONLY even inside that grant, because writing them\n"
              "  is code execution or credential theft rather than state:\n")
        for path in protect:
            print(f"      {path}")
    print(
        "\n  What this costs, plainly:\n"
        "    - Everything in the sandboxed tree can write there, not only the\n"
        "      client. A Bash tool it runs could alter your transcripts or its\n"
        "      session state.\n"
        "    - Reading was never restricted. Anything in the tree could already\n"
        "      read that directory, so this adds modification, not exposure.\n"
        "    - Your home directory is NOT granted, and Aegis refuses a policy\n"
        "      that names it.\n"
        "  This is written down in THREAT-MODEL.md §7.11 rather than only here."
    )

    if not (force or prompt.confirm(
            "\n  Add these to sandbox_state_paths?", default=True)):
        print(
            "  Declined. The wrapper is installed and the client will start\n"
            "  sandboxed but unable to write its own state — for Claude Code that\n"
            "  means a 401 on every request. Add the paths when you want it to\n"
            "  work, or remove the wrapper with `aegis uninstall`."
        )
        return False

    doc["sandbox_state_paths"] = sorted(
        set(doc.get("sandbox_state_paths") or []) | {w[0] for w in missing})
    if protect:
        doc["sandbox_state_protect"] = sorted(
            set(doc.get("sandbox_state_protect") or []) | set(protect))
    try:
        Policy(doc, policy_path)
    except PolicyError as exc:
        print(f"  Refusing: that policy would not load ({exc}). Nothing written.")
        return False
    return _write_policy(policy_path, doc, prompt)


def _offer_path_line(prompt: Prompt, force: bool = False) -> bool:
    """Put the wrapper directory on PATH, in the file that would do it.

    The wrappers are written and unreachable until this happens: PATH decides
    whether `claude` finds the wrapper or the real binary, and a wrapper PATH
    never reaches is a file, not a control. `aegis init` used to print the line
    and leave it to the user. Most people do not do it, `aegis doctor` then
    correctly reports the client as unsandboxed, and the whole flow ends one
    edit short of working.

    So it is offered — and only offered. Appending to a shell rc silently would
    be a worse citizen than editing an MCP config silently, which S7 already
    refuses to do: an rc file is hand-maintained, order-sensitive, and entirely
    the user's. The rules are the ones every other write here follows — show
    the exact file, show the exact bytes, ask, back up first — plus one this
    file needs on its own: never write it twice.
    """
    rc = launcher.shell_rc()
    shell = launcher.login_shell()

    if launcher.path_line_present(rc):
        print(
            f"\n  {launcher.wrapper_dir()} is already named in {rc}, so the\n"
            f"  wrappers will be found in a new shell. Nothing to add."
        )
        return False

    addition = launcher.render_path_line(shell)
    print(
        f"\n  ONE MORE STEP — the wrappers are written but not reachable.\n"
        f"  {launcher.wrapper_dir()} is not on your PATH, so `claude` still\n"
        f"  resolves to the unwrapped binary and nothing is sandboxed.\n"
        f"\n  Your shell is {shell}, so the file that fixes it is:\n"
        f"\n      {rc}{'' if rc.exists() else '   (does not exist yet)'}\n"
        f"\n  and the line to add is:\n"
    )
    for line in addition.strip().splitlines():
        print(f"      {line}")
    print(
        "\n  Aegis can append exactly that, after backing the file up. It is\n"
        "  your shell configuration, so it is a question rather than a step."
    )

    # default=False, and --wrap-clients deliberately does NOT reach here.
    #
    # A shell rc is more the user's than an MCP config is: hand-maintained,
    # order-sensitive, and read by every shell they open. `_offer_launch_wrapping`
    # already defaults its own confirm to False because "installing a launch
    # wrapper is not something to do to someone's machine on a default"; this is
    # the same argument about a more personal file, so it gets its own flag
    # (`--path-line`) rather than riding on that one. A bare `--yes` therefore
    # never edits a shell rc.
    if not (force or prompt.confirm("  Append it?", default=False)):
        print(
            f"\n  Declined. Nothing was written. Add it yourself when you want the\n"
            f"  wrappers to take effect:\n\n"
            f"      {launcher.path_line(shell)}\n\n"
            f"  or use `aegis shell-init`, which prints that line plus a function\n"
            f"  per client. `aegis doctor` reports whether it actually took effect."
        )
        return False

    try:
        existed = rc.exists()
        if existed:
            dest = clients.backup(rc, kind="shell_rc")
            print(f"    backed up to {dest}")
        else:
            rc.parent.mkdir(parents=True, exist_ok=True)
            clients.record_created(rc, kind="shell_rc")
        with open(rc, "a", encoding="utf-8") as handle:
            handle.write(addition)
    except OSError as exc:
        print(
            f"    could not write {rc}: {exc}\n"
            f"    Nothing was changed. Add this line yourself:\n"
            f"        {launcher.path_line(shell)}"
        )
        return False

    print(
        f"    appended to {rc}\n"
        f"\n  It takes effect in a NEW shell — this one already has its PATH.\n"
        f"  Start a new terminal, or run:  source {rc}\n"
        f"  Then `aegis doctor` will report the client as covered.\n"
        f"\n  `aegis uninstall` will NOT remove this line. It restores MCP\n"
        f"  configuration and the wrappers it wrote; your shell rc is yours, and\n"
        f"  reverting a file you may have edited since is not something Aegis\n"
        f"  will do on your behalf. Delete the two lines under the marker."
    )
    return True


def _offer_launch_wrapping(
    prompt: Prompt, policy_path: Path, force: bool = False,
    path_line_force: bool = False,
) -> int:
    """S9c. Offer to route each detected client's launch through `aegis run`.

    A choice, never automatic. Declining leaves exactly the pre-S9c behaviour —
    the sandbox stays available via `aegis run` and `aegis doctor` keeps saying
    it is not being used. Making this automatic would mean silently changing
    what the user's `claude` command does, which is a bigger thing to do to
    someone's machine than editing a config file.
    """
    from . import sandbox as sandbox_mod

    print("\n" + "=" * 60)
    print("Sandboxing the client itself (optional)")
    print("=" * 60)

    clients_found = launcher.detect_clients()
    if not clients_found:
        print("  No known agent client found on PATH, so there is nothing to wrap.")
        return 0

    problems = sandbox_mod.preflight()
    print(
        "\nAegis can mediate this client's MCP tool calls already. What it "
        "cannot\ndo, unless the client itself starts inside the sandbox, is "
        "constrain the\nclient's Bash tool, its native file edits, or anything "
        "it spawns.\n"
    )
    for name, label, real in clients_found:
        print(f"  {label:<14} {real}")
    if problems:
        print(
            "\n  The sandbox runtime is not installed, so a wrapper would "
            "refuse to\n  launch anything until it is:\n"
            f"      {sandbox_mod.RUNTIME_INSTALL_HINT}\n"
            "  Wrappers can still be written now and will start working then."
        )

    if not (force or prompt.confirm(
        "\nRoute these through `aegis run`, so they start sandboxed?", default=False
    )):
        print(
            "  Declined. Nothing changed — the sandbox is still available with\n"
            "  `aegis run -- <command>`, and `aegis doctor` will keep reporting\n"
            "  that your client is not covered by it."
        )
        return 0

    installed = []
    # Every client whose launch ends up going through the sandbox, including
    # one that was already wrapped. A user re-running `aegis init` to fix a
    # client that cannot reach its API is exactly the case that matters, and
    # skipping the already-wrapped ones would skip them.
    covered: list[str] = []
    for name, label, real in clients_found:
        path = launcher.wrapper_path(name)
        existed = path.exists()
        body = launcher.render_wrapper(name, real)
        old = path.read_text() if existed else ""
        if old == body:
            print(f"\n  {label}: already wrapped, unchanged.")
            covered.append(name)
            continue
        import difflib
        diff = "".join(difflib.unified_diff(
            old.splitlines(keepends=True), body.splitlines(keepends=True),
            fromfile=f"{path} (now)", tofile=f"{path} (after aegis init)"))
        print(f"\n  {label} -> {path}\n")
        print(diff or "".join(f"    {l}\n" for l in body.splitlines()))
        if not prompt.confirm(f"  install the {label} wrapper?"):
            print("    skipped")
            continue
        if existed:
            dest = clients.backup(path, kind="launch_wrapper")
            print(f"    backed up to {dest}")
        else:
            clients.record_created(path, kind="launch_wrapper")
        launcher.install_wrapper(name, real)
        installed.append(name)
        covered.append(name)
        print(f"    installed")

    if covered:
        _offer_client_domains(prompt, covered, policy_path, force=force)
        _offer_client_state(prompt, covered, policy_path, force=force)

    # `covered`, not `installed`. A user re-running `aegis init` because their
    # client is still unsandboxed has a wrapper that already exists and is
    # therefore "unchanged" — and that is precisely the person who needs the
    # PATH line. Gating on `installed` would offer it only to someone who had
    # just installed a wrapper for the first time, which is the one case that
    # was already working.
    if covered and not launcher.wrapper_dir_on_path():
        _offer_path_line(prompt, force=path_line_force)
    elif covered:
        print(f"\n  {launcher.wrapper_dir()} is already on PATH, so these take "
              f"effect in a new shell.")
    return len(installed)

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
        "--wrap-clients", action="store_true",
        help="install launch wrappers without asking (S9c; implies consent)",
    )
    parser.add_argument(
        "--path-line", action="store_true",
        help="append the PATH line to your shell rc without asking (S9h; "
             "implies consent to edit that file). Separate from --wrap-clients "
             "on purpose: a shell rc is yours in a way an MCP config is not.",
    )
    parser.add_argument(
        "--no-wrap-clients", action="store_true",
        help="do not offer launch wrappers at all",
    )
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

    # --- 6. S9c: make the sandbox the default rather than an opt-in ------
    if not args.no_wrap_clients:
        _offer_launch_wrapping(prompt, policy_path, force=args.wrap_clients,
                               path_line_force=args.path_line)

    print("\n" + "=" * 60)
    print("Next, and do not skip it:\n")
    print("    aegis doctor\n")
    print(
        "doctor sends a real tool call through the configuration you just wrote\n"
        "and checks the audit log gained a row for it. Until that passes, there\n"
        "is no evidence Aegis is in the pipe at all."
    )
    return 0
