"""Deterministic policy engine for Aegis.

S1: controls C1 (path allow/deny per tools/call) and C2 (default-deny).
S3a: partial C4 (egress domain allowlist) and partial C5 (outbound secret
scan), delegated to egress.py and dlp.py but sequenced here.

Design constraints from THREAT-MODEL.md:
  - B1: nothing on the agent side is trusted, including tool arguments.
  - D1: decisions here are deterministic. No model judgement anywhere in this file.
  - Fail-closed: any exception raised out of this module must be treated as DENY
    by the caller. The caller is responsible for that; this module never guesses.
"""

import fnmatch
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# S7: import plumbing only. Relative when loaded as `aegis.policy` (installed
# package, `python -m aegis.proxy`), flat when this directory is on sys.path
# (`python3 aegis/proxy.py`, the tests' sys.path.insert). Both forms have to
# keep working: the second is what every .mcp.json written before S7 uses.
# Nothing below this block changed in S7.
try:
    from . import broker, dlp, egress, killswitch
except ImportError:  # pragma: no cover - exercised by running this as a script
    import broker
    import dlp
    import egress
    import killswitch


class Effect(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reason: str
    rule_id: str
    tool: str
    paths: tuple[str, ...] = ()

    def is_allowed(self) -> bool:
        return self.effect is Effect.ALLOW


class PolicyError(Exception):
    """Raised for any malformed or unsafe policy. Callers must fail closed."""


# Argument keys that carry filesystem paths in the reference MCP filesystem server.
# Anything not listed here is not treated as a path. Unknown path-bearing tools are
# caught by default-deny rather than by guessing at argument names.
PATH_ARG_KEYS = ("path", "paths", "source", "destination", "src", "dst", "directory")

# Substrings that make a tool name look like it performs network requests.
# Used only to refuse a policy that leaves such a tool's "egress" flag unstated
# (S3b fix 1). Matching is case-insensitive substring, so `web_fetch`,
# `HTTPRequest` and `mcp__browser__open` are all caught.
EGRESS_NAME_HINTS = (
    "fetch", "http", "request", "curl", "browse", "download", "web", "url", "api",
)


def safe_resolve(raw: str, cwd: Path) -> Path:
    """Resolve a path for policy evaluation without trusting it.

    Resolves symlinks on the deepest existing ancestor, then re-appends the
    non-existent tail. This prevents two escapes:
      - '../../etc/passwd' traversal
      - a symlink inside the workspace pointing outside it
    A path that does not exist yet (a file about to be created) still gets its
    parent directory resolved, so a symlinked parent cannot be used to escape.
    """
    p = Path(raw)
    if not p.is_absolute():
        p = cwd / p

    tail: list[str] = []
    probe = p
    # Walk up to the deepest component that actually exists.
    while not probe.exists():
        if probe.parent == probe:  # reached filesystem root
            break
        tail.append(probe.name)
        probe = probe.parent

    resolved = probe.resolve()
    for part in reversed(tail):
        resolved = resolved / part
    return resolved


def _within(child: Path, parent: Path) -> bool:
    try:
        return child == parent or child.is_relative_to(parent)
    except (ValueError, OSError):
        return False


class Policy:
    """Loaded, validated policy. Immutable after construction."""

    def __init__(self, doc: dict, source_path: Path):
        self.source_path = source_path

        if doc.get("version") != 1:
            raise PolicyError(f"unsupported policy version: {doc.get('version')!r}")

        roots = doc.get("workspace_roots") or []
        if not isinstance(roots, list) or not roots:
            raise PolicyError("workspace_roots must be a non-empty list")
        self.workspace_roots = tuple(Path(r).expanduser().resolve() for r in roots)

        self.deny_paths = tuple(doc.get("deny_paths") or ())
        if not isinstance(self.deny_paths, tuple):
            raise PolicyError("deny_paths must be a list")

        self.allowed_domains = self._load_allowed_domains(doc)
        self.sandbox_domains = self._load_sandbox_domains(doc)
        self.sandbox_state_paths = self._load_state_paths(doc, "sandbox_state_paths")
        self.sandbox_state_protect = self._load_state_paths(doc, "sandbox_state_protect")
        self.credentials = self._load_credentials(doc)
        self.folder_rules = self._load_folder_rules(doc)

        rules = doc.get("tool_rules") or {}
        if not isinstance(rules, dict):
            raise PolicyError("tool_rules must be an object")
        for tool, rule in rules.items():
            if rule.get("effect") not in {e.value for e in Effect}:
                raise PolicyError(f"tool_rules[{tool}] has invalid effect")
            if "egress" in rule and not isinstance(rule["egress"], bool):
                raise PolicyError(
                    f"tool_rules[{tool}].egress must be true or false, "
                    f"got {rule['egress']!r}"
                )
            if "destructive" in rule and not isinstance(rule["destructive"], bool):
                raise PolicyError(
                    f"tool_rules[{tool}].destructive must be true or false, "
                    f"got {rule['destructive']!r}"
                )
        self.tool_rules = rules
        self._assert_fetching_tools_declare_egress()

        default = doc.get("default_effect", "deny")
        if default == Effect.ALLOW.value:
            # D1/C2: a policy file that defaults to allow is a misconfiguration
            # severe enough that we refuse to run rather than run insecurely.
            raise PolicyError("default_effect may not be 'allow'")
        self.default_effect = Effect(default)

        # S5: ASK now means ask. `ask_behavior` survives as an explicit opt-out
        # for headless deployments that would rather deny than block on a
        # prompt nobody will see; "prompt" is the default and "allow" is still
        # refused outright, because a policy that auto-approves its own ASK
        # rules has written a deny rule and an allow rule and got both wrong.
        behaviour = doc.get("ask_behavior", "prompt")
        if behaviour == Effect.ALLOW.value:
            raise PolicyError("ask_behavior may not be 'allow'")
        if behaviour not in ("prompt", Effect.DENY.value, Effect.ASK.value):
            raise PolicyError(
                f"ask_behavior must be 'prompt' or 'deny', got {behaviour!r}"
            )
        self.ask_behavior = Effect.ASK if behaviour in ("prompt", "ask") else Effect.DENY

        # S9e. Whether the sandboxed process tree may drive a terminal.
        #
        # It sounds cosmetic and is not. Without it the kernel refuses every
        # ioctl on /dev/ttys*, so `tcsetattr` fails with EPERM and no program
        # inside the sandbox can put the terminal into raw mode. A TUI then
        # runs with the tty still in canonical+echo, and every escape sequence
        # the terminal sends back — arrow keys, bracketed paste, mouse reports
        # — is echoed by the tty driver as literal text into the input line.
        # That is the reported `^[[<65;63;22M` bug, and it made every
        # interactive client launched through `aegis run` unusable.
        #
        # Default true, because the default has to be a client that works. It
        # lives in the policy rather than being decided from os.isatty() at
        # launch so the profile stays a pure function of policy.json: a
        # document that changed with the caller's terminal would make its own
        # digest unstable, and `aegis doctor` compares that digest to decide
        # whether the kernel is enforcing the current rules.
        #
        # Setting it false is the narrower profile and is the right choice for
        # a headless run that never attaches a terminal. It costs nothing
        # there and breaks every TUI everywhere else.
        pty = doc.get("sandbox_pty", True)
        if not isinstance(pty, bool):
            raise PolicyError(f"sandbox_pty must be true or false, got {pty!r}")
        self.sandbox_pty = pty

        # C7. How long a prompt waits before denying. Not unbounded: a proxy
        # blocked forever on a prompt nobody is looking at is a hung agent, and
        # the safe resolution of "nobody answered" is no.
        timeout = doc.get("ask_timeout_seconds", 120)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise PolicyError(
                f"ask_timeout_seconds must be a positive number, got {timeout!r}"
            )
        self.ask_timeout_seconds = float(timeout)

        # C8. Any call touching more than this many paths escalates to ASK, no
        # matter what its tool rule says. T1 is the confused agent that globs
        # too widely; the count is the only signal available at this layer that
        # separates "edit a file" from "rewrite the project".
        threshold = doc.get("bulk_threshold", 10)
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
            raise PolicyError(
                f"bulk_threshold must be a positive integer, got {threshold!r}"
            )
        self.bulk_threshold = threshold

        # C9. Where destructive calls stage their backups. No default: silently
        # inventing a directory to write copies of the user's files into is not
        # a decision Aegis should make on its own.
        trash = doc.get("trash_dir")
        if trash is not None and not isinstance(trash, str):
            raise PolicyError("trash_dir must be a string path")
        self.trash_dir = Path(trash).expanduser() if trash else None
        if self.trash_dir is not None:
            for root in self.workspace_roots:
                if _within(self.trash_dir.resolve(), root):
                    raise PolicyError(
                        f"trash_dir {self.trash_dir} is inside agent-writable "
                        f"workspace root {root}; the agent could delete its own "
                        f"undo history"
                    )
        if any(r.get("destructive") for r in self.tool_rules.values()) and not self.trash_dir:
            raise PolicyError(
                "tool_rules declare \"destructive\": true but no trash_dir is set; "
                "refusing to run a soft-delete control with nowhere to put the copy"
            )

        # Resolved once; the file's *presence* is what gets checked per call.
        self.killswitch_path = killswitch.killswitch_path()

        self._assert_policy_file_unreachable()

    def tool_is_destructive(self, tool: str) -> bool:
        rule = self.tool_rules.get(tool)
        return bool(rule.get("destructive", False)) if isinstance(rule, dict) else False

    def _assert_fetching_tools_declare_egress(self) -> None:
        """S3b: the egress flag defaults to false, so a fetching tool that
        loses its flag silently loses its destination check. That is a
        catastrophic default to get wrong quietly, so any tool whose *name*
        suggests it fetches must state the flag either way.

        This is a spelling check on names, not a capability check — Aegis
        cannot know what a tool does. It catches the realistic accident (a
        renamed or newly added fetch tool, a hand-edited policy) and nothing
        else. A network tool named `summarize_page` still slips through, which
        is why S3a-REPORT.md lists server-derived requests as out of scope.
        """
        missing = [
            tool
            for tool, rule in self.tool_rules.items()
            if "egress" not in rule
            and any(hint in tool.lower() for hint in EGRESS_NAME_HINTS)
        ]
        if missing:
            raise PolicyError(
                "tool_rules entries "
                + ", ".join(repr(t) for t in sorted(missing))
                + " have names suggesting they make network requests but do not "
                  'declare "egress". Add "egress": true to apply the destination '
                  'allowlist, or "egress": false to state explicitly that the tool '
                  "does not fetch. Refusing to start rather than guess."
            )

    def tool_does_egress(self, tool: str) -> bool:
        """Absent means false: non-fetching tools are the overwhelming common
        case, and treating every argument as a destination is what made S3a
        deny ordinary README writes."""
        rule = self.tool_rules.get(tool)
        return bool(rule.get("egress", False)) if isinstance(rule, dict) else False

    @staticmethod
    def _load_allowed_domains(doc: dict) -> tuple[str, ...]:
        """S3a: a missing key is the empty list, and the empty list denies every
        URL. Absence must never mean permissive — the same rule as C2.

        Entries are bare hostnames. Subdomains are implied, so '*.example.com'
        is rejected rather than silently reinterpreted, and a bare '*' is
        rejected outright for the same reason `default_effect: allow` is: a
        policy that permits everything is a misconfiguration severe enough to
        refuse to start over.
        """
        raw = doc.get("allowed_domains")
        if raw is None:
            return ()
        return Policy._normalize_host_list(raw, "allowed_domains")

    @staticmethod
    def _load_state_paths(doc: dict, key: str) -> tuple[Path, ...]:
        """Directories a sandboxed client may write for its OWN state, and the
        paths inside them that stay read-only anyway.

        `sandbox_state_paths`    added to the profile's allowWrite.
        `sandbox_state_protect`  added to its denyWrite, which beats allowWrite
                                 in this runtime. These are the files inside a
                                 granted directory that must never become
                                 writable, because writing them is code
                                 execution or credential theft rather than
                                 state — see launcher.py's table.

        Only sandbox.py reads either. Neither reaches policy.py's own decision
        path, so granting a client its state directory does not make that
        directory reachable through an MCP tool call.

        THE ONE THING THAT MAY NOT BE GRANTED IS THE HOME DIRECTORY.
        `~/.claude` is a client's state; `~` is everything the user owns, and a
        policy that granted it would hand the agent write access to every
        config file, shell rc and ssh directory on the machine while still
        reading as a modest two-line policy. `/` is refused for the same
        reason, and so is a glob: a write grant that can match by pattern is a
        write grant nobody can read off the page.
        """
        raw = doc.get(key)
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise PolicyError(f"{key} must be a list")
        home = Path.home().resolve()
        out: list[Path] = []
        for entry in raw:
            if not isinstance(entry, str) or not entry.strip():
                raise PolicyError(f"{key} entry {entry!r} is not a non-empty string")
            if any(ch in entry for ch in "*?["):
                raise PolicyError(
                    f"{key} entry {entry!r}: patterns are not allowed here. A "
                    f"write grant has to name the directory it grants."
                )
            resolved = Path(entry).expanduser()
            # Not .resolve(): a protected path may legitimately not exist yet
            # (a credentials file that has never been written), and resolve()
            # of a missing path is fine while resolve() of a symlink is the
            # thing we want to see through. absolute() + resolve(strict=False)
            # gives both.
            resolved = Path(os.path.abspath(resolved)).resolve()
            if resolved == home:
                raise PolicyError(
                    f"{key} may not contain the home directory ({resolved}). "
                    f"Grant the client's own state directory, not everything "
                    f"the user owns."
                )
            if resolved == Path(resolved.anchor):
                raise PolicyError(f"{key} may not contain the filesystem root")
            out.append(resolved)
        return tuple(out)

    @staticmethod
    def _load_sandbox_domains(doc: dict) -> tuple[str, ...]:
        """Hosts the sandboxed PROCESS TREE may reach. Deliberately not
        `allowed_domains`.

        The two lists answer different questions and have different blast
        radii, so they are different keys:

          allowed_domains   where the AGENT'S OWN tool calls may go. C4 reads
                            it (egress.py, fetch.py) to decide whether a URL in
                            a tool argument is permitted, and a host listed
                            here becomes fetchable *through Aegis*, with the
                            credential broker and the audit trail attached.

          sandbox_domains   where the sandboxed process tree may open a socket
                            at all. Only sandbox.py reads it. A host here is
                            reachable by the client, by its Bash tool and by
                            everything it spawns — and by nothing that goes
                            through the proxy, because the proxy does not
                            consult this list.

        The distinction exists because of what S9c made the default. A client
        launched through the wrapper starts inside the sandbox, and the sandbox
        starts with zero reachable domains — so the client cannot reach its own
        API and does not work at all. Fixing that by adding the client's
        endpoints to `allowed_domains` would also hand the agent's fetch tool
        an allowlisted route to those hosts, which is a widening of a different
        control that nobody asked for. This key grants the socket without
        granting the tool.

        Same validation as `allowed_domains`, so no wildcard and no '*': the
        list can only ever name hosts. There is no spelling of "everything".
        """
        raw = doc.get("sandbox_domains")
        if raw is None:
            return ()
        return Policy._normalize_host_list(raw, "sandbox_domains")

    @staticmethod
    def _normalize_host_list(raw, where: str) -> tuple[str, ...]:
        """Validate and normalize a list of bare hostnames.

        Shared by `allowed_domains` and by each credential's `hosts`, so the
        two cannot drift into disagreeing about what a host entry may look
        like — a credential scoped by a laxer rule than the egress allowlist
        would be a quiet way to widen both.
        """
        if not isinstance(raw, list):
            raise PolicyError(f"{where} must be a list")

        out: list[str] = []
        for entry in raw:
            if not isinstance(entry, str):
                raise PolicyError(f"{where} entry {entry!r} is not a string")
            value = egress.normalize_domain(entry)
            if not value:
                raise PolicyError(f"{where} contains an empty entry")
            if value == "*":
                raise PolicyError(f"{where} may not contain '*' (allow-all)")
            if value.startswith("*."):
                raise PolicyError(
                    f"{where} entry {entry!r}: wildcards are not supported; "
                    f"write {value[2:]!r}, which already covers its subdomains"
                )
            if "/" in value:
                raise PolicyError(
                    f"{where} entry {entry!r} must be a bare host, "
                    f"without scheme or path"
                )
            head, sep, tail = value.rpartition(":")
            if sep and tail.isdigit() and egress.parse_ip_literal(value) is None:
                # ...but ':' inside a bare IPv6 literal is not a port.
                raise PolicyError(
                    f"{where} entry {entry!r} must not carry a port; "
                    f"ports are not part of the host check"
                )
            out.append(value)
        return tuple(out)

    @staticmethod
    def _load_credentials(doc: dict) -> dict:
        """S4: `credentials` maps a handle to the tools and hosts it may be
        substituted into. Nothing here touches the keychain — this is the
        grant, not the secret, and the secret lives only in the OS keychain.

        A handle with neither `tools` nor `hosts` is loadable but unusable:
        every substitution attempt denies. That is the "both absent means
        deny" rule, kept as a runtime denial rather than a load error so the
        denial is visible in the audit trail rather than only in a startup
        message nobody rereads.
        """
        raw = doc.get("credentials")
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise PolicyError("credentials must be an object")

        out: dict[str, dict] = {}
        for handle, grant in raw.items():
            if not broker.HANDLE_RE.fullmatch("${aegis:%s}" % handle):
                raise PolicyError(
                    f"credentials handle {handle!r} is not a valid handle name "
                    f"(letters, digits, underscore, dot, dash; 64 chars max)"
                )
            if not isinstance(grant, dict):
                raise PolicyError(f"credentials[{handle}] must be an object")
            for key in grant:
                if key not in ("tools", "hosts"):
                    raise PolicyError(
                        f"credentials[{handle}] has unknown key {key!r}; "
                        f"only 'tools' and 'hosts' are understood"
                    )
            tools = grant.get("tools")
            if tools is not None:
                if not isinstance(tools, list) or not all(
                    isinstance(t, str) and t for t in tools
                ):
                    raise PolicyError(
                        f"credentials[{handle}].tools must be a list of tool names"
                    )
                if "*" in tools:
                    raise PolicyError(
                        f"credentials[{handle}].tools may not contain '*'; "
                        f"name the tools that may use this secret"
                    )
            hosts = grant.get("hosts")
            out[handle] = {
                "tools": tuple(tools) if tools is not None else None,
                "hosts": (
                    Policy._normalize_host_list(hosts, f"credentials[{handle}].hosts")
                    if hosts is not None
                    else None
                ),
            }
        return out

    @staticmethod
    def _load_folder_rules(doc: dict) -> tuple:
        """S10: per-folder allow/ask/deny, so the Permissions UI can offer three
        states truthfully.

        Absent means the empty tuple, and the empty tuple changes nothing — every
        policy written before S10 evaluates exactly as it did. That matters more
        than usual here: this is the first sprint to touch the decision chain
        since S5, and a default that altered behaviour would silently reinterpret
        nine sprints of verified policies.

        `deny` here does NOT replace `deny_paths`. deny_paths is checked first and
        still beats everything, including a folder rule that says allow — a UI
        that could override the deny list by adding a folder would be a UI that
        can widen the strongest rule in the file.
        """
        raw = doc.get("folder_rules")
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise PolicyError("folder_rules must be a list")
        out = []
        for entry in raw:
            if not isinstance(entry, dict):
                raise PolicyError(f"folder_rules entry {entry!r} is not an object")
            for key in entry:
                if key not in ("path", "effect"):
                    raise PolicyError(
                        f"folder_rules entry has unknown key {key!r}; "
                        f"only 'path' and 'effect' are understood"
                    )
            path = entry.get("path")
            if not isinstance(path, str) or not path.strip():
                raise PolicyError("folder_rules entry has no 'path' string")
            effect = entry.get("effect")
            if effect not in {e.value for e in Effect}:
                raise PolicyError(
                    f"folder_rules[{path!r}] has invalid effect {effect!r}; "
                    f"expected allow, ask or deny"
                )
            out.append((Path(path).expanduser().resolve(), Effect(effect)))
        return tuple(out)

    def folder_rule_for(self, path: Path):
        """The most specific folder rule covering `path`, or None.

        Longest match wins, so a deny on a subfolder of an allowed folder is
        reachable — which is the whole point of having them nest.
        """
        best = None
        for folder, effect in self.folder_rules:
            if _within(path, folder) and (best is None or len(str(folder)) > len(str(best[0]))):
                best = (folder, effect)
        return best

    def authorize_credentials(self, tool: str, handles, strings) -> str | None:
        """None if every handle in the call may be substituted, else the reason
        it may not. Config only — no secret is read, because this runs while
        the call may still be denied.
        """
        hosts_in_call = None
        for where, handle in handles:
            grant = self.credentials.get(handle)
            if grant is None:
                return (
                    f"credential handle {handle!r} at {where} is not declared in "
                    f"policy credentials"
                )
            tools, hosts = grant["tools"], grant["hosts"]
            if not tools and not hosts:
                return (
                    f"credential handle {handle!r} declares neither tools nor "
                    f"hosts, so it can never be substituted"
                )
            if not tools or tool not in tools:
                return (
                    f"credential handle {handle!r} is not permitted for tool "
                    f"{tool!r}"
                )
            if not hosts:
                return (
                    f"credential handle {handle!r} declares no hosts, so there is "
                    f"nothing to check the destination against"
                )

            if hosts_in_call is None:
                hosts_in_call = [
                    h for h in (egress.url_host(u) for _, u in
                                egress.extract_urls(strings)) if h
                ]
            if not hosts_in_call:
                return (
                    f"credential handle {handle!r} is scoped to hosts "
                    f"{list(hosts)}, but this call carries no URL to check"
                )
            # Every destination in the call must be covered. One unlisted URL
            # is enough to smuggle the credential somewhere it was not granted.
            for host in hosts_in_call:
                if not egress.host_allowed(host, hosts):
                    return (
                        f"credential handle {handle!r} is not permitted for host "
                        f"{host!r}"
                    )
        return None

    def _assert_policy_file_unreachable(self) -> None:
        """S0 decision #2: the agent must not be able to write the policy file.

        Verified structurally at load time: if the policy file sits inside any
        workspace root the agent can write to, refuse to start. A proxy that
        enforces a policy the agent can edit enforces nothing.
        """
        policy = self.source_path.resolve()
        for root in self.workspace_roots:
            if _within(policy, root):
                raise PolicyError(
                    f"policy file {policy} is inside agent-writable workspace root "
                    f"{root}; move it outside every workspace root"
                )

    @classmethod
    def load(cls, path: Path) -> "Policy":
        if not path.exists():
            raise PolicyError(f"policy file not found: {path}")
        mode = path.stat().st_mode
        if mode & 0o022:
            raise PolicyError(
                f"policy file {path} is group/world writable (mode {oct(mode & 0o777)})"
            )
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy file is not valid JSON: {exc}") from exc
        return cls(doc, path)

    # ---- evaluation -----------------------------------------------------

    def extract_paths(self, arguments: dict) -> list[str]:
        found: list[str] = []
        for key in PATH_ARG_KEYS:
            val = arguments.get(key)
            if isinstance(val, str):
                found.append(val)
            elif isinstance(val, list):
                found.extend(v for v in val if isinstance(v, str))
        return found

    def evaluate(self, tool: str, arguments: dict, cwd: Path) -> Decision:
        """Return a Decision. Order is fixed and deny always wins.

        deny_paths -> DLP -> egress -> credentials -> tool rule -> containment
        -> default.

        DLP and egress sit above the tool rule for the same reason deny_paths
        does: they must be unreachable by any allow rule. A tool being allowed
        says the *operation* is permitted, never that the *content* is.

        S3b: the egress step is skipped entirely for tools that do not declare
        `"egress": true`. DLP is not — a secret in a write payload is a
        disclosure whatever the destination, and the file it lands in is read
        by something eventually.
        """
        args = arguments if isinstance(arguments, dict) else {}
        raw_paths = self.extract_paths(args)
        resolved = [safe_resolve(p, cwd) for p in raw_paths]
        shown = tuple(str(p) for p in resolved)

        # 0. Kill switch (C10). Before everything, including deny_paths: when a
        # human has hit stop, Aegis should not be evaluating rules at all, and
        # the reason recorded should be "stopped", not whichever rule the call
        # happened to trip first. One stat() per call, never cached.
        if killswitch.is_engaged(self.killswitch_path):
            why = killswitch.reason(self.killswitch_path)
            return Decision(
                Effect.DENY,
                "Aegis kill switch is engaged; every tool call is denied until it "
                "is released with aegis-resume" + (f" (reason: {why})" if why else ""),
                "killswitch",
                tool,
                shown,
            )

        # 1. Explicit deny globs. Highest precedence, checked before anything else.
        for pattern in self.deny_paths:
            for p in resolved:
                if fnmatch.fnmatch(str(p), pattern) or fnmatch.fnmatch(p.name, pattern):
                    return Decision(
                        Effect.DENY,
                        f"path matches deny rule {pattern!r}",
                        "deny_paths",
                        tool,
                        shown,
                    )

        # One traversal feeds both content controls, so they cannot disagree
        # about what the arguments contained. An argument tree too large to
        # scan completely is denied rather than partially scanned.
        try:
            strings = egress.walk_strings(args)
        except egress.ScanLimitExceeded as exc:
            return Decision(
                Effect.DENY,
                f"arguments could not be scanned completely ({exc}); failing closed",
                "scan_limit",
                tool,
                shown,
            )

        # 2. Secrets in arguments (C5, partial). Pattern name only — the value
        # is never carried into the Decision, which is written to the audit db
        # and shown to the model.
        secret = dlp.scan(strings)
        if secret is not None:
            return Decision(Effect.DENY, secret.reason(), "dlp", tool, shown)

        # 3. Egress destinations (C4, partial). Deny-by-default allowlist, but
        # only for tools that declare they fetch. A URL inside a file being
        # written is not a destination, and treating it as one denied ordinary
        # README edits in S3a — a control widened until it is turned off buys
        # nothing (D4).
        if self.tool_does_egress(tool):
            url = egress.check(strings, self.allowed_domains)
            if url is not None:
                return Decision(
                    Effect.DENY,
                    f"URL {url.scheme}://{url.host} in {url.where}: {url.reason}",
                    "egress_domain",
                    tool,
                    shown,
                )

        # 4. Credential handles (C6). Authorization only — the value is not
        # read here, and must not be: this call may still be denied below, and
        # a secret fetched for a call that is never sent is a secret exposed
        # for no reason.
        handles = broker.find_handles(args)
        if handles:
            refusal = self.authorize_credentials(tool, handles, strings)
            if refusal is not None:
                return Decision(Effect.DENY, refusal, "credential_denied", tool, shown)

        # 5. Tool must be named in policy. Unknown tool -> default (never allow).
        rule = self.tool_rules.get(tool)
        if rule is None:
            return self._default(tool, shown, f"tool {tool!r} not present in tool_rules")

        effect = Effect(rule["effect"])
        if effect is Effect.DENY:
            return Decision(Effect.DENY, "tool is denied by policy", f"tool_rules.{tool}", tool, shown)

        # 6. Containment. Every path in the call must sit inside an allowed root,
        # or be covered by a folder rule that permits it (S10).
        if resolved:
            allowed_roots = self._roots_for(rule)
            needs_ask: Path | None = None
            for p in resolved:
                folder = self.folder_rule_for(p)
                if folder is not None and folder[1] is Effect.DENY:
                    return Decision(
                        Effect.DENY,
                        f"path {p} is inside {folder[0]}, which is set to Deny",
                        "folder_rules",
                        tool,
                        shown,
                    )
                if folder is not None and folder[1] is Effect.ASK and needs_ask is None:
                    needs_ask = folder[0]
                permitted = any(_within(p, root) for root in allowed_roots) or (
                    folder is not None and folder[1] in (Effect.ALLOW, Effect.ASK)
                )
                if not permitted:
                    return Decision(
                        Effect.DENY,
                        f"path {p} is outside every allowed root for this tool",
                        f"tool_rules.{tool}.within",
                        tool,
                        shown,
                    )
            if needs_ask is not None:
                # Reuses C7 entirely: the prompt, the timeout-to-deny and the
                # no-tty denial are S5's, unchanged. This only decides that a
                # human should be asked, never how the asking works.
                return Decision(
                    self._ask_or_deny(),
                    f"path is inside {needs_ask}, which is set to Ask",
                    "folder_rules",
                    tool,
                    shown,
                )

        # 7. Bulk threshold (C8). Placed here, above every path that can return
        # ALLOW, so an allow rule cannot skip it. It sits *below* the deny
        # checks on purpose: a call that policy already refuses should be
        # refused, not put in front of a human. Escalating a denial to a prompt
        # would spend the approval budget (D4) on calls whose answer is already
        # known, which is how prompts get clicked through without reading.
        if len(resolved) > self.bulk_threshold:
            return Decision(
                self._ask_or_deny(),
                f"call touches {len(resolved)} paths, above the bulk threshold of "
                f"{self.bulk_threshold}; a human should confirm an operation this "
                f"wide even though {tool!r} is otherwise permitted",
                "bulk_operation",
                tool,
                shown,
            )

        if effect is Effect.ASK:
            return Decision(
                self._ask_or_deny(),
                "policy marks this tool as requiring human approval",
                f"tool_rules.{tool}",
                tool,
                shown,
            )

        return Decision(Effect.ALLOW, "matched allow rule", f"tool_rules.{tool}", tool, shown)

    def _ask_or_deny(self) -> Effect:
        """ASK unless the operator has explicitly asked for headless denial."""
        return Effect.ASK if self.ask_behavior is Effect.ASK else Effect.DENY

    def _roots_for(self, rule: dict) -> tuple[Path, ...]:
        within = rule.get("within")
        if not within:
            return self.workspace_roots
        out: list[Path] = []
        for entry in within:
            if entry == "<workspace>":
                out.extend(self.workspace_roots)
            else:
                out.append(Path(entry).expanduser().resolve())
        return tuple(out)

    def _default(self, tool: str, shown: tuple[str, ...], why: str) -> Decision:
        effect = self.default_effect
        if effect is Effect.ASK:
            effect = self.ask_behavior
        return Decision(effect, why, "default_effect", tool, shown)
