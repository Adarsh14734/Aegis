"""Aegis S3a — MCP-layer egress control. Partial C4.

Extracts every URL from a `tools/call` argument tree and checks its host
against a deny-by-default allowlist, with SSRF rejection of IP literals and
private/loopback/link-local targets.

WHAT THIS IS NOT. C4 in THREAT-MODEL.md is a TLS-terminating egress proxy.
This is not that, and must never be described as that. D3 already says it:
"Filtering on the client-supplied hostname without inspecting TLS can be
defeated by domain fronting." This module reads a hostname out of a tool
argument and believes it. It constrains what a *tool call* can be pointed at.
It does not constrain what the server does once the call is forwarded, and it
sees nothing at all about a request the agent makes by some other route.

Concretely, this control is blind to:
  - an allowed tool that fetches a URL it derived itself, or follows a redirect
  - a server that resolves an allowed hostname to an attacker-controlled IP
    (DNS rebinding — no resolution happens here, by design; see below)
  - any request not expressed as a URL in a tool argument

Deny-by-default: an absent `allowed_domains` key is the empty list, and the
empty list denies every URL. Absence never means permissive (C2).

No DNS resolution happens at policy time. Resolving would make policy
evaluation depend on a network service the agent may influence, would add
latency to every call, and would still be a TOCTOU window — the address
checked is not the address later dialled. So the SSRF checks here are purely
lexical: they reject hosts that are *written* as an IP literal or as
localhost. A hostname whose DNS record points at 169.254.169.254 is NOT
caught. That gap closes only in C4 proper, at the socket.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Bounded traversal. A tool argument tree deep or wide enough to hit these is
# not a shape any real MCP server produces, so hitting them is itself
# suspicious and the caller denies rather than scanning a subset.
MAX_DEPTH = 16
MAX_STRINGS = 5000
MAX_STRING_LEN = 1_000_000

# Any scheme with an authority component: http://, file://, gopher://, ftp://,
# ws://, jar:file://... The '//' is what makes this safe to match greedily —
# requiring it is why 'TODO: fix this' and '{"note": "x"}' are not URLs.
URL_RE = re.compile(r"""[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>\\`\[\]{}|^]+""")

# data: is the one opaque scheme worth matching, because it is a real
# exfiltration and payload-smuggling carrier. RFC 2397 shape is required — a
# mediatype containing '/' or a ';base64' parameter, then a mandatory comma,
# with no whitespace anywhere before it. Compact JSON such as {"data":1,"x":2}
# must not look like a data URL, and with this shape it does not.
DATA_URL_RE = re.compile(r"data:(?:[\w.+-]+/[\w.+-]+)?(?:;[\w.+-]+)*,\S", re.IGNORECASE)

# Other opaque schemes (javascript:, blob:, view-source:) are deliberately NOT
# matched. They carry no fetch semantics at the MCP layer, and matching them
# would deny any tool call whose content contains href="javascript:void(0)" —
# a false positive with a real cost and no corresponding threat. Recorded here
# so the omission reads as a decision rather than an oversight.

# Trailing punctuation that is almost always prose, not part of the URL.
_TRAILING = ".,;:!?)\"'>"


class ScanLimitExceeded(Exception):
    """Argument tree too deep/large to scan completely. Caller fails closed."""


@dataclass(frozen=True)
class Finding:
    """A URL that policy rejects. `where` is the argument path, `host` and
    `scheme` are safe to log; the full URL deliberately is not — query strings
    routinely carry tokens, and this reason string is written to the audit db
    and shown to the model in the denial frame."""

    where: str
    scheme: str
    host: str
    reason: str


def walk_strings(obj, path: str = "arguments", depth: int = 0):
    """Yield (argument_path, string) for every string anywhere in the tree.

    Shared traversal: policy.py walks once and hands the result to both the
    DLP scan and the egress check, so the two controls cannot disagree about
    what the arguments contained.
    """
    out: list[tuple[str, str]] = []
    _walk(obj, path, depth, out)
    return out


def _walk(obj, path: str, depth: int, out: list) -> None:
    if depth > MAX_DEPTH:
        raise ScanLimitExceeded(f"argument tree deeper than {MAX_DEPTH} levels at {path}")
    if len(out) > MAX_STRINGS:
        raise ScanLimitExceeded(f"more than {MAX_STRINGS} strings in arguments")

    if isinstance(obj, str):
        if len(obj) > MAX_STRING_LEN:
            raise ScanLimitExceeded(f"string at {path} exceeds {MAX_STRING_LEN} bytes")
        out.append((path, obj))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            _walk(value, f"{path}.{key}", depth + 1, out)
    elif isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            _walk(value, f"{path}[{i}]", depth + 1, out)
    # numbers, booleans and null carry no URL and no secret


def extract_urls(strings) -> list[tuple[str, str]]:
    """[(argument_path, url)] for every URL-like substring. A single string may
    contain several — prose, HTML and JSON blobs routinely do."""
    found: list[tuple[str, str]] = []
    for where, text in strings:
        for match in URL_RE.finditer(text):
            found.append((where, match.group(0).rstrip(_TRAILING)))
        for match in DATA_URL_RE.finditer(text):
            found.append((where, match.group(0)))
    return found


def normalize_domain(entry: str) -> str:
    return entry.strip().lower().strip(".")


def parse_ip_literal(host: str):
    """Return an ip_address if `host` is written as one, else None.

    Covers the encodings an allowlist check is expected to miss:
    dotted-quad, IPv6 (with or without a zone id), IPv4-mapped IPv6, and the
    integer forms — http://2130706433/ and http://0x7f000001/ are both
    127.0.0.1 and both defeat a naive string comparison.
    """
    h = host.strip("[]").split("%")[0]
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
            value = int(h, 16)
        elif re.fullmatch(r"0[0-7]+", h):
            value = int(h, 8)
        elif re.fullmatch(r"\d+", h):
            value = int(h, 10)
        else:
            return None
        if 0 <= value <= 0xFFFFFFFF:
            return ipaddress.ip_address(value)
    except ValueError:
        pass
    return None


def looks_numeric(host: str) -> bool:
    """A host whose rightmost label is all digits or hex cannot be a DNS name —
    no TLD is numeric (RFC 3696). Catches the short forms ipaddress rejects but
    the C resolver accepts, such as http://127.1/."""
    last = host.strip(".").split(".")[-1]
    return bool(re.fullmatch(r"\d+|0[xX][0-9a-fA-F]+", last))


def ip_category(ip) -> str | None:
    """Name the reason this address is not a legitimate egress target."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback; the v6 flags miss it
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address (cloud instance metadata lives here)"
    if ip.is_private:
        return "private address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_multicast:
        return "multicast address"
    return None


def host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    """Exact match or subdomain. 'example.com' allows 'a.example.com' but must
    never allow 'notexample.com' — hence the leading dot."""
    host = normalize_domain(host)
    for entry in allowed:
        if host == entry or host.endswith("." + entry):
            return True
    return False


def check_url(where: str, url: str, allowed: tuple[str, ...]) -> Finding | None:
    """None if this URL may be forwarded, a Finding if it may not."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return Finding(where, "?", "?", f"URL could not be parsed ({exc}); failing closed")

    scheme = (parts.scheme or "").lower()

    if scheme not in ("http", "https"):
        return Finding(
            where, scheme, "",
            f"scheme {scheme!r} is not http/https; only those two can be "
            f"host-checked, so everything else is denied",
        )

    try:
        host = parts.hostname or ""
    except ValueError as exc:
        return Finding(where, scheme, "?", f"URL host could not be parsed ({exc}); failing closed")

    if not host:
        return Finding(where, scheme, "", "URL has no host")

    host = normalize_domain(host)

    # An explicitly listed host wins outright — that is how an operator opts
    # into a localhost service or a fixed IP. It is an exact-string opt-in:
    # subdomain semantics are not applied to addresses.
    explicitly_listed = host in allowed

    ip = parse_ip_literal(host)
    if ip is not None:
        if explicitly_listed:
            return None  # operator listed this exact address, private ones included
        category = ip_category(ip)
        return Finding(
            where, scheme, host,
            f"host is a raw IP literal"
            + (f" — {category}" if category else "")
            + "; list the address explicitly in allowed_domains to permit it",
        )

    if looks_numeric(host):
        return Finding(
            where, scheme, host,
            "host has an all-numeric rightmost label, so it is an "
            "abbreviated or encoded IP address, not a DNS name",
        )

    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        if explicitly_listed:
            return None
        return Finding(
            where, scheme, host,
            "host resolves to this machine (localhost/.local); list it "
            "explicitly in allowed_domains to permit it",
        )

    if not host_allowed(host, allowed):
        return Finding(
            where, scheme, host,
            "host is not in allowed_domains"
            if allowed
            else "allowed_domains is empty, so every URL is denied",
        )

    return None


def check(strings, allowed: tuple[str, ...]) -> Finding | None:
    """First rejected URL in the argument tree, or None. Deny wins, so the
    first Finding ends evaluation — the remaining URLs are not reported."""
    for where, url in extract_urls(strings):
        finding = check_url(where, url, allowed)
        if finding is not None:
            return finding
    return None
