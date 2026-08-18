"""Aegis S8 — Aegis as the HTTP client. C4 and C6.

Until S8, an egress tool call was *inspected* and then forwarded: Aegis read a
URL out of an argument, checked the hostname it found there, and handed the
whole thing to the MCP server to fetch. S3a-REPORT.md §What this is not lists
what that buys and what it does not, and the summary is that it constrains what
a tool call can be *pointed at* and nothing else. Three holes follow directly:

  - **TOCTOU.** The host checked was never the host dialled. Nothing stopped
    the name resolving to 169.254.169.254 a millisecond later.
  - **Redirects.** An allowed host answering `302 Location: http://evil/` was
    invisible; the server followed it and Aegis never knew.
  - **The credential.** S4 substituted the plaintext into the arguments and gave
    them to the server, which THREAT-MODEL.md §3 names as adversary T3.

This module closes those by doing the request itself. The MCP server is not
involved in an egress call at all: it never sees the URL, never sees the
credential, and never returns the response. That is what B4 asks for —
"the broker performs the operation; the agent receives a result".

THE THREE PROPERTIES THIS FILE EXISTS FOR

  1. **The address checked is the address dialled.** `resolve()` calls
     getaddrinfo exactly once. Every address it returns is checked. The socket
     is then opened to that literal address, with the original hostname
     presented as SNI and in the Host header, and TLS validated against the
     hostname. There is no second resolution for anyone to race.

  2. **Every redirect hop is a new decision.** Hops are followed one at a time,
     by us, and each one re-runs the entire check: allowlist, resolution, IP
     category, and — if a credential is in play — the credential's own host
     grant. A hop to a denied host is a *denial* with a reason, not a silent
     stop at the previous response.

  3. **The credential is attached here or not at all.** It goes into the
     outbound HTTP request and into nothing else.

WHAT IS STILL NOT TRUE (read S8-REPORT.md before describing this as C4)

  - This is not a TLS-terminating proxy and does not inspect anyone else's
    traffic. It controls requests *Aegis makes*. A server that fetches on its
    own, or a Bash tool with curl, is exactly as far outside the boundary as it
    was in S1.
  - Domain fronting is not addressed by anything here, and D3 is the reason C4
    was specified as TLS-terminating in the first place.
  - The response body is returned to the model unscanned.
"""

import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

try:  # S7 import plumbing: package when installed, flat when run as a script
    from . import broker, egress
except ImportError:  # pragma: no cover - exercised by python3 aegis/proxy.py
    import broker
    import egress

# One hop more than five is denied. Five is enough for every legitimate chain
# anyone has ever needed and short enough that a loop cannot be used to burn
# time or to walk a chain of hosts hoping one of them is allowed.
MAX_REDIRECTS = 5

# Read cap. A response larger than this is truncated and said to be truncated:
# the alternative is an MCP frame big enough to be its own denial of service,
# and a model that silently receives half a document is worse than one told the
# document was cut.
MAX_RESPONSE_BYTES = 5_000_000

CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 30.0

ALLOWED_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")

# The argument contract. An egress tool call must name its destination in `url`
# and may carry the rest. Aegis has to build a real HTTP request out of these,
# so a call it cannot build one from is denied rather than forwarded — see
# `describe_contract()` for what the denial says.
URL_KEYS = ("url",)
METHOD_KEYS = ("method",)
HEADER_KEYS = ("headers",)
BODY_KEYS = ("body", "data")


class FetchError(Exception):
    """A request could not be performed. Never carries a secret: every message
    built on the substituted path is scrubbed before it is raised."""


@dataclass(frozen=True)
class Outcome:
    """The result of an egress call, as both the model and the audit see it.

    `host` is the host actually connected to at the last hop, not the one the
    model asked for. On a chain that ends in a denial it is the host that was
    refused — which is the one worth recording.
    """

    allowed: bool
    rule_id: str
    reason: str
    host: str | None = None
    status: int | None = None
    req_bytes: int | None = None
    resp_bytes: int | None = None
    body: str = ""
    hops: tuple[str, ...] = ()
    truncated: bool = False

    def summary(self) -> str:
        chain = " -> ".join(self.hops) if len(self.hops) > 1 else ""
        return (
            f"Aegis performed the request: {self.host} status {self.status}, "
            f"{self.req_bytes} bytes sent, {self.resp_bytes} bytes received"
            + (f"; redirects followed: {chain}" if chain else "")
            + ("; response truncated at the read cap" if self.truncated else "")
        )


# ---------------------------------------------------------------------------
# resolution — the whole point of the sprint
# ---------------------------------------------------------------------------


@dataclass
class Destination:
    host: str
    port: int
    https: bool
    addresses: tuple = field(default_factory=tuple)

    @property
    def dial(self) -> str:
        return str(self.addresses[0])


def resolve(host: str, port: int, resolver=None) -> tuple:
    """Every address `host` currently resolves to. Raises FetchError on failure.

    `resolver` exists so the suite can drive a name onto a chosen address
    without owning DNS. It is not a bypass: whatever it returns goes through
    exactly the same address checks as a real answer, and production passes
    nothing, so the default is `socket.getaddrinfo`.
    """
    getaddrinfo = resolver or socket.getaddrinfo
    try:
        infos = getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, socket.gaierror) as exc:
        raise FetchError(f"could not resolve {host!r}: {exc}") from None
    out = []
    for info in infos:
        sockaddr = info[4]
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not out:
        raise FetchError(f"{host!r} resolved to no usable address")
    return tuple(out)


def address_refusal(ip, allowed: tuple[str, ...]) -> str | None:
    """Why this resolved address may not be connected to, or None.

    The explicit-listing escape is the same one `egress.check_url` already
    applies to an IP written directly into a URL: an operator who puts
    `127.0.0.1` in `allowed_domains` has opted into a local service on purpose,
    and refusing them would just push them to turn the control off. It is an
    exact-string opt-in — subdomain semantics never apply to an address.
    """
    category = egress.ip_category(ip)
    if category is None:
        return None
    if str(ip) in allowed:
        return None
    return (
        f"{host_label(ip)} is a {category}; Aegis will not connect to it. "
        f"List the address itself in allowed_domains if that is deliberate."
    )


def host_label(ip) -> str:
    return f"[{ip}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)


def check_destination(url: str, allowed: tuple[str, ...], resolver=None):
    """(Destination, None) if this URL may be dialled, else (None, reason).

    Two checks, in this order and never merged:

      1. The **written** host, against the allowlist and the lexical SSRF rules
         from S3a. Cheap, and it means a denied destination never causes a DNS
         lookup — a lookup is itself a signal sent to a name the agent chose.
      2. The **resolved** addresses. This is the check S3a could not make and
         said so: "no DNS resolution happens at policy time... the address
         checked is not the address later dialled". Here it is, and the address
         that passes is the one handed to `socket.create_connection`.
    """
    finding = egress.check_url("url", url, allowed)
    if finding is not None:
        return None, f"{finding.scheme}://{finding.host}: {finding.reason}"

    parts = urlsplit(url)
    https = parts.scheme.lower() == "https"
    host = egress.normalize_domain(parts.hostname or "")
    try:
        port = parts.port or (443 if https else 80)
    except ValueError:
        return None, f"{host}: port is not a number"

    try:
        addresses = resolve(host, port, resolver)
    except FetchError as exc:
        return None, str(exc)

    # Every address, not just the one about to be dialled. A name answering
    # with one public and one private address is a rebinding attack wearing a
    # round-robin costume, and picking the good one would be luck.
    for ip in addresses:
        refusal = address_refusal(ip, allowed)
        if refusal is not None:
            return None, f"{host} resolves to {refusal}"

    return Destination(host, port, https, addresses), None


# ---------------------------------------------------------------------------
# byte counting
# ---------------------------------------------------------------------------


class _CountingSocket:
    """Counts the plaintext HTTP bytes crossing a socket, in both directions.

    Wrapping the socket rather than reconstructing the request from its parts:
    `http.client` adds headers of its own (Host, Accept-Encoding,
    Content-Length, Connection) and a reconstruction would be a guess at what
    it did. These are the bytes actually written and actually read. For a TLS
    connection this is the plaintext inside the tunnel, which is the number
    worth recording — TLS record overhead says nothing about what was sent.
    """

    def __init__(self, sock):
        self._sock = sock
        self.sent = 0
        self.received = 0

    def sendall(self, data, *args):
        self.sent += len(data)
        return self._sock.sendall(data, *args)

    def send(self, data, *args):
        n = self._sock.send(data, *args)
        self.sent += n
        return n

    def makefile(self, mode="rb", *args, **kwargs):
        return _CountingReader(self._sock.makefile(mode, *args, **kwargs), self)

    def close(self):
        return self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)


class _CountingReader:
    def __init__(self, fp, counter: _CountingSocket):
        self._fp = fp
        self._counter = counter

    def read(self, *args):
        data = self._fp.read(*args)
        self._counter.received += len(data or b"")
        return data

    def readline(self, *args):
        data = self._fp.readline(*args)
        self._counter.received += len(data or b"")
        return data

    def readinto(self, buffer):
        n = self._fp.readinto(buffer)
        self._counter.received += n or 0
        return n

    def close(self):
        return self._fp.close()

    def __getattr__(self, name):
        return getattr(self._fp, name)


# ---------------------------------------------------------------------------
# one hop
# ---------------------------------------------------------------------------


@dataclass
class Hop:
    status: int
    headers: dict
    body: bytes
    req_bytes: int
    resp_bytes: int
    truncated: bool


def send_once(dest: Destination, method: str, url: str, headers: dict, body) -> Hop:
    """One HTTP request to an address already cleared by `check_destination`.

    The socket is opened to `dest.dial` — the literal address that was checked
    — and the hostname is used for three things only: SNI, certificate
    validation, and the Host header. There is no second name lookup anywhere in
    this function, which is the entire TOCTOU fix.
    """
    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query

    raw = None
    try:
        # Connecting is inside the try: a refused connection is an ordinary
        # outcome of dialling an address, and it has to come back as a
        # FetchError the caller can record, not as an OSError escaping into
        # the proxy's pump.
        raw = socket.create_connection((dest.dial, dest.port), timeout=CONNECT_TIMEOUT)
        if dest.https:
            context = ssl.create_default_context()
            # check_hostname against the *name*, not the address we dialled: the
            # point is to prove the address is genuinely serving that name.
            sock = context.wrap_socket(raw, server_hostname=dest.host)
        else:
            sock = raw
        sock.settimeout(READ_TIMEOUT)
        counting = _CountingSocket(sock)

        conn = http.client.HTTPConnection(dest.host, dest.port, timeout=READ_TIMEOUT)
        conn.sock = counting  # already connected; http.client must not dial again
        try:
            conn.request(method, target, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(payload) > MAX_RESPONSE_BYTES
            if truncated:
                payload = payload[:MAX_RESPONSE_BYTES]
            return Hop(
                status=response.status,
                headers={k.lower(): v for k, v in response.getheaders()},
                body=payload,
                req_bytes=counting.sent,
                resp_bytes=counting.received,
                truncated=truncated,
            )
        finally:
            conn.close()
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}") from None
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# the call
# ---------------------------------------------------------------------------


def describe_contract() -> str:
    return (
        "An egress tool call must name its destination so Aegis can make the "
        "request itself: arguments.url (a string), optionally arguments.method "
        f"(one of {', '.join(ALLOWED_METHODS)}), arguments.headers (an object of "
        "strings) and arguments.body or arguments.data (a string)."
    )


def read_call(arguments: dict):
    """(method, url, headers, body) or raise FetchError describing the shape.

    A call Aegis cannot build a request from is denied by the caller. It is not
    forwarded to the server as a fallback: forwarding is the S3a behaviour this
    sprint exists to replace, and for a call carrying a credential it is the
    exact disclosure S4 was unable to prevent."""
    url = arguments.get("url")
    if not isinstance(url, str) or not url.strip():
        raise FetchError(
            "no 'url' string in the arguments, so Aegis cannot perform this "
            "request itself. " + describe_contract()
        )

    method = arguments.get("method", "GET")
    if not isinstance(method, str) or method.upper() not in ALLOWED_METHODS:
        raise FetchError(
            f"method {method!r} is not one of {', '.join(ALLOWED_METHODS)}"
        )

    headers = arguments.get("headers") or {}
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ):
        raise FetchError("'headers' must be an object of string to string")

    body = None
    for key in BODY_KEYS:
        value = arguments.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise FetchError(f"{key!r} must be a string")
            body = value.encode("utf-8")
            break

    return method.upper(), url.strip(), dict(headers), body


def credential_hosts(policy, handles) -> dict:
    """{handle: allowed hosts} for the handles this call carries.

    Read straight off the loaded policy rather than through
    `authorize_credentials`, which answers a different question (may this call
    proceed) and answers it about the arguments. Here the question is asked
    again at every redirect hop, about a host the arguments never mentioned.
    """
    out = {}
    for handle in handles:
        grant = policy.credentials.get(handle) or {}
        out[handle] = tuple(grant.get("hosts") or ())
    return out


def perform(tool: str, arguments: dict, policy, redactor=None, resolver=None) -> Outcome:
    """Make the request Aegis was asked to make, and report what happened.

    Called only after the policy chain has returned ALLOW, so the destination
    and the credential grant have already been checked against the arguments.
    Everything here re-checks them against reality: the resolved address, and
    every host a redirect moves us to.
    """
    try:
        method, url, headers, body = read_call(arguments)
    except FetchError as exc:
        return Outcome(False, "egress_not_performable", str(exc))

    handles = [h for _, h in broker.find_handles(arguments)]
    grants = credential_hosts(policy, handles)
    allowed = policy.allowed_domains

    hops: list[str] = []
    secrets_resolved: dict = {}

    for hop_index in range(MAX_REDIRECTS + 1):
        dest, refusal = check_destination(url, allowed, resolver)
        if refusal is not None:
            where = "destination" if hop_index == 0 else f"redirect hop {hop_index}"
            return Outcome(
                False,
                "egress_domain" if hop_index == 0 else "egress_redirect",
                f"{where} refused: {refusal}"
                + (f" (after {' -> '.join(hops)})" if hops else ""),
                host=_host_of(url),
                hops=tuple(hops),
            )

        # A credential may only travel to a host its own grant names, at every
        # hop and not just the first. An allowed host that redirects to another
        # allowed host is fine for the request and not fine for the secret.
        for handle, hosts in grants.items():
            if not egress.host_allowed(dest.host, hosts):
                return Outcome(
                    False,
                    "credential_denied" if hop_index == 0 else "credential_redirect",
                    f"credential handle {handle!r} is not permitted for host "
                    f"{dest.host!r}"
                    + (
                        f"; the request was redirected there from {hops[0]} and "
                        f"Aegis will not carry a credential to a host it was not "
                        f"granted for"
                        if hop_index
                        else ""
                    ),
                    host=dest.host,
                    hops=tuple(hops),
                )

        hops.append(dest.host)

        # Resolve the secrets only now: the destination for this hop is cleared,
        # so a request that was never going to be sent has not caused a keychain
        # read. Same ordering rule as S4 (S4-REPORT.md §Evaluation order).
        if handles and not secrets_resolved:
            try:
                filled_headers, secrets_resolved = broker.substitute(
                    headers, redactor=redactor
                )
                filled_url, more = broker.substitute(url, redactor=redactor)
                secrets_resolved.update(more)
                filled_body = body
                if body is not None:
                    text, more = broker.substitute(
                        body.decode("utf-8", "surrogateescape"), redactor=redactor
                    )
                    secrets_resolved.update(more)
                    filled_body = text.encode("utf-8", "surrogateescape")
            except broker.BrokerError as exc:
                return Outcome(
                    False, "credential_unavailable",
                    f"credential could not be resolved: {exc}",
                    host=dest.host, hops=tuple(hops),
                )
            headers, url, body = filled_headers, filled_url, filled_body
            dest, refusal = check_destination(url, allowed, resolver)
            if refusal is not None:
                # A handle inside the URL can move the destination. Whatever it
                # moved it to gets checked before anything is dialled.
                return Outcome(
                    False, "egress_domain",
                    f"destination refused after credential substitution: {refusal}",
                    hops=tuple(hops),
                )

        try:
            hop = send_once(dest, method, url, headers, body)
        except FetchError as exc:
            return Outcome(
                False, "egress_failed",
                _scrub(f"request to {dest.host} failed: {exc}", secrets_resolved),
                host=dest.host, hops=tuple(hops),
            )

        location = hop.headers.get("location")
        if hop.status in (301, 302, 303, 307, 308) and location:
            if hop_index >= MAX_REDIRECTS:
                return Outcome(
                    False, "egress_redirect_limit",
                    f"more than {MAX_REDIRECTS} redirects: "
                    f"{' -> '.join(hops)} -> (refused). A chain this long is "
                    f"either a loop or an attempt to walk to a host that would "
                    f"not have been allowed directly.",
                    host=dest.host, status=hop.status,
                    req_bytes=hop.req_bytes, resp_bytes=hop.resp_bytes,
                    hops=tuple(hops),
                )
            url = urljoin(url, location)
            if hop.status == 303 or (hop.status in (301, 302) and method not in ("GET", "HEAD")):
                method, body = "GET", None
                headers = {k: v for k, v in headers.items()
                           if k.lower() not in ("content-type", "content-length")}
            continue

        text = hop.body.decode("utf-8", "replace")
        echoed = {}
        if redactor is not None:
            text, echoed = redactor.redact(text)
        if hop.truncated:
            text += f"\n\n[aegis: response truncated at {MAX_RESPONSE_BYTES} bytes]"

        used = ", ".join(sorted(secrets_resolved))
        note = ""
        if used:
            # The handle NAME, never the value — the same rule S4 established
            # and the reason the audit can say which credential was spent.
            note += f"; used credential handle(s) {used}"
        if echoed:
            note += (
                "; the response echoed the credential back "
                + ", ".join(f"{h} x{n}" for h, n in sorted(echoed.items()))
                + " and it was redacted before the model saw it"
            )
        return Outcome(
            allowed=True,
            rule_id=f"tool_rules.{tool}",
            reason="matched allow rule; request performed by Aegis" + note,
            host=dest.host,
            status=hop.status,
            req_bytes=hop.req_bytes,
            resp_bytes=hop.resp_bytes,
            body=text,
            hops=tuple(hops),
            truncated=hop.truncated,
        )

    # Unreachable: the loop returns on every path. Kept as a hard stop rather
    # than a fall-through that would look like success.
    return Outcome(False, "egress_redirect_limit", "redirect loop exhausted", hops=tuple(hops))


def _host_of(url: str) -> str | None:
    try:
        return egress.url_host(url)
    except ValueError:
        return None


def _scrub(text: str, secrets: dict) -> str:
    for value in secrets.values():
        if value:
            text = text.replace(value, "[AEGIS-REDACTED]")
    return text


def result_frame(request_id, outcome: Outcome) -> dict:
    """The MCP result the model receives. The server is never involved."""
    text = outcome.body
    if outcome.status is not None and outcome.status >= 400:
        text = f"HTTP {outcome.status} from {outcome.host}\n\n{text}"
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": bool(outcome.status and outcome.status >= 400),
        },
    }


def denial_text(tool: str, outcome: Outcome) -> str:
    lines = [
        f"AEGIS DENIED: {tool}",
        f"Reason: {outcome.reason}",
        f"Rule: {outcome.rule_id}",
    ]
    if outcome.hops:
        lines.append("Hops: " + " -> ".join(outcome.hops))
    lines.append(
        "Aegis performs egress requests itself; this one was not performed and "
        "nothing was sent to the destination."
    )
    return "\n".join(lines)


def json_headers(headers: dict) -> str:
    """Header names only, for logging. Values carry credentials."""
    return json.dumps(sorted(headers))
