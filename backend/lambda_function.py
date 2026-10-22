"""
PHP2Shell Scanner backend  -  AWS Lambda (Python 3.12), Function URL or API Gateway.

WHAT IT DOES
  Given ?url=<target>, fetches that URL server-side (no browser CORS), reads the
  response banner headers (Server, X-Powered-By, Set-Cookie), and returns JSON the
  static frontend turns into a verdict. Passive only: a single GET, no redirects
  followed, no payload, no multipart probe, no memory-corruption attempt.

WHY A BACKEND
  A static S3 page cannot read another origin's headers (same-origin policy). The
  fetch must run server-side. This Lambda is that server side.

SECURITY  (this endpoint fetches user-supplied URLs, so it MUST be guarded)
  - SSRF defense: resolves the host and refuses private, loopback, link-local,
    CGNAT (100.64/10), multicast/reserved, and cloud-metadata (169.254.169.254 /
    fd00:ec2::254) addresses, including IPv4-mapped IPv6.
  - http/https only; credentials in the URL rejected; no redirects chased.
  - Hard timeout, response-size cap, header-only use of the response.
  - CORS locked to your site origin via the ALLOWED_ORIGIN env var.
  - Put AWS WAF rate-limiting in front for public deployments (see DEPLOY.md).
  Note: validate-then-connect leaves a small DNS-rebinding window; network
  isolation (don't give the Lambda a route to internal subnets) is the real control.

Dependencies: none (standard library only). No layer or pip install needed.

ENV
  ALLOWED_ORIGIN    e.g. https://scanner.example.com   (default "*", tighten this)
  FETCH_TIMEOUT_MS  default 8000
  MAX_BYTES         default 65536

Handler: lambda_function.lambda_handler
"""

import ipaddress
import json
import os
import socket
import urllib.request
import urllib.error
from urllib.parse import urlsplit

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
TIMEOUT = max(1.0, int(os.environ.get("FETCH_TIMEOUT_MS", "8000")) / 1000.0)
MAX_BYTES = int(os.environ.get("MAX_BYTES", "65536"))
USER_AGENT = "PHP2Shell-Scanner/1.0 (+defensive version check)"


def _cors_headers():
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "content-type",
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
    }


def _reply(status, body):
    return {"statusCode": status, "headers": _cors_headers(), "body": json.dumps(body)}


# ---- SSRF guard ---------------------------------------------------------
def _ip_is_disallowed(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable: refuse

    # Unwrap IPv4-mapped / 6to4 / teredo IPv6 to inspect the embedded v4.
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _ip_is_disallowed(str(ip.ipv4_mapped))
        if getattr(ip, "sixtofour", None):
            return _ip_is_disallowed(str(ip.sixtofour))
        # IMDSv6
        if ip in ipaddress.ip_network("fd00:ec2::/32"):
            return True

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local      # covers 169.254.0.0/16 incl. 169.254.169.254
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Carrier-grade NAT 100.64.0.0/10 (not flagged by is_private on all versions).
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True

    return False


def _assert_public_host(hostname):
    # Literal IP in the URL.
    try:
        ipaddress.ip_address(hostname)
        if _ip_is_disallowed(hostname):
            raise ValueError("destination is a private/reserved address")
        return
    except ValueError as e:
        if "private/reserved" in str(e):
            raise
        # not a literal IP -> fall through to name checks

    low = hostname.lower().rstrip(".")
    if (
        low in ("localhost",)
        or low.endswith(".local")
        or low.endswith(".internal")
        or low.endswith(".localdomain")
        or "." not in low
    ):
        raise ValueError("destination hostname is not public")

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

    addrs = {info[4][0] for info in infos}
    if not addrs:
        raise ValueError("no addresses resolved")
    for a in addrs:
        if _ip_is_disallowed(a):
            raise ValueError("destination resolves to a private/reserved address")


def _parse_target(raw):
    if not raw:
        raise ValueError("missing url parameter")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError("only http/https allowed")
    if parts.username or parts.password:
        raise ValueError("credentials in url are not allowed")
    if not parts.hostname:
        raise ValueError("invalid url")
    return parts


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # do not follow; the 3xx surfaces as an HTTPError we read below


_opener = urllib.request.build_opener(_NoRedirect)


def _headers_payload(status, headers):
    server = headers.get("Server")
    xpb = headers.get("X-Powered-By")
    try:
        set_cookies = headers.get_all("Set-Cookie") or []
    except Exception:
        sc = headers.get("Set-Cookie")
        set_cookies = [sc] if sc else []

    lines = ["HTTP {}".format(status)]
    if server:
        lines.append("server: {}".format(server))
    if xpb:
        lines.append("x-powered-by: {}".format(xpb))
    for c in set_cookies:
        lines.append("set-cookie: {}".format(c))

    return {
        "ok": True,
        "status": status,
        "headers": {"server": server, "x-powered-by": xpb},
        "setCookies": set_cookies,
        "headersText": "\n".join(lines),
    }


def lambda_handler(event, context=None):
    event = event or {}
    method = (
        (event.get("requestContext", {}).get("http", {}) or {}).get("method")
        or event.get("httpMethod")
        or "GET"
    )
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    qs = event.get("queryStringParameters") or {}
    raw = qs.get("url")

    try:
        parts = _parse_target(raw)
        _assert_public_host(parts.hostname)
    except ValueError as e:
        return _reply(400, {"ok": False, "error": str(e)})

    req = urllib.request.Request(
        parts.geturl(), method="GET", headers={"User-Agent": USER_AGENT}
    )
    try:
        try:
            resp = _opener.open(req, timeout=TIMEOUT)
            status, headers = resp.getcode(), resp.headers
            try:
                resp.read(MAX_BYTES)  # drain a bounded slice; body is not parsed
            except Exception:
                pass
            resp.close()
        except urllib.error.HTTPError as he:
            # 3xx (not followed), 4xx, 5xx: still carry the banner headers.
            status, headers = he.code, he.headers
        return _reply(200, _headers_payload(status, headers))
    except socket.timeout:
        return _reply(200, {"ok": False, "error": "request timed out"})
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        msg = "request timed out" if isinstance(reason, socket.timeout) else str(reason)
        return _reply(200, {"ok": False, "error": msg})
    except Exception as e:  # noqa: BLE001
        return _reply(200, {"ok": False, "error": str(e)})
