"""Low-level request security: API-key extraction, admin access, SSRF-safe remote image fetch."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import os
from urllib.parse import urlsplit

import httpx
from fastapi import Request

from virodh.openai_compat import BadRequest

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def api_key_from(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (request.headers.get("x-api-key") or request.headers.get("api-key") or "").strip()


def _is_loopback(request: Request) -> bool:
    """Direct loopback client AND a loopback Host header (blocks DNS-rebinding pages pretending to be local)."""
    client = request.client.host if request.client else ""
    try:
        direct = ipaddress.ip_address(client).is_loopback
    except ValueError:
        direct = False
    return direct and _host_only(request.headers.get("host") or "") in LOOPBACK_HOSTS


def _host_only(h: str) -> str:
    h = h.strip().lower()
    if h.startswith("["):  # [::1]:8000
        return h[: h.find("]") + 1]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def admin_denied(request: Request, admin_cfg: dict) -> tuple[int, str] | None:
    """None if the caller may use the admin/console API, else (status, message).

    - Every admin call must carry X-Virodh-Console: 1. Browsers cannot send a custom header cross-origin without
      a CORS preflight (which this server never approves), so other websites cannot drive the console (CSRF).
    - With VIRODH_ADMIN_TOKEN set, the token is accepted from anywhere; without it, only a direct loopback client
      is allowed (and only if allow_loopback_without_token)."""
    if request.headers.get("x-virodh-console") != "1":
        return 403, "missing X-Virodh-Console header"
    token = os.environ.get(admin_cfg.get("token_env", "VIRODH_ADMIN_TOKEN"), "")
    supplied = request.headers.get("x-virodh-admin-token", "")
    if token and supplied and hmac.compare_digest(token.encode(), supplied.encode()):
        return None
    if admin_cfg.get("allow_loopback_without_token", True) and _is_loopback(request):
        return None
    return 401, "admin token required (header X-Virodh-Admin-Token)"


def _public_ips(host: str, infos) -> bool:
    ips = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    return bool(ips) and all(ip.is_global and not ip.is_multicast for ip in ips)


async def fetch_remote_image(url: str, param: str, max_bytes: int, timeout: float) -> tuple[bytes, str]:
    """Fetch an http(s) image for inspection. Public addresses only, no redirects, size-capped, short timeout.
    The inspected bytes (not the URL) are what gets forwarded, so the server cannot swap the image afterwards.
    Residual risk: DNS rebinding between our resolve and connect (documented; remote images are off by default)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise BadRequest("invalid_image_url", "Only plain http(s) image URLs are accepted.", param)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(parts.hostname, port)
    except OSError:
        raise BadRequest("remote_image_failed", "Image host could not be resolved.", param) from None
    if not _public_ips(parts.hostname, infos):
        raise BadRequest("remote_image_blocked", "Image URL points to a private or reserved address.", param)
    try:
        headers = {"User-Agent": "VirodhGateway/1.0", "Accept": "image/*"}
        async with (
            httpx.AsyncClient(follow_redirects=False, timeout=timeout) as c,
            c.stream("GET", url, headers=headers) as r,
        ):
            if r.status_code != 200:
                raise BadRequest("remote_image_failed", f"Image URL returned HTTP {r.status_code}.", param)
            mime = r.headers.get("content-type", "").split(";")[0].strip().lower()
            if not mime.startswith("image/"):
                raise BadRequest("remote_image_failed", "URL did not return an image.", param)
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) > max_bytes:
                    raise BadRequest("image_too_large", "Remote image is too large.", param, 413)
            return bytes(buf), mime
    except httpx.HTTPError as e:
        raise BadRequest("remote_image_failed", f"Image download failed ({type(e).__name__}).", param) from None
