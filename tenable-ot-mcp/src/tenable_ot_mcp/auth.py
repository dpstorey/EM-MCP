# SPDX-License-Identifier: Apache-2.0
"""Bearer-token authentication for the MCP endpoint.

A single bearer token is issued at setup time. Clients present it in
the standard `Authorization: Bearer <token>` header. Constant-time
comparison defeats trivial timing oracles.

Capabilities (read-only vs read+write) follow `write_tools_enabled`
from the setup wizard, NOT which token was presented. There is only
one token. This matches every production MCP server in the wild and
stays interoperable with Claude.ai, ChatGPT, Cursor, etc.

`/setup` and `/healthz` are unauthenticated; `/mcp` and any future
status endpoints check the header.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .config import Config


@dataclass(frozen=True)
class Principal:
    """Result of authenticating an incoming request."""

    can_write: bool


class AuthError(Exception):
    """Raised when a request fails bearer-token authentication."""


def _extract_bearer(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def authenticate(authorization_header: str | None, cfg: Config) -> Principal:
    """Match the incoming bearer token against the configured token.

    Raises AuthError when the header is missing, malformed, or the
    token does not match the configured token. Comparison is
    constant-time.

    The returned Principal's `can_write` reflects the server's setup
    flag, not the token itself — there is only one token.
    """
    presented = _extract_bearer(authorization_header)
    if not presented:
        raise AuthError("Missing or malformed Authorization header")

    if hmac.compare_digest(presented, cfg.bearer_token):
        return Principal(can_write=cfg.write_tools_enabled)
    raise AuthError("Bearer token does not match the configured token")
