# SPDX-License-Identifier: Apache-2.0
"""Starlette app exposing /healthz, /setup, /.well-known/*, and /mcp.

The app picks its mode at startup based on whether
`<data_dir>/config.enc` exists:

  - If absent: only /healthz and /setup are wired. /mcp returns 503.
    After the wizard completes, the operator restarts the container
    so the MCP sub-app and its session-manager lifespan come up
    cleanly.
  - If present: the FastMCP Streamable HTTP sub-app is built eagerly
    and mounted under /mcp behind a bearer-auth gate. Its lifespan
    is delegated from the outer Starlette app so the session manager
    starts before any request arrives.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from . import __version__
from .audit import AuditLog
from .auth import AuthError, authenticate
from .config import Config, ConfigStore, generate_bearer_token
from .tenable_client import TenableClient

# ----------------------------------------------------------------------
# State holder
# ----------------------------------------------------------------------


class AppState:
    """Process-wide state shared by all request handlers.

    The config is loaded eagerly at startup. If config is present the
    FastMCP sub-app is built and its lifespan delegated to the outer
    app so its session manager comes up before the first request. If
    config is absent the server runs in setup-only mode; the operator
    restarts the container after completing the wizard.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.store = ConfigStore(data_dir)
        self.audit = AuditLog(data_dir)
        self._config: Config | None = None
        self.mcp_app: Any | None = None
        if self.store.is_configured():
            self._config = self.store.load()
            from .mcp_app import build_mcp_app

            self.mcp_app = build_mcp_app(self._config, self.audit)

    def get_config(self) -> Config | None:
        return self._config

    def set_config(self, cfg: Config) -> None:
        self._config = cfg


# ----------------------------------------------------------------------
# Route handlers
# ----------------------------------------------------------------------


def _jinja(loader_pkg: str = "tenable_ot_mcp") -> Environment:
    return Environment(
        loader=PackageLoader(loader_pkg, "templates"),
        autoescape=select_autoescape(["html"]),
    )


async def healthz(request: Request) -> JSONResponse:
    state: AppState = request.app.state.app_state
    return JSONResponse(
        {
            "status": "ok",
            "configured": state.get_config() is not None,
            "version": __version__,
        }
    )


async def setup_get(request: Request) -> Response:
    state: AppState = request.app.state.app_state
    env = request.app.state.jinja
    if state.get_config() is not None:
        return JSONResponse(
            {
                "error": "Server is already configured.",
                "hint": (
                    "Delete /data/config.enc and /data/config.key on the "
                    "host volume to re-run setup. This will invalidate "
                    "the existing bearer tokens."
                ),
            },
            status_code=409,
        )
    tmpl = env.get_template("setup.html")
    return HTMLResponse(
        tmpl.render(form={"tls_verify": True, "write_tools_enabled": False}, error=None)
    )


async def setup_post(request: Request) -> Response:
    state: AppState = request.app.state.app_state
    env = request.app.state.jinja
    if state.get_config() is not None:
        return JSONResponse({"error": "Server is already configured."}, status_code=409)

    form = await request.form()

    def _form_str(name: str) -> str:
        # Starlette's FormData.get() returns str | UploadFile | None — the same
        # parser handles text inputs and file uploads. The setup form is text-
        # only, but a multipart payload with a file part named the same field
        # would otherwise hit .strip() and AttributeError at runtime.
        val = form.get(name)
        return val.strip() if isinstance(val, str) else ""

    tenable_url = _form_str("tenable_url")
    tenable_api_key = _form_str("tenable_api_key")
    tls_verify = "tls_verify" in form
    write_tools_enabled = "write_tools_enabled" in form

    form_state = {
        "tenable_url": tenable_url,
        "tls_verify": tls_verify,
        "write_tools_enabled": write_tools_enabled,
        # Never echo the API key back into the form; user re-enters on error.
        "tenable_api_key": "",
    }

    def _render_error(msg: str, status: int = 400) -> HTMLResponse:
        tmpl = env.get_template("setup.html")
        return HTMLResponse(tmpl.render(form=form_state, error=msg), status_code=status)

    if not tenable_url or not tenable_api_key:
        return _render_error("Both URL and API key are required.")

    if not tenable_url.lower().startswith(("http://", "https://")):
        return _render_error("URL must start with http:// or https://.")

    # Verify connectivity to Tenable OT/EM before saving.
    client = TenableClient(
        tenable_url,
        tenable_api_key,
        tls_verify=tls_verify,
    )
    ok = await client.healthcheck()
    if not ok:
        return _render_error(
            "Could not reach Tenable OT/EM or authenticate. Check URL, API key, and TLS settings.",
            status=502,
        )

    # Generate the single bearer token, persist config.
    bearer_token = generate_bearer_token()

    cfg = Config(
        tenable_url=tenable_url,
        tenable_api_key=tenable_api_key,
        tls_verify=tls_verify,
        bearer_token=bearer_token,
        write_tools_enabled=write_tools_enabled,
        icp_machine_id=None,
    )
    state.store.save(cfg)
    state.set_config(cfg)

    # Build the MCP URL the user will paste into their client.
    scheme = request.url.scheme
    netloc = request.url.netloc
    mcp_url = f"{scheme}://{netloc}/mcp"

    tmpl = env.get_template("setup_done.html")
    return HTMLResponse(
        tmpl.render(
            bearer_token=bearer_token,
            write_tools_enabled=write_tools_enabled,
            mcp_url=mcp_url,
        )
    )


async def well_known_protected_resource(request: Request) -> JSONResponse:
    """RFC 9728 OAuth 2.0 Protected Resource Metadata.

    Advertises bearer-token authentication. v1 does not run an OAuth
    issuer; clients use the bearer tokens issued by the setup wizard.
    """
    state: AppState = request.app.state.app_state
    if state.get_config() is None:
        return JSONResponse({"error": "Server not configured."}, status_code=503)

    base = f"{request.url.scheme}://{request.url.netloc}"
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [],
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://gitlab.com/jwalley/tenable-ot-mcp",
        }
    )


async def mcp_unconfigured(request: Request) -> Response:
    """Stub /mcp handler used in setup-only mode."""
    return JSONResponse(
        {
            "error": (
                "Server not configured. Visit /setup, then restart the "
                "container so the MCP endpoint comes up."
            )
        },
        status_code=503,
    )


class McpAuthGate:
    """Bearer-auth gate in front of the FastMCP Streamable HTTP app.

    Registered as a Starlette route endpoint. Because it is a callable
    instance rather than a function, Starlette routes to it as a raw
    ASGI app instead of wrapping it in request/response semantics. That
    is required here: the FastMCP sub-app owns the entire response
    lifecycle — including long-lived server-to-client SSE streams — and
    writes directly to `send`. A request/response endpoint, by contrast,
    must return a Response for Starlette to invoke, which this gate has
    nothing to hand back.

    Only wired when configuration was present at startup, so the FastMCP
    sub-app's session manager has already been started by the outer
    lifespan. Authenticates the bearer token, attaches the resolved
    Principal to request scope state, and delegates to the sub-app.
    """

    def __init__(self, state: AppState) -> None:
        self._state = state

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        state = self._state
        cfg = state.get_config()
        if cfg is None or state.mcp_app is None:
            await JSONResponse(
                {"error": "Server not configured. Visit /setup."},
                status_code=503,
            )(scope, receive, send)
            return
        try:
            principal = authenticate(Headers(scope=scope).get("authorization"), cfg)
        except AuthError as e:
            await JSONResponse(
                {"error": str(e)},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="tenable-ot-mcp"'},
            )(scope, receive, send)
            return

        scope["state"] = scope.get("state") or {}
        scope["state"]["principal"] = principal
        await state.mcp_app(scope, receive, send)


# ----------------------------------------------------------------------
# App factory
# ----------------------------------------------------------------------


def create_app(data_dir: Path) -> Starlette:
    """Build the Starlette application with all routes wired.

    When configuration is present at startup, the FastMCP sub-app's
    lifespan (which starts its Streamable-HTTP session manager) is
    delegated from the outer Starlette lifespan so requests landing
    on /mcp find an initialized task group.
    """
    state = AppState(data_dir)

    routes: list[Any] = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/setup", setup_get, methods=["GET"]),
        Route("/setup", setup_post, methods=["POST"]),
        Route(
            "/.well-known/oauth-protected-resource",
            well_known_protected_resource,
            methods=["GET"],
        ),
    ]

    if state.mcp_app is not None:
        # Configured: bearer-auth gate (raw ASGI) in front of the
        # prebuilt FastMCP sub-app, registered at the same /mcp path the
        # sub-app's own router serves, so the scope passes through
        # unmodified.
        routes.append(Route("/mcp", McpAuthGate(state), methods=["GET", "POST", "DELETE"]))
    else:
        # Setup-only: /mcp returns 503 until the operator finishes
        # the wizard and restarts the container.
        routes.append(Route("/mcp", mcp_unconfigured, methods=["GET", "POST", "DELETE"]))

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        if state.mcp_app is not None:
            async with state.mcp_app.router.lifespan_context(state.mcp_app):
                yield
        else:
            yield

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.app_state = state
    app.state.jinja = _jinja()
    return app
