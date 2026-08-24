# SPDX-License-Identifier: Apache-2.0
"""CLI entrypoint for tenable-ot-mcp."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from . import __version__

BANNER = r"""
   ╔══════════════════════════════════════════════╗
   ║  Tenable OT MCP Server                       ║
   ║  Open source · Apache 2.0 · v{version:<16} ║
   ║  https://github.com/dpstorey/EM-MCP          ║
   ╚══════════════════════════════════════════════╝
"""


def _print_banner() -> None:
    click.echo(BANNER.format(version=__version__))


@click.group()
@click.version_option(__version__, prog_name="tenable-ot-mcp")
def cli() -> None:
    """Tenable OT MCP Server — open-source MCP bridge to Tenable OT Security."""


@cli.command()
@click.option(
    "--host",
    default=os.environ.get("MCP_BIND_HOST", "0.0.0.0"),
    show_default=True,
    help="Address to bind. Override with MCP_BIND_HOST.",
)
@click.option(
    "--port",
    type=int,
    default=int(os.environ.get("MCP_BIND_PORT", "40443")),
    show_default=True,
    help="Port to bind. Override with MCP_BIND_PORT.",
)
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path(os.environ.get("MCP_DATA_DIR", "/data")),
    show_default=True,
    help="Persistent state directory. Override with MCP_DATA_DIR.",
)
@click.option(
    "--tls-cert",
    type=click.Path(dir_okay=False, path_type=Path),
    default=lambda: Path(os.environ["MCP_TLS_CERT"]) if os.environ.get("MCP_TLS_CERT") else None,
    help="Path to a PEM-encoded TLS certificate. Override with MCP_TLS_CERT.",
)
@click.option(
    "--tls-key",
    type=click.Path(dir_okay=False, path_type=Path),
    default=lambda: Path(os.environ["MCP_TLS_KEY"]) if os.environ.get("MCP_TLS_KEY") else None,
    help="Path to the matching PEM-encoded private key. Override with MCP_TLS_KEY.",
)
def serve(
    host: str,
    port: int,
    data_dir: Path,
    tls_cert: Path | None,
    tls_key: Path | None,
) -> None:
    """Run the MCP server.

    Transport (HTTPS-by-default):

    - If `--tls-cert` and `--tls-key` (or `MCP_TLS_CERT` /
      `MCP_TLS_KEY`) are provided, those are used.
    - Otherwise, a self-signed cert is auto-generated into the data
      directory on first start and reused thereafter. The cert covers
      `localhost`, `127.0.0.1`, and `::1`. Add hostnames or external
      IPs via `MCP_TLS_HOSTNAME` (comma-separated) to extend the SAN.
    - Set `MCP_TLS_DISABLE=1` to fall back to plain HTTP — only
      appropriate behind a TLS-terminating reverse proxy.

    Mode:

    - If `<data_dir>/config.enc` exists, the server starts and serves
      the MCP endpoint at `/mcp` plus the configuration metadata at
      `/.well-known/oauth-protected-resource`.
    - Otherwise, the server starts in setup mode and serves the
      first-run wizard at `/setup`. The `/mcp` endpoint returns a 503
      until setup completes (and the container is restarted so the
      MCP session manager comes up against the saved config).
    """
    _print_banner()

    data_dir.mkdir(parents=True, exist_ok=True)
    if not os.access(data_dir, os.W_OK):
        click.echo(f"Error: data directory {data_dir} is not writable.", err=True)
        sys.exit(1)

    if (tls_cert is None) != (tls_key is None):
        click.echo(
            "Error: --tls-cert and --tls-key must both be provided, or both omitted.",
            err=True,
        )
        sys.exit(1)
    if tls_cert is not None and not tls_cert.is_file():
        click.echo(f"Error: TLS cert file not found: {tls_cert}", err=True)
        sys.exit(1)
    if tls_key is not None and not tls_key.is_file():
        click.echo(f"Error: TLS key file not found: {tls_key}", err=True)
        sys.exit(1)

    tls_disabled = os.environ.get("MCP_TLS_DISABLE") == "1"
    auto_generated = False

    if tls_disabled and tls_cert is None:
        scheme = "http"
    elif tls_cert is not None:
        scheme = "https"
    else:
        from .tls import ensure_self_signed_cert

        extra_hostnames = [
            h.strip() for h in (os.environ.get("MCP_TLS_HOSTNAME") or "").split(",") if h.strip()
        ]
        tls_cert, tls_key = ensure_self_signed_cert(data_dir, extra_hostnames)
        auto_generated = True
        scheme = "https"

    from .config import ConfigStore

    store = ConfigStore(data_dir)
    setup_complete = store.is_configured()

    click.echo(f"  Listening on {scheme}://{host}:{port}")
    click.echo(f"  Data directory: {data_dir}")
    if scheme == "https":
        if auto_generated:
            click.echo(f"  TLS: self-signed cert at {tls_cert} (auto-generated)")
            click.echo("       For a CA-signed cert, replace cert.pem / key.pem in the data dir.")
            click.echo(
                "       To extend the SAN, set MCP_TLS_HOSTNAME=host1,host2,... and restart."
            )
        else:
            click.echo(f"  TLS: operator-supplied cert at {tls_cert}")
    else:
        click.echo("  ⚠  TLS DISABLED via MCP_TLS_DISABLE=1 — bearer tokens and the")
        click.echo("     Tenable OT API key will travel in cleartext. Use only when")
        click.echo("     a reverse proxy in front terminates TLS.")
    if setup_complete:
        click.echo("  Mode: serve  (configuration loaded)")
        click.echo("  MCP endpoint:        /mcp")
        click.echo("  Discovery metadata:  /.well-known/oauth-protected-resource")
    else:
        click.echo("  Mode: setup  (no configuration yet)")
        click.echo(f"  Open {scheme}://{host}:{port}/setup to configure.")
    click.echo("")

    import uvicorn

    from .server import create_app

    app = create_app(data_dir)
    log_level = (os.environ.get("MCP_LOG_LEVEL") or "info").lower()
    if log_level not in {"critical", "error", "warning", "info", "debug", "trace"}:
        click.echo(
            f"Error: invalid MCP_LOG_LEVEL={log_level!r}. "
            "Use one of critical,error,warning,info,debug,trace.",
            err=True,
        )
        sys.exit(1)
    if tls_cert is not None and tls_key is not None:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=log_level,
            access_log=True,
            ssl_certfile=str(tls_cert),
            ssl_keyfile=str(tls_key),
        )
    else:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=log_level,
            access_log=True,
        )


@cli.command()
def version() -> None:
    """Print the package version and exit."""
    click.echo(__version__)


if __name__ == "__main__":
    cli()
