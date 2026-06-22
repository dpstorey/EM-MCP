# SPDX-License-Identifier: Apache-2.0
"""Smoke tests — verify the package installs and the wiring holds."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from tenable_ot_mcp import __version__
from tenable_ot_mcp.auth import AuthError, authenticate
from tenable_ot_mcp.config import Config, ConfigStore, generate_bearer_token
from tenable_ot_mcp.main import cli

# ---- Package wiring -------------------------------------------------------


def test_package_has_version() -> None:
    assert __version__
    assert isinstance(__version__, str)


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "tenable ot mcp" in result.output.lower()
    assert "serve" in result.output


# ---- Config round-trip ----------------------------------------------------


def test_config_round_trip(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    assert not store.is_configured()
    cfg = Config(
        tenable_url="https://tenable.example.com",
        tenable_api_key="key-123",
        tls_verify=True,
        bearer_token=generate_bearer_token(),
        write_tools_enabled=True,
    )
    store.save(cfg)
    assert store.is_configured()
    loaded = store.load()
    assert loaded.tenable_url == cfg.tenable_url
    assert loaded.tenable_api_key == cfg.tenable_api_key
    assert loaded.bearer_token == cfg.bearer_token
    assert loaded.write_tools_enabled is True


def test_config_file_is_actually_encrypted(tmp_path: Path) -> None:
    """Plain bytes on disk must not contain the API key."""
    store = ConfigStore(tmp_path)
    cfg = Config(
        tenable_url="https://example.com",
        tenable_api_key="UNIQUEKEYTHATSHOULDNTLEAK",
        tls_verify=True,
        bearer_token="bearer-tok",
        write_tools_enabled=False,
    )
    store.save(cfg)
    raw = (tmp_path / "config.enc").read_bytes()
    assert b"UNIQUEKEYTHATSHOULDNTLEAK" not in raw
    assert b"bearer-tok" not in raw


def test_bearer_tokens_are_unique() -> None:
    tokens = {generate_bearer_token() for _ in range(64)}
    assert len(tokens) == 64


# ---- Auth -----------------------------------------------------------------


def _cfg(token: str = "TOKEN", write_enabled: bool = True) -> Config:  # noqa: S107
    return Config(
        tenable_url="https://x",
        tenable_api_key="k",
        tls_verify=True,
        bearer_token=token,
        write_tools_enabled=write_enabled,
    )


def test_auth_accepts_token_with_writes_enabled() -> None:
    p = authenticate("Bearer TOKEN", _cfg(write_enabled=True))
    assert p.can_write is True


def test_auth_accepts_token_with_writes_disabled() -> None:
    p = authenticate("Bearer TOKEN", _cfg(write_enabled=False))
    assert p.can_write is False


def test_auth_rejects_missing_header() -> None:
    with pytest.raises(AuthError):
        authenticate(None, _cfg())


def test_auth_rejects_wrong_token() -> None:
    with pytest.raises(AuthError):
        authenticate("Bearer BOGUS", _cfg())


def test_auth_rejects_malformed_header() -> None:
    with pytest.raises(AuthError):
        authenticate("TOKEN", _cfg())  # no scheme
    with pytest.raises(AuthError):
        authenticate("Basic dXNlcjpwYXNz", _cfg())  # wrong scheme
