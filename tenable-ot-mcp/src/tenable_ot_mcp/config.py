# SPDX-License-Identifier: Apache-2.0
"""Encrypted configuration persisted to /data/config.enc.

Contents (JSON before encryption):
    tenable_url            — base URL of the customer's Tenable OT or EM endpoint
    icp_machine_id         — optional ICP machine id when routing through EM
    tenable_api_key        — service-account key the server uses to talk to Tenable OT
    tls_verify             — whether httpx should verify Tenable OT's TLS cert
    bearer_token           — bearer token MCP clients present in `Authorization: Bearer <token>`
    write_tools_enabled    — boolean; controls whether write tools appear in tools/list
    setup_completed_at     — ISO timestamp marking first-run completion

A single bearer token is issued at setup. Capabilities follow
`write_tools_enabled` from the setup wizard: if writes were enabled,
write tools are exposed and any authenticated client can call them;
if not, only read tools are registered. This matches the model used
by every production MCP server in the wild (one token, scoped at
setup) and stays interoperable with Claude.ai, ChatGPT, Cursor, and
other MCP-compatible clients.

Encryption: Fernet (AES-128 in CBC + HMAC-SHA256), key derived from
`/data/config.key` written on first run with mode 0600. The key file is
generated once and never rotated by the server itself; operators can
rotate by deleting both files and re-running setup.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

CONFIG_FILENAME = "config.enc"
KEY_FILENAME = "config.key"


@dataclass
class Config:
    tenable_url: str
    tenable_api_key: str
    tls_verify: bool
    bearer_token: str
    write_tools_enabled: bool
    icp_machine_id: str | None = None
    setup_completed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Config:
        return cls(**d)


class ConfigStore:
    """Reads and writes the encrypted config file under data_dir."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config_path = data_dir / CONFIG_FILENAME
        self.key_path = data_dir / KEY_FILENAME

    # ---- Key management -------------------------------------------------

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            return self.key_path.read_bytes()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        os.chmod(self.key_path, 0o600)
        return key

    # ---- Public API -----------------------------------------------------

    def is_configured(self) -> bool:
        return self.config_path.is_file()

    def load(self) -> Config:
        if not self.is_configured():
            raise FileNotFoundError(f"No config at {self.config_path}")
        key = self._load_or_create_key()
        try:
            payload = Fernet(key).decrypt(self.config_path.read_bytes())
        except InvalidToken as e:
            raise RuntimeError(
                "Config decryption failed — the encryption key under "
                f"{self.key_path} does not match {self.config_path}. "
                "Delete both and re-run setup, or restore the matching key."
            ) from e
        return Config.from_dict(json.loads(payload.decode("utf-8")))

    def save(self, cfg: Config) -> None:
        key = self._load_or_create_key()
        payload = json.dumps(cfg.to_dict()).encode("utf-8")
        self.config_path.write_bytes(Fernet(key).encrypt(payload))
        os.chmod(self.config_path, 0o600)


def generate_bearer_token() -> str:
    """Generate a 32-byte URL-safe token (~43 chars after base64)."""
    return secrets.token_urlsafe(32)
