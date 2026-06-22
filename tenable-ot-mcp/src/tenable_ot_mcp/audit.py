# SPDX-License-Identifier: Apache-2.0
"""Append-only audit log for write operations.

One JSON object per line at /data/audit.jsonl. Compliance teams can
grep, ship to a SIEM, or rotate by truncating. The server never reads
this file back — it's write-only by design.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_FILENAME = "audit.jsonl"


class AuditLog:
    """Thread-safe append-only writer."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / AUDIT_FILENAME
        self._lock = threading.Lock()
        data_dir.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        tool_name: str,
        params: dict[str, Any],
        dry_run: bool,
        outcome: str,
        tenable_status: int | None = None,
        error: str | None = None,
    ) -> None:
        """Write one audit row.

        Args:
            tool_name: e.g. 'hide_asset'.
            params: tool arguments. Sensitive substrings should already be redacted by the caller.
            dry_run: True if this was a preview-only call.
            outcome: 'ok' | 'error' | 'rejected'.
            tenable_status: HTTP status from the upstream Tenable OT call, if any.
            error: error class or short message when outcome != 'ok'.
        """
        row = {
            "ts": datetime.now(UTC).isoformat(),
            "tool": tool_name,
            "dry_run": dry_run,
            "outcome": outcome,
            "params": params,
        }
        if tenable_status is not None:
            row["tenable_status"] = tenable_status
        if error:
            row["error"] = error
        line = json.dumps(row, default=str, sort_keys=True) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line)
