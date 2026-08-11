# SPDX-License-Identifier: Apache-2.0
"""Status tool: tenable_ot_status.

Reports whether this MCP server can currently reach the Tenable OT
Security appliance behind it. A client can connect to and enumerate this
server without the appliance being reachable — discovery and tool calls
travel different paths. This tool exposes the second hop so a caller can
tell a live backend from a dead one, and surface the reason when it's
dead.
"""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..audit import AuditLog
from ..tenable_client import TenableClient


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register the backend connection status tool."""

    @mcp.tool(
        title="Check Tenable OT connection",
        description=(
            "Reports whether this server can currently reach the Tenable "
            "OT Security appliance it fronts. Call this to confirm the "
            "data source is live before drawing conclusions from a failed "
            "query, or when a user asks whether the Tenable connection is "
            "working. Returns `connected` (bool), the appliance URL, "
            "round-trip `latency_ms`, and — when the appliance is "
            "unreachable — an `error` string with the reason. A healthy "
            "MCP session does not imply a healthy appliance connection; "
            "this tool checks the appliance directly."
        ),
    )
    async def tenable_ot_status() -> dict[str, Any]:
        """Probe the Tenable OT appliance and report the connection state."""
        status = await client.connection_status()
        status["server_version"] = __version__
        return status
