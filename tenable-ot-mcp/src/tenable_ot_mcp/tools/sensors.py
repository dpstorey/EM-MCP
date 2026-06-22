# SPDX-License-Identifier: Apache-2.0
"""Sensor health tools: list_sensors.

Tenable OT sensors capture network traffic on the operator's
industrial networks. Their health (online/offline, tunnel status,
version, errors) is a precondition for any other event/asset
visibility, so SOC analysts often start their day here. The
`sensors` query is pagination-only — there's no server-side filter —
so optional client-side filtering is applied to the projected list.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._shared import unwrap_nodes

_QUERY_SENSORS = """
query Q {
  sensors(first: 500) {
    nodes {
      id
      name
      ip
      externalIp
      internalIp
      natIp
      version
      fullVersion
      status
      statusTs
      connectionStatus
      tunnelStatus
      tunnelStatusTs
      active
      approved
      speed
      error
      errorTs
      systemUpdatesExist
      stockdogUpdateExists
      updatableSensor
      lastCheckForUpdates
    }
  }
}
"""


def _project_sensor(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "ip": node.get("ip"),
        "external_ip": node.get("externalIp"),
        "internal_ip": node.get("internalIp"),
        "nat_ip": node.get("natIp"),
        "version": node.get("version"),
        "full_version": node.get("fullVersion"),
        "status": node.get("status"),
        "status_ts": node.get("statusTs"),
        "connection_status": node.get("connectionStatus"),
        "tunnel_status": node.get("tunnelStatus"),
        "tunnel_status_ts": node.get("tunnelStatusTs"),
        "active": node.get("active"),
        "approved": node.get("approved"),
        "speed": node.get("speed"),
        "error": node.get("error"),
        "error_ts": node.get("errorTs"),
        "system_updates_available": node.get("systemUpdatesExist"),
        "stockdog_update_available": node.get("stockdogUpdateExists"),
        "updatable": node.get("updatableSensor"),
        "last_check_for_updates": node.get("lastCheckForUpdates"),
    }


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register the sensor read tool."""

    @mcp.tool(
        title="List sensors",
        description=(
            "Returns every Tenable OT sensor in the deployment with "
            "its current status, connection / tunnel status, version, "
            "addressing, error state, and whether updates are pending. "
            "Use this to verify visibility coverage before drawing "
            "conclusions from query_assets / query_events — an offline "
            "sensor means absence of evidence, not evidence of absence.\n\n"
            "The `status` filter applies client-side after fetch."
        ),
    )
    async def list_sensors(
        status: str | None = None,
        connection_status: str | None = None,
    ) -> dict[str, Any]:
        """List sensors.

        Args:
            status: Client-side filter on the sensor `status` field
                (e.g. "Connected", "Disconnected"). The exact enum
                values come from Tenable's `SensorStatus`; pass them
                literally.
            connection_status: Client-side filter on the
                `connection_status` field (Tenable's
                `ConnectionStatus` enum).
        """
        data = await client.query(_QUERY_SENSORS)
        nodes = unwrap_nodes(data.get("sensors"))
        projected = [_project_sensor(n) for n in nodes]

        def keep(s: dict[str, Any]) -> bool:
            if status and (s.get("status") or "") != status:
                return False
            if connection_status and (s.get("connection_status") or "") != connection_status:
                return False
            return True

        filtered = [s for s in projected if keep(s)]
        return {"count": len(filtered), "total": len(projected), "sensors": filtered}
