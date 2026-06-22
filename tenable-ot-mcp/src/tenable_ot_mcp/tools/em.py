# SPDX-License-Identifier: Apache-2.0
"""Enterprise Manager tools.

These tools operate on EM's root GraphQL endpoint and are useful when
this MCP is configured to relay most data queries through a specific ICP.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient

_QUERY_EM_PAIRED_ICPS = """
query Q($pageSize: Int!) {
  emPairedIcps(first: $pageSize) {
    totalCount
    edges {
      node {
        status
        dataSyncTs
        statusTs
        site {
          machineId
          name
          host
          totalSensorsCount
          onlineSensorsCount
          activeQueriesEnabled
        }
        version {
          version
        }
      }
    }
  }
}
"""


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register Enterprise Manager discovery tools."""

    @mcp.tool(
        title="List paired ICP appliances via EM",
        description=(
            "Queries Enterprise Manager's root GraphQL endpoint and returns paired "
            "ICP appliance status, machine ids, site metadata, and version details. "
            "Use this to discover the machine id needed for EM relay URLs like "
            "https://<em>/<machine_id>/graphql."
        ),
    )
    async def list_paired_icps(limit: int = 100) -> dict[str, Any]:
        """Return paired ICP inventory from Enterprise Manager.

        If this MCP is configured with a default ICP machine id, this tool still
        bypasses relay mode and queries EM root directly.
        """
        page_size = max(1, min(int(limit), 500))
        d = await client.query_em(_QUERY_EM_PAIRED_ICPS, variables={"pageSize": page_size})
        conn = (d or {}).get("emPairedIcps") or {}
        rows = []
        for edge in conn.get("edges") or []:
            node = (edge or {}).get("node") or {}
            site = node.get("site") or {}
            version = node.get("version") or {}
            rows.append(
                {
                    "status": node.get("status"),
                    "data_sync_ts": node.get("dataSyncTs"),
                    "status_ts": node.get("statusTs"),
                    "site": {
                        "machine_id": site.get("machineId"),
                        "name": site.get("name"),
                        "host": site.get("host"),
                        "total_sensors_count": site.get("totalSensorsCount"),
                        "online_sensors_count": site.get("onlineSensorsCount"),
                        "active_queries_enabled": site.get("activeQueriesEnabled"),
                    },
                    "version": version.get("version"),
                }
            )

        return {
            "total_count": conn.get("totalCount") or len(rows),
            "returned": len(rows),
            "icps": rows,
        }
