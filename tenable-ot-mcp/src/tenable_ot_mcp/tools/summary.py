# SPDX-License-Identifier: Apache-2.0
"""Summary tool: summarize_environment.

A one-shot snapshot of the Tenable OT deployment's shape and scale —
total counts plus the most useful subtotals (events resolved/unresolved,
plugins by severity, assets by criticality and hidden flag). Ideal as
the first call an AI makes to orient itself before drilling in.

All counts come from the connection-style `totalCount` fields. Where
Tenable's filter shape allows it (events resolved, plugins severity,
assets criticality / hidden), subtotals are pulled in the same query
to avoid an N+1.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient

# One large multi-aliased query — Tenable's GraphQL accepts arbitrarily
# many connection sub-queries in one POST. Each alias hits the same
# top-level connection with a different filter and returns just
# totalCount, so the wire payload stays tiny.
_QUERY_SUMMARY = """
query Q {
  assetsTotal: assets { totalCount }
  assetsHidden: assets(filter: {field: hidden, op: Equal, values: true}) { totalCount }
  assetsHighCrit: assets(filter: {field: criticality, op: Equal, values: ["HighCriticality"]}) {
    totalCount
  }
  assetsMediumCrit: assets(filter: {field: criticality, op: Equal, values: ["MediumCriticality"]}) {
    totalCount
  }
  assetsLowCrit: assets(filter: {field: criticality, op: Equal, values: ["LowCriticality"]}) {
    totalCount
  }
  assetsNoCrit: assets(filter: {field: criticality, op: Equal, values: ["NoneCriticality"]}) {
    totalCount
  }

  eventsTotal: events { totalCount }
  eventsUnresolved: events(filter: {field: resolved, op: Equal, values: false}) { totalCount }
  eventsResolved: events(filter: {field: resolved, op: Equal, values: true}) { totalCount }

  pluginsTotal: plugins { totalCount }
  pluginsCritical: plugins(filter: {field: severity, op: Equal, values: ["Critical"]}) {
    totalCount
  }
  pluginsHigh: plugins(filter: {field: severity, op: Equal, values: ["High"]}) { totalCount }
  pluginsMedium: plugins(filter: {field: severity, op: Equal, values: ["Medium"]}) { totalCount }
  pluginsLow: plugins(filter: {field: severity, op: Equal, values: ["Low"]}) { totalCount }
  pluginsInfo: plugins(filter: {field: severity, op: Equal, values: ["Info"]}) { totalCount }

  sensorsTotal: sensors { totalCount }
  segmentGroupsTotal: segmentGroups { totalCount }
  zonesTotal: zones { totalCount }
  policiesTotal: policies { totalCount }
}
"""


def _count(block: dict | None) -> int:
    return (block or {}).get("totalCount") or 0


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register the environment summary tool."""

    @mcp.tool(
        title="Summarize the OT environment",
        description=(
            "Returns a one-shot snapshot of the operator's OT "
            "environment — total counts and useful subtotals across "
            "assets, events, vulnerabilities, sensors, topology, and "
            "policies. Ideal as the first call when the AI doesn't yet "
            "know the deployment's shape and scale. Each section is a "
            "compact dict; subtotals are best-effort (only those "
            "Tenable's filters support are populated).\n\n"
            "Asset criticality buckets: none / low / medium / high. "
            "Plugin severity buckets: info / low / medium / high / "
            "critical. Event subtotals split by resolved flag."
        ),
    )
    async def summarize_environment() -> dict[str, Any]:
        """Return aggregate counts across the deployment."""
        d = await client.query(_QUERY_SUMMARY)
        return {
            "assets": {
                "total": _count(d.get("assetsTotal")),
                "hidden": _count(d.get("assetsHidden")),
                "by_criticality": {
                    "none": _count(d.get("assetsNoCrit")),
                    "low": _count(d.get("assetsLowCrit")),
                    "medium": _count(d.get("assetsMediumCrit")),
                    "high": _count(d.get("assetsHighCrit")),
                },
            },
            "events": {
                "total": _count(d.get("eventsTotal")),
                "unresolved": _count(d.get("eventsUnresolved")),
                "resolved": _count(d.get("eventsResolved")),
            },
            "vulnerabilities": {
                "total": _count(d.get("pluginsTotal")),
                "by_severity": {
                    "info": _count(d.get("pluginsInfo")),
                    "low": _count(d.get("pluginsLow")),
                    "medium": _count(d.get("pluginsMedium")),
                    "high": _count(d.get("pluginsHigh")),
                    "critical": _count(d.get("pluginsCritical")),
                },
            },
            "sensors": {"total": _count(d.get("sensorsTotal"))},
            "topology": {
                "segments": _count(d.get("segmentGroupsTotal")),
                "zones": _count(d.get("zonesTotal")),
            },
            "policies": {"total": _count(d.get("policiesTotal"))},
        }
