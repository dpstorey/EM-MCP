# SPDX-License-Identifier: Apache-2.0
"""Summary tools: summarize_environment and get_classification_summary.

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
from ._sites import run_site_read

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


# ---------------------------------------------------------------------------
# Classification quality
#
# Every asset starts as "Endpoint" (enum value `Unknown`) and only moves off
# it once Tenable positively classifies it, so the share of assets still
# `Unknown` is a data-quality meter for the inventory.
# ---------------------------------------------------------------------------

UNCLASSIFIED_TYPE = "Unknown"

# Asset types accepted by the `type` *filter* (the Tenable UI Type dropdown),
# which is narrower than the editable UserDefinedAssetType vocabulary.
_FILTER_ASSET_TYPES: tuple[str, ...] = (
    "BackplaneModule", "Bms", "Camera", "Cnc", "Controller", "Cp", "Dcs",
    "DomainController", "Eng", "FileServer", "Gateway", "Hmi", "Ied",
    "IndustrialGateway", "IndustrialSwitch", "Io", "Iot", "NetworkDevice",
    "OtDevice", "OtServer", "Plc", "PowerSupply", "Printer", "Router", "Rtu",
    "SerialEthernetBridge", "Server", "StorageDevice", "Switch", "TenableEm",
    "TenableIcp", "TenableSensor", "ThreeDPrinter", "Unknown",
    "VideoManagementSystem", "Workstation",
)  # fmt: skip

# Default target for data quality (the classified share), in percent.
# Callers can override it per call with `min_quality_pct`.
DEFAULT_MIN_QUALITY_PCT = 90.0


def _type_alias(asset_type: str) -> str:
    return f"t_{asset_type}"


def _classification_query(by_type: bool) -> str:
    """Build the one-shot count query (total, unclassified, optional per-type)."""
    parts = [
        "assetsTotal: assets { totalCount }",
        f'assetsUnknown: assets(filter: {{field: type, op: In, values: ["{UNCLASSIFIED_TYPE}"]}}) '
        "{ totalCount }",
    ]
    if by_type:
        parts.extend(
            f'{_type_alias(t)}: assets(filter: {{field: type, op: In, values: ["{t}"]}}) '
            "{ totalCount }"
            for t in _FILTER_ASSET_TYPES
            if t != UNCLASSIFIED_TYPE
        )
    return "query Q {\n  " + "\n  ".join(parts) + "\n}"


def classification_result(
    site_uuid: str,
    data: dict[str, Any],
    by_type: bool = False,
    min_quality_pct: float = DEFAULT_MIN_QUALITY_PCT,
) -> dict[str, Any]:
    """Shape raw GraphQL counts into the tool's result."""
    total = _count(data.get("assetsTotal"))
    unclassified = _count(data.get("assetsUnknown"))
    classified = max(total - unclassified, 0)
    if total:
        quality_pct: float | None = round(100.0 * classified / total, 1)
        unclassified_pct: float | None = round(100.0 * unclassified / total, 1)
        meets: bool | None = 100.0 * classified / total >= min_quality_pct
        rating = "good" if meets else "poor"
    else:
        quality_pct = unclassified_pct = meets = None
        rating = "no_assets"
    result: dict[str, Any] = {
        "site_uuid": site_uuid,
        "data_quality_pct": quality_pct,
        "quality": rating,
        "target_pct": min_quality_pct,
        "meets_target": meets,
        "assets_total": total,
        "classified": classified,
        "unclassified": unclassified,
        "unclassified_pct": unclassified_pct,
        "note": (
            "Data quality = share of assets positively classified (higher is better). "
            "Unclassified = Tenable type `Unknown` (shown as 'Endpoint' in the UI); "
            "every asset starts there and moves off only when positively classified."
        ),
    }
    if rating == "poor":
        result["warning"] = (
            "Data quality is below the target: many assets are unclassified, so type-based asset "
            "groups (for example 'all Controllers') will miss them. Prefer IP, "
            "segment or asset-list groups until classification improves."
        )
    if by_type:
        counts = {
            t: _count(data.get(_type_alias(t)))
            for t in _FILTER_ASSET_TYPES
            if t != UNCLASSIFIED_TYPE
        }
        counts[UNCLASSIFIED_TYPE] = unclassified
        by = {t: n for t, n in sorted(counts.items(), key=lambda kv: -kv[1]) if n}
        result["by_type"] = by
        other = total - sum(by.values())
        if other > 0:
            result["by_type_other"] = other
    return result


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
    async def summarize_environment(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return aggregate counts across the deployment."""

        async def query_site(machine_id: str) -> dict[str, Any]:
            d = await client.query(_QUERY_SUMMARY, icp_machine_id=machine_id)
            return {
                "site_uuid": machine_id,
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

        return await run_site_read(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
            worker=query_site,
        )


    @mcp.tool(
        title="Asset classification quality",
        description=(
            "Reports asset data quality: the percentage of assets that are "
            "positively classified (higher is better). Every asset starts as "
            "'Endpoint' (Tenable type `Unknown`) and only moves off it when "
            "positively classified, so this shows how settled discovery and "
            "enrichment are.\n\n"
            "Returns data_quality_pct and a rating against a target: good "
            "when data quality is at or above `min_quality_pct` (default 90), "
            "otherwise poor, plus assets_total, classified, unclassified and "
            "unclassified_pct, and a warning when poor: type-based asset "
            "groups will miss unclassified assets. Set `by_type=true` for a "
            "per-type breakdown. Counts only; never lists assets. Call this "
            "for 'data quality', 'how many assets are unclassified', or "
            "before building zones from asset types."
        ),
    )
    async def get_classification_summary(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        by_type: bool = False,
        min_quality_pct: float = DEFAULT_MIN_QUALITY_PCT,
    ) -> dict[str, Any]:
        """Return unclassified-asset counts and ratio per site."""
        if not 0.0 <= min_quality_pct <= 100.0:
            raise ValueError(f"min_quality_pct must be between 0 and 100; got {min_quality_pct}")
        query = _classification_query(by_type)

        async def query_site(machine_id: str) -> dict[str, Any]:
            data = await client.query(query, icp_machine_id=machine_id)
            return classification_result(machine_id, data, by_type, min_quality_pct)

        return await run_site_read(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
            worker=query_site,
        )
