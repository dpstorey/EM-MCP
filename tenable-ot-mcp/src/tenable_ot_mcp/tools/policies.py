# SPDX-License-Identifier: Apache-2.0
"""Detection policy tools: list_detection_policies, query_policy_findings.

Detection policies are the rules that fire OT events. Tenable OT's
`policies` GraphQL query has no server-side filter argument — only
pagination — so this tool fetches all configured policies (capped at
`limit`) and applies category / enabled / search filtering
client-side. Per-asset findings are exposed via `policyFindings`,
which DOES support a filter expression tree.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import (
    EXPR_EQUAL,
    EXPR_GREATER_EQUAL,
    EXPR_IN,
    expr,
    expr_and,
    to_policy_level,
)
from ._shared import clamp_page_size, unwrap_nodes
from ._sites import run_site_read

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

_POLICY_FIELDS = """
  id
  title
  level
  disabled
  archived
  paused
  system
  continuous
  snapshot
  key
  lastModifiedDate
  lastModifiedBy
  disableAfterHit
  eventTypeDetails { type group description category family }
  aggregatedEventsCount { last24h last7d last30d }
"""

_QUERY_POLICIES = (
    "query Q($pageSize: Int!, $after: String) { "
    "policies(first: $pageSize, after: $after) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _POLICY_FIELDS + " } "
    "} "
    "}"
)


_FINDING_FIELDS = """
  id
  policyTitle
  severity
  status
  firstHitTime
  lastHitTime
  activeHits
  resolvedHits
  activePolicyHits
  pluginId
  pluginName
  category
  eventType { type group description category family }
  policy { id title level disabled }
  srcAssets(first: 5) { nodes { id name type } }
  dstAssets(first: 5) { nodes { id name type } }
"""

_QUERY_POLICY_FINDINGS = (
    "query Q($pageSize: Int!, $after: String, "
    "$filter: PolicyFindingsExpressionsParams, $search: String, "
    "$sort: [PolicyFindingsSortParams!]) { "
    "policyFindings(first: $pageSize, after: $after, filter: $filter, "
    "search: $search, sort: $sort) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _FINDING_FIELDS + " } "
    "} "
    "}"
)


# Severity floor → Tenable PolicyLevel In-list.
_POLICY_LEVEL_ORDINAL = ["none", "low", "medium", "high"]


def _to_policy_level_at_least(natural: str) -> list[str]:
    v = (natural or "").strip().lower()
    if v not in _POLICY_LEVEL_ORDINAL:
        raise ValueError(f"severity must be one of {_POLICY_LEVEL_ORDINAL}; got {natural!r}")
    idx = _POLICY_LEVEL_ORDINAL.index(v)
    return [to_policy_level(k) for k in _POLICY_LEVEL_ORDINAL[idx:]]


# ----------------------------------------------------------------------
# Projections
# ----------------------------------------------------------------------


def _project_policy(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten Policy. The natural shape exposes `enabled` (the
    inverse of Tenable's `disabled`) and a category derived from
    `eventTypeDetails.category` rather than a nonexistent top-level
    Policy.category field."""
    et = node.get("eventTypeDetails") or {}
    counts = node.get("aggregatedEventsCount") or {}
    return {
        "id": node.get("id"),
        "title": node.get("title"),
        "level": node.get("level"),
        "enabled": (not node.get("disabled")) if node.get("disabled") is not None else None,
        "paused": node.get("paused"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "continuous": node.get("continuous"),
        "snapshot": node.get("snapshot"),
        "disable_after_hit": node.get("disableAfterHit"),
        "key": node.get("key"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
        "category": et.get("category"),
        "event_type_group": et.get("group"),
        "event_type_family": et.get("family"),
        "event_type_description": et.get("description"),
        "events_last_24h": counts.get("last24h"),
        "events_last_7d": counts.get("last7d"),
        "events_last_30d": counts.get("last30d"),
    }


def _project_finding(node: dict[str, Any]) -> dict[str, Any]:
    et = node.get("eventType") or {}
    policy = node.get("policy") or {}
    return {
        "id": node.get("id"),
        "policy_title": node.get("policyTitle"),
        "severity": node.get("severity"),
        "status": node.get("status"),
        "first_hit_time": node.get("firstHitTime"),
        "last_hit_time": node.get("lastHitTime"),
        "active_hits": node.get("activeHits"),
        "resolved_hits": node.get("resolvedHits"),
        "active_policy_hits": node.get("activePolicyHits"),
        "plugin_id": node.get("pluginId"),
        "plugin_name": node.get("pluginName"),
        "category": node.get("category"),
        "event_type": et.get("type"),
        "event_type_group": et.get("group"),
        "policy": (
            {
                "id": policy.get("id"),
                "title": policy.get("title"),
                "level": policy.get("level"),
                "enabled": (
                    (not policy.get("disabled")) if policy.get("disabled") is not None else None
                ),
            }
            if policy
            else None
        ),
        "src_assets": [
            {"id": a.get("id"), "name": a.get("name"), "type": a.get("type")}
            for a in unwrap_nodes(node.get("srcAssets"))
        ],
        "dst_assets": [
            {"id": a.get("id"), "name": a.get("name"), "type": a.get("type")}
            for a in unwrap_nodes(node.get("dstAssets"))
        ],
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only detection-policy tools."""

    @mcp.tool(
        title="List detection policies",
        description=(
            "Returns OT detection policies — the rules that fire events. "
            "Each policy has a level (severity), enabled / paused / "
            "archived flags, an event-type classification, and aggregate "
            "fired-event counts. Use this to audit which policies are "
            "configured, which are noisy, or which are paused. Call "
            "`query_policy_findings` for the per-asset hits one policy "
            "is producing.\n\n"
            "Note: Tenable OT's `policies` query supports pagination "
            "only — the category / enabled / search filters below are "
            "applied client-side after fetching a page. For large "
            "deployments, increase `limit` to capture more before "
            "filtering."
        ),
    )
    async def list_detection_policies(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        category: str | None = None,
        enabled: bool | None = None,
        paused: bool | None = None,
        search: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        """List detection policies (client-side filtered).

        Args:
            category: Filter by event-type category (e.g. "Anomaly",
                "IntrusionDetection", "ConfigurationChange",
                "AssetDiscovery"). Matches the policy's
                `eventTypeDetails.category`.
            enabled: True returns only enabled policies; False only
                disabled; None (default) returns both.
            paused: True returns only paused policies; False only
                non-paused; None (default) returns both.
            search: Substring (case-insensitive) on policy title.
            limit: Maximum policies to return (default 200, max 500).
        """
        page_size = clamp_page_size(limit, default=200)

        # Client-side filter pass.
        def keep(p: dict[str, Any]) -> bool:
            if category and (p.get("category") != category):
                return False
            if enabled is True and not p.get("enabled"):
                return False
            if enabled is False and p.get("enabled"):
                return False
            if paused is True and not p.get("paused"):
                return False
            if paused is False and p.get("paused"):
                return False
            if search:
                title = (p.get("title") or "").lower()
                if search.lower() not in title:
                    return False
            return True

        async def query_site(machine_id: str) -> dict[str, Any]:
            data = await client.query(
                _QUERY_POLICIES,
                variables={"pageSize": page_size},
                icp_machine_id=machine_id,
            )
            block = data.get("policies") or {}
            nodes = block.get("nodes") or []
            page_info = block.get("pageInfo") or {}
            projected = [_project_policy(node) for node in nodes]
            filtered = [policy for policy in projected if keep(policy)]
            for policy in filtered:
                policy["site_uuid"] = machine_id
                policy["policy_ref"] = {
                    "site_uuid": machine_id,
                    "policy_id": policy.get("id"),
                }
            return {
                "site_uuid": machine_id,
                "count": len(filtered),
                "total_count_unfiltered": block.get("totalCount"),
                "page_returned": len(projected),
                "has_more_in_tenable": bool(page_info.get("hasNextPage")),
                "policies": filtered,
            }

        return await run_site_read(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
            worker=query_site,
        )

    @mcp.tool(
        title="Query policy findings",
        description=(
            "Returns per-asset findings for one or more detection "
            "policies — i.e. the rows of (policy × asset × hit count) "
            "that the policies have produced. Use this to see which "
            "assets keep tripping a policy (often a tuning gap), or "
            "which assets are MITRE-mapped to a specific technique. "
            "Each finding has firstHitTime / lastHitTime, activeHits / "
            "resolvedHits, status, and joined source / destination "
            "assets.\n\n"
            "Filter values use natural OT vocabulary:\n"
            "  • severity_at_least: one of 'none', 'low', 'medium', 'high'\n"
            "  • status: a FindingStatus value (e.g. 'Open', 'Resolved')\n"
            "  • mitre_technique: a MITRE ATT&CK id (e.g. 'T1565.001')\n"
            "  • since: ISO-8601 timestamp; findings last-seen at or after"
        ),
    )
    async def query_policy_findings(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        policy_id: str | None = None,
        severity_at_least: str | None = None,
        status: str | None = None,
        since: str | None = None,
        mitre_technique: str | None = None,
        plugin_id: str | None = None,
        search: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Filter policy findings.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            policy_id: Equal-match on the firing policy's id.
            severity_at_least: One of "none" / "low" / "medium" / "high".
            status: FindingStatus enum value.
            since: ISO-8601; findings with `lastHitTime >= since`.
            mitre_technique: Equal-match on MITRE ATT&CK technique id.
            plugin_id: Equal-match on the firing plugin id.
            search: Single-term, case-insensitive substring across
                finding text fields.
            limit: Maximum results (default 100, max 500).

        Note: numeric-floor filters on `activeHits` aren't supported by
        Tenable's GraphQL — fetch results and filter client-side on
        the projected `active_hits` field.
        """
        page_size = clamp_page_size(limit, default=100)
        parts: list[dict] = []
        if policy_id:
            parts.append(expr("policyId", EXPR_EQUAL, [policy_id]))
        if severity_at_least:
            parts.append(expr("severity", EXPR_IN, _to_policy_level_at_least(severity_at_least)))
        if status:
            parts.append(expr("status", EXPR_EQUAL, [status]))
        if since:
            parts.append(expr("lastHitTime", EXPR_GREATER_EQUAL, [since]))
        if mitre_technique:
            parts.append(expr("mitreTechniques", EXPR_EQUAL, [mitre_technique]))
        if plugin_id:
            parts.append(expr("pluginId", EXPR_EQUAL, [str(plugin_id)]))

        variables: dict[str, Any] = {
            "pageSize": page_size,
            "sort": [{"field": "lastHitTime", "direction": "DescNullLast"}],
        }
        if parts:
            variables["filter"] = parts[0] if len(parts) == 1 else expr_and(*parts)
        if search:
            variables["search"] = search

        async def query_site(machine_id: str) -> dict[str, Any]:
            data = await client.query(
                _QUERY_POLICY_FINDINGS,
                variables=variables,
                icp_machine_id=machine_id,
            )
            block = data.get("policyFindings") or {}
            nodes = block.get("nodes") or []
            page_info = block.get("pageInfo") or {}
            findings = [_project_finding(node) for node in nodes]
            for finding in findings:
                finding["site_uuid"] = machine_id
            return {
                "site_uuid": machine_id,
                "count": len(nodes),
                "total_count": block.get("totalCount"),
                "has_more": bool(page_info.get("hasNextPage")),
                "findings": findings,
            }

        return await run_site_read(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
            worker=query_site,
        )
