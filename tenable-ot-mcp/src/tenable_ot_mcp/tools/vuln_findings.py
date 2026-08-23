# SPDX-License-Identifier: Apache-2.0
"""Vulnerability finding tools: query_vulnerability_findings.

Tenable OT's `plugins`/`plugin` surface (see `vulns.py`) models the
vulnerability *catalog* — one row per Tenable plugin, with the list of
currently-affected assets. It does not carry per-instance state: when
a given plugin first/last hit a given asset, on what port/protocol,
or whether that specific hit has since been resolved.

That per-(asset x plugin) instance record is a separate GraphQL root
query, `findings`, backed by the `Finding` object type — verified live
against Tenable OT/EM 4.7.44 via schema introspection (this type/query
pair is not covered by Tenable's public docs or by pyTenable). `Finding`
is the vulnerability-side analog of `PolicyFinding` (see `policies.py`):
same three-value lifecycle (`FindingStatus`: Active / Resurfaced /
Resolved) as the product's Policy Violations UI, plus its own id,
firstHit/lastHit timestamps, an optional fixedAt, and per-hit
port/protocol/service/output detail.

(Tenable's schema also exposes a lower-level `pluginHits` root query
over a `PluginHit` type with an overlapping but rougher shape — no id,
a single `time` instant instead of firstHit/lastHit, `mitigatedAt`
instead of `fixedAt`. `findings`/`Finding` is the richer, individually
addressable, filterable-and-sortable surface, so that's what this
module queries.)
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import (
    EXPR_EQUAL,
    EXPR_GREATER_EQUAL,
    EXPR_IN,
    EXPR_LIKE,
    expr,
    expr_and,
    to_finding_status,
)
from ._shared import clamp_page_size
from ._sites import resolve_read_site_ids, run_multi_site_read
from .vulns import _to_severity_at_least

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

# Lean plugin/asset sub-selections — mirrors the lean-by-default
# projection vulns.py uses for `query_vulnerabilities` (full plugin
# `details` are a multi-KB blob not worth carrying on every row of a
# paginated findings listing).
_FINDING_PLUGIN_FIELDS = """
  id
  name
  severity
  vprScore
  vprLevel
  cvss3Score
  details { cves }
"""

_FINDING_ASSET_FIELDS = "id name type"

_FINDING_FIELDS = (
    """
  id
  port
  protocol
  svcName
  firstHit
  lastHit
  fixedAt
  status
  output
  asset { """
    + _FINDING_ASSET_FIELDS
    + " } plugin { "
    + _FINDING_PLUGIN_FIELDS
    + " } "
)

_QUERY_FINDINGS = (
    "query Q($pageSize: Int!, $after: String, "
    "$filter: FindingsObjExpressionsParams, $search: String, "
    "$sort: [FindingsObjSortParams!]) { "
    "findings(first: $pageSize, after: $after, filter: $filter, "
    "search: $search, sort: $sort) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _FINDING_FIELDS + " } "
    "} "
    "}"
)


# ----------------------------------------------------------------------
# Filter + projection
# ----------------------------------------------------------------------


def _build_finding_filter(
    *,
    plugin_id: str | None,
    cve: str | None,
    severity_at_least: str | None,
    status: str | None,
    asset_id: str | None,
    since: str | None,
) -> dict | None:
    parts: list[dict] = []
    if plugin_id:
        parts.append(expr("pluginId", EXPR_EQUAL, [str(plugin_id)]))
    if cve:
        # Plugin names typically contain the CVE id (same convention as
        # vulns.py's `_build_vuln_filter`).
        parts.append(expr("pluginName", EXPR_LIKE, [f"%{cve}%"]))
    if severity_at_least:
        parts.append(expr("pluginSeverity", EXPR_IN, _to_severity_at_least(severity_at_least)))
    if status:
        parts.append(expr("findingStatus", EXPR_EQUAL, [to_finding_status(status)]))
    if asset_id:
        parts.append(expr("assetId", EXPR_EQUAL, [asset_id]))
    if since:
        parts.append(expr("findingLastHit", EXPR_GREATER_EQUAL, [since]))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


def _project_vulnerability_finding(node: dict[str, Any]) -> dict[str, Any]:
    asset = node.get("asset") or {}
    plugin = node.get("plugin") or {}
    details = plugin.get("details") or {}
    cves = details.get("cves") or []
    return {
        "id": node.get("id"),
        "status": node.get("status"),
        "port": node.get("port"),
        "protocol": node.get("protocol"),
        "service_name": node.get("svcName"),
        "first_hit_time": node.get("firstHit"),
        "last_hit_time": node.get("lastHit"),
        "fixed_at": node.get("fixedAt"),
        "output": node.get("output"),
        "plugin_id": plugin.get("id"),
        "plugin_name": plugin.get("name"),
        "severity": plugin.get("severity"),
        "vpr_score": plugin.get("vprScore"),
        "vpr_level": plugin.get("vprLevel"),
        "cvss3_score": plugin.get("cvss3Score"),
        "cves": cves if isinstance(cves, list) else [],
        "asset_id": asset.get("id"),
        "asset_name": asset.get("name"),
        "asset_type": asset.get("type"),
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only vulnerability-finding tools."""

    @mcp.tool(
        title="Query vulnerability findings",
        description=(
            "Returns per-(asset x vulnerability) finding records — the "
            "instances of a Tenable plugin actually being detected on a "
            "specific asset, as opposed to `query_vulnerabilities`' "
            "plugin catalog view. Each finding has its own id, "
            "first_hit_time / last_hit_time, an optional fixed_at, a "
            "lifecycle status ('active', 'resolved', or 'resurfaced' — "
            "same vocabulary the Policy Violations UI uses), and the "
            "port/protocol/service the plugin fired against. Use this "
            "to see when a specific asset first/last tripped a specific "
            "vulnerability, whether it's been fixed, or to list every "
            "currently-active vulnerability finding for an asset or a "
            "site. Call `get_vulnerability` for the full plugin catalog "
            "entry (CVEs, CVSS vector, exploit/KEV flags, solution "
            "text) behind a returned plugin_id.\n\n"
            "Filter values use natural OT vocabulary:\n"
            "  • severity_at_least: one of 'info', 'low', 'medium', "
            "'high', 'critical'\n"
            "  • status: one of 'active', 'resolved', 'resurfaced'\n"
            "  • cve: a CVE substring (matched against the plugin name, "
            "same convention as `query_vulnerabilities`)\n"
            "  • since: ISO-8601 timestamp; findings last hit at or "
            "after this time"
        ),
    )
    async def query_vulnerability_findings(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        plugin_id: str | None = None,
        cve: str | None = None,
        severity_at_least: str | None = None,
        status: str | None = None,
        asset_id: str | None = None,
        since: str | None = None,
        search: str | None = None,
        limit: int = 100,
        after: str | None = None,
        after_by_site: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Filter vulnerability findings and return a projected list.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            plugin_id: Equal-match on the underlying Tenable plugin id.
            cve: A CVE identifier or substring (matched against the
                plugin name).
            severity_at_least: One of "info" / "low" / "medium" /
                "high" / "critical" (default None = any severity).
            status: One of "active" / "resolved" / "resurfaced".
            asset_id: Equal-match on the affected asset's id.
            since: ISO-8601; findings with `last_hit_time >= since`.
            search: Single-term, case-insensitive substring across
                finding text fields.
            limit: Maximum results per page (default 100, max 500).
            after: Opaque page cursor. Omit for the first page; to
                continue, pass the `end_cursor` value from the previous
                response. Keep paging while `has_more` is true to
                retrieve every matching finding.
        """
        page_size = clamp_page_size(limit, default=100)
        filt = _build_finding_filter(
            plugin_id=plugin_id,
            cve=cve,
            severity_at_least=severity_at_least,
            status=status,
            asset_id=asset_id,
            since=since,
        )
        variables: dict[str, Any] = {
            "pageSize": page_size,
            "sort": [{"field": "findingLastHit", "direction": "DescNullLast"}],
        }
        if filt is not None:
            variables["filter"] = filt
        if search:
            variables["search"] = search
        if after and after_by_site:
            raise ValueError("after cannot be combined with after_by_site")
        site_ids = await resolve_read_site_ids(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
        )

        async def query_site(machine_id: str) -> dict[str, Any]:
            site_variables = dict(variables)
            cursor = after if len(site_ids) == 1 else (after_by_site or {}).get(machine_id)
            if cursor:
                site_variables["after"] = cursor
            data = await client.query(
                _QUERY_FINDINGS,
                variables=site_variables,
                icp_machine_id=machine_id,
            )
            block = data.get("findings") or {}
            nodes = block.get("nodes") or []
            page_info = block.get("pageInfo") or {}
            findings = []
            for node in nodes:
                finding = _project_vulnerability_finding(node)
                finding["site_uuid"] = machine_id
                finding["finding_ref"] = {
                    "site_uuid": machine_id,
                    "finding_id": finding.get("id"),
                }
                if finding.get("asset_id"):
                    finding["asset_ref"] = {
                        "site_uuid": machine_id,
                        "asset_id": finding.get("asset_id"),
                    }
                if finding.get("plugin_id"):
                    finding["vulnerability_ref"] = {
                        "site_uuid": machine_id,
                        "plugin_id": finding.get("plugin_id"),
                    }
                findings.append(finding)
            return {
                "site_uuid": machine_id,
                "count": len(nodes),
                "total_count": block.get("totalCount"),
                "has_more": bool(page_info.get("hasNextPage")),
                "end_cursor": page_info.get("endCursor"),
                "findings": findings,
            }

        if len(site_ids) == 1:
            return await query_site(site_ids[0])
        return await run_multi_site_read(site_ids, query_site)
