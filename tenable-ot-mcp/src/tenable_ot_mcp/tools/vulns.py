# SPDX-License-Identifier: Apache-2.0
"""Vulnerability tools: query_vulnerabilities, get_vulnerability.

Tenable OT models vulnerabilities as Tenable plugins. Each plugin
describes one vulnerability check; an asset is "affected" when the
asset matches the plugin's triggering conditions.

Filter scope notes (verified live):

  • `severity` (PluginSeverity enum: Info / Low / Medium / High /
    Critical) — supported via Equal / In.
  • `name` Like '%CVE-2023-12345%' — works for CVE-substring matching.
  • `family`, `source`, `owner` — exact-match filters supported.
  • Numeric filters on `cvss3Score`, `affectedAssets`, `vprScore` are
    NOT supported by this GraphQL surface (Tenable returns 500 with
    "cannot use array or slice with less than or greater than
    operators"). For score-based prioritization, fetch and sort/filter
    on the projected fields client-side.
  • `kev_only`, `exploit_available`, etc. live on `PluginDetails`,
    NOT in the top-level `PluginField` filter enum — fetch results
    and inspect the projected flags client-side.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import EXPR_EQUAL, EXPR_IN, EXPR_LIKE, expr, expr_and
from ._shared import clamp_page_size, project_vuln, unwrap_nodes

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

_VULN_FIELDS = """
  id
  name
  source
  family
  severity
  vprScore
  vprLevel
  cvss3Score
  totalAffectedAssets
  totalFixedAssets
  details {
    description
    solution
    cves
    cvssV3BaseScore
    cvssV3Vector
    exploitAvailable
    exploitedByMalware
    cisaKnownExploitedDates
    threatRecency
    threatIntensity
    exploitCodeMaturity
    pluginPubDate
    vulnPubDate
    ageOfVuln
  }
"""

_QUERY_VULNS = (
    "query Q($pageSize: Int!, $after: String, "
    "$filter: PluginExpressionsParams, $search: String) { "
    "plugins(first: $pageSize, after: $after, filter: $filter, search: $search) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _VULN_FIELDS + " } "
    "} "
    "}"
)


_AFFECTED_ASSET_FIELDS = "id name type vendor model criticality firstSeen lastSeen"

_GET_VULN = (
    "query Q($id: ID!) { plugin(id: $id) { "
    + _VULN_FIELDS
    + " affectedAssets(first: 200) { nodes { "
    + _AFFECTED_ASSET_FIELDS
    + " } } "
    + "} }"
)


# Severity translation — natural floor → list of acceptable severities.
_SEVERITY_ORDINAL = ["info", "low", "medium", "high", "critical"]
_SEVERITY_NATURAL_TO_TENABLE = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
SEVERITY_VALUES = list(_SEVERITY_ORDINAL)


def _to_severity_at_least(natural: str) -> list[str]:
    v = (natural or "").strip().lower()
    if v not in _SEVERITY_NATURAL_TO_TENABLE:
        raise ValueError(f"severity must be one of {SEVERITY_VALUES}; got {natural!r}")
    idx = _SEVERITY_ORDINAL.index(v)
    return [_SEVERITY_NATURAL_TO_TENABLE[k] for k in _SEVERITY_ORDINAL[idx:]]


def _build_vuln_filter(
    *,
    cve: str | None,
    severity_at_least: str | None,
    family: str | None,
    source: str | None,
) -> dict | None:
    parts: list[dict] = []
    if cve:
        # Plugin names typically contain the CVE id.
        parts.append(expr("name", EXPR_LIKE, [f"%{cve}%"]))
    if severity_at_least:
        parts.append(expr("severity", EXPR_IN, _to_severity_at_least(severity_at_least)))
    if family:
        parts.append(expr("family", EXPR_EQUAL, [family]))
    if source:
        parts.append(expr("source", EXPR_EQUAL, [source]))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


def _project_affected_asset(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "vendor": node.get("vendor"),
        "model": node.get("model"),
        "criticality": node.get("criticality"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only vulnerability tools."""

    @mcp.tool(
        title="Query OT vulnerabilities",
        description=(
            "Returns Tenable plugins (vulnerabilities) matching the "
            "filter criteria. Each result includes CVEs, CVSS v3 score "
            "and vector, exploit availability flags (CISA KEV, "
            "exploit-available, exploited-by-malware), age, public "
            "disclosure date, and the official vendor solution. Call "
            "`get_vulnerability` on a returned plugin id to see every "
            "affected asset.\n\n"
            "`total_count` is the full number of plugins matching the "
            "filter, independent of the page size — use it to answer "
            "'how many' questions directly. When the match exceeds one "
            "page the response sets `has_more: true` and returns an "
            "`end_cursor`; pass that as `after` to fetch the next page, "
            "repeating until `has_more` is false to walk the entire "
            "matched set.\n\n"
            "Filter values use natural OT vocabulary:\n"
            "  • severity_at_least: one of 'info', 'low', 'medium', "
            "'high', 'critical'\n"
            "  • cve: a CVE substring (e.g. 'CVE-2023-25619' or "
            "'CVE-2023' for a year-bucket)\n"
            "  • family / source: exact-match plugin metadata\n\n"
            "For KEV-only or exploit-available filtering, inspect the "
            "projected flags in the response — those live on plugin "
            "details and aren't filterable server-side."
        ),
    )
    async def query_vulnerabilities(
        site_uuid: str | None = None,
        site_name: str | None = None,
        cve: str | None = None,
        severity_at_least: str | None = None,
        family: str | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 50,
        after: str | None = None,
    ) -> dict[str, Any]:
        """Filter vulnerabilities and return a projected list.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            cve: A CVE identifier or substring.
            severity_at_least: One of "info" / "low" / "medium" /
                "high" / "critical".
            family: Plugin family (vendor-defined grouping).
            source: Plugin source (e.g. "Tenable").
            search: Single-term, case-insensitive substring across
                plugin text fields.
            limit: Maximum results per page (default 50, max 500).
            after: Opaque page cursor. Omit for the first page; to
                continue, pass the `end_cursor` value from the previous
                response. Keep paging while `has_more` is true to
                retrieve every matching vulnerability.
        """
        page_size = clamp_page_size(limit)
        filt = _build_vuln_filter(
            cve=cve,
            severity_at_least=severity_at_least,
            family=family,
            source=source,
        )
        variables: dict[str, Any] = {"pageSize": page_size}
        if filt is not None:
            variables["filter"] = filt
        if search:
            variables["search"] = search
        if after:
            variables["after"] = after

        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        data = await client.query(_QUERY_VULNS, variables=variables, icp_machine_id=machine_id)
        block = data.get("plugins") or {}
        nodes = block.get("nodes") or []
        page_info = block.get("pageInfo") or {}
        return {
            "count": len(nodes),
            "total_count": block.get("totalCount"),
            "has_more": bool(page_info.get("hasNextPage")),
            "end_cursor": page_info.get("endCursor"),
            "vulnerabilities": [project_vuln(n) for n in nodes],
        }

    @mcp.tool(
        title="Get one vulnerability",
        description=(
            "Returns one Tenable plugin (vulnerability) by id, plus "
            "the full list of OT assets currently affected. Use this "
            "to reason about exposure breadth ('which assets are "
            "affected by this exploited-in-the-wild vuln?'). To look "
            "up by CVE id, call `query_vulnerabilities(cve='CVE-...')` "
            "first and then fetch by the returned plugin_id."
        ),
    )
    async def get_vulnerability(plugin_id: str) -> dict[str, Any]:
        """Fetch one vulnerability and its affected-asset list.

        Args:
            plugin_id: A Tenable plugin id.
        """
        if not plugin_id:
            raise ValueError("plugin_id is required")
        data = await client.query(_GET_VULN, variables={"id": str(plugin_id)})
        node = data.get("plugin")
        if not node:
            return {
                "vulnerability": None,
                "error": f"No plugin with id {plugin_id!r}.",
            }
        out = project_vuln(node)
        out["affected_assets"] = [
            _project_affected_asset(a) for a in unwrap_nodes(node.get("affectedAssets"))
        ]
        return {"vulnerability": out}
