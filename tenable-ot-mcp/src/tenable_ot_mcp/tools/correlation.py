# SPDX-License-Identifier: Apache-2.0
"""Correlation tools — relational projections, not analytics.

These tools expose JOINED relational data so the consuming AI can walk
relationships and reason about attack pathways, vulnerability clusters,
temporal patterns, and per-asset intelligence. They do NOT compute
analyses server-side: no graph algorithms, no clustering, no
time-series motif extraction, no LLM calls. The AI does the
interpretation; we provide the schema.

Schema-correctness notes (verified live):
  • The top-level `plugins(filter: PluginExpressionsParams)` query's
    `affectedAssets` filter expects a Tenable internal numeric id
    (bigint), not the public `Asset.id` UUID. To get plugins for a
    specific asset, traverse `asset(id).plugins(...)` instead — that
    path uses the UUID and accepts the same filter shape.
  • `EventsExpressionsParams` filter on `srcAssets` / `dstAssets` does
    accept the UUID.
  • `LinkExpressionsParams` filter on `asset1` / `asset2` accepts the
    UUID; either side may be the queried asset, so OR them.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import (
    EXPR_EQUAL,
    EXPR_GREATER_EQUAL,
    EXPR_IN,
    EXPR_LESS_EQUAL,
    EXPR_OR,
    expr,
    expr_and,
)
from ._shared import clamp_page_size, project_event, project_vuln, unwrap_nodes

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

_ASSET_CORE = """
  id
  name
  type
  vendor
  model
  criticality
  purdueLevel
  hidden
  ips(first: 20) { nodes }
  segments(first: 20) { nodes { id name type } }
  risk { totalRisk pluginCount unresolvedEvents }
"""

_GET_ASSET_CORE = "query Q($id: ID!) { asset(id: $id) { " + _ASSET_CORE + " } }"

_QUERY_LINKS_FOR_ASSET = """
query Q($pageSize: Int!, $filter: LinkExpressionsParams) {
  links(first: $pageSize, filter: $filter) {
    nodes {
      id
      asset1
      asset2
      traffic
      convCount
      lastConv
      protocols(first: 10) { nodes { name ics } }
    }
  }
}
"""

# Plugins for ONE asset, traversed via asset(id).plugins.
_PLUGINS_FOR_ASSET_FIELDS = """
  id
  name
  severity
  vprScore
  vprLevel
  cvss3Score
  totalAffectedAssets
  details {
    cves
    cvssV3BaseScore
    cvssV3Vector
    exploitAvailable
    exploitedByMalware
    cisaKnownExploitedDates
    vulnPubDate
  }
"""

_QUERY_PLUGINS_FOR_ASSET = (
    "query Q($id: ID!, $pageSize: Int!, $filter: PluginExpressionsParams) {"
    "  asset(id: $id) {"
    "    plugins(first: $pageSize, filter: $filter) {"
    "      totalCount"
    "      nodes { " + _PLUGINS_FOR_ASSET_FIELDS + " }"
    "    }"
    "  }"
    "}"
)

# Global plugin query — used when filtering by CVE substring only
# (no per-asset scope). Includes affectedAssets sublist.
_QUERY_PLUGINS_BY_CVE = """
query Q($pageSize: Int!, $filter: PluginExpressionsParams) {
  plugins(first: $pageSize, filter: $filter) {
    totalCount
    nodes {
      id
      name
      severity
      vprScore
      vprLevel
      cvss3Score
      totalAffectedAssets
      affectedAssets(first: 100) { nodes { id name type vendor criticality } }
      details {
        cves
        cvssV3BaseScore
        cvssV3Vector
        exploitAvailable
        exploitedByMalware
        cisaKnownExploitedDates
        vulnPubDate
      }
    }
  }
}
"""

_EVENT_PROJECTION = """
  id
  time
  severity
  eventType { type group description category family }
  type
  srcIP
  dstIP
  protocolNiceName
  protocol
  port
  srcAssets(first: 5) { nodes { id name } }
  dstAssets(first: 5) { nodes { id name } }
  policy { id title level }
  findingId
  resolved
  resolvedTs
"""

_QUERY_EVENTS = (
    "query Q($pageSize: Int!, $filter: EventsExpressionsParams, "
    "$sort: [EventsSortParams!]) {"
    "  events(first: $pageSize, filter: $filter, sort: $sort) {"
    "    totalCount nodes { " + _EVENT_PROJECTION + " }"
    "  }"
    "}"
)

# Per-asset events: traverse asset(id).events. The top-level events
# filter (PolicyHitField) does NOT include srcAssets/dstAssets — to
# scope events to one asset we must traverse the Asset.events
# connection, which DOES accept the same EventsExpressionsParams.
_QUERY_EVENTS_FOR_ASSET = (
    "query Q($id: ID!, $pageSize: Int!, $filter: EventsExpressionsParams, "
    "$sort: [EventsSortParams!]) {"
    "  asset(id: $id) {"
    "    events(first: $pageSize, filter: $filter, sort: $sort) {"
    "      totalCount nodes { " + _EVENT_PROJECTION + " }"
    "    }"
    "  }"
    "}"
)


# Severity translation for the per-asset PluginExpressionsParams filter.
_SEVERITY_ORDINAL = ["info", "low", "medium", "high", "critical"]
_SEVERITY_TENABLE = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def _severity_at_least(natural: str) -> list[str]:
    v = (natural or "").strip().lower()
    if v not in _SEVERITY_TENABLE:
        raise ValueError(f"severity must be one of {list(_SEVERITY_TENABLE)}; got {natural!r}")
    idx = _SEVERITY_ORDINAL.index(v)
    return [_SEVERITY_TENABLE[k] for k in _SEVERITY_ORDINAL[idx:]]


# ----------------------------------------------------------------------
# Projections
# ----------------------------------------------------------------------


def _project_asset_compact(node: dict[str, Any]) -> dict[str, Any]:
    risk = node.get("risk") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "vendor": node.get("vendor"),
        "model": node.get("model"),
        "criticality": node.get("criticality"),
        "purdue_level": node.get("purdueLevel"),
        "hidden": node.get("hidden"),
        "ips": unwrap_nodes(node.get("ips")),
        "segments": [
            {"id": s.get("id"), "name": s.get("name"), "type": s.get("type")}
            for s in unwrap_nodes(node.get("segments"))
        ],
        "risk": {
            "total_risk": risk.get("totalRisk"),
            "plugin_count": risk.get("pluginCount"),
            "unresolved_events": risk.get("unresolvedEvents"),
        },
    }


def _project_neighbor_link(link: dict[str, Any], self_id: str) -> dict[str, Any]:
    """Fold a link so the queried asset is `self` and the other side
    is `peer_id`. Peer enrichment is the AI's job (call get_asset)."""
    a1 = link.get("asset1")
    a2 = link.get("asset2")
    peer_id = a2 if a1 == self_id else a1
    protos = unwrap_nodes(link.get("protocols"))
    return {
        "link_id": link.get("id"),
        "peer_id": peer_id,
        "traffic": link.get("traffic"),
        "conversation_count": link.get("convCount"),
        "last_conversation": link.get("lastConv"),
        "protocols": [p.get("name") for p in protos if p.get("name")],
    }


def _link_filter_for_asset(asset_id: str) -> dict[str, Any]:
    return {
        "op": EXPR_OR,
        "expressions": [
            expr("asset1", EXPR_EQUAL, [asset_id]),
            expr("asset2", EXPR_EQUAL, [asset_id]),
        ],
    }


def _build_per_asset_plugin_filter(
    severity_at_least: str | None,
    cve_substring: str | None,
) -> dict[str, Any] | None:
    parts: list[dict] = []
    if severity_at_least:
        parts.append(expr("severity", EXPR_IN, _severity_at_least(severity_at_least)))
    if cve_substring:
        parts.append({"field": "name", "op": "Like", "values": [f"%{cve_substring}%"]})
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register correlation tools — pure relational projections."""

    @mcp.tool(
        title="Query attack-pathway data (relational, not computed)",
        description=(
            "Returns the asset's 1-hop network neighborhood: the asset "
            "itself plus a list of peer-asset IDs it has communicated "
            "with, with the protocols and conversation count of each "
            "link. Use this AS THE GRAPH the AI walks to reason about "
            "attack paths — call again on each peer's id to expand "
            "further. The server does NOT compute paths, pick "
            "highest-risk routes, or score compromise time. That's the "
            "AI's job. Peer assets are returned as IDs only — call "
            "`get_asset` on each to enrich with name / vendor / type."
        ),
    )
    async def query_attack_pathways(
        entry_asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        max_peers: int = 100,
    ) -> dict[str, Any]:
        """Return one asset and its 1-hop comms peers.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            entry_asset_id: The starting asset's id.
            max_peers: Cap on returned peers per call (default 100,
                max 500).
        """
        if not entry_asset_id:
            raise ValueError("entry_asset_id is required")
        page_size = clamp_page_size(max_peers, default=100)
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)

        asset_data = await client.query(
            _GET_ASSET_CORE,
            variables={"id": entry_asset_id},
            icp_machine_id=machine_id,
        )
        center = asset_data.get("asset")
        if not center:
            return {"asset": None, "error": f"No asset with id {entry_asset_id!r}."}

        link_data = await client.query(
            _QUERY_LINKS_FOR_ASSET,
            variables={
                "pageSize": page_size,
                "filter": _link_filter_for_asset(entry_asset_id),
            },
            icp_machine_id=machine_id,
        )
        peers = [
            _project_neighbor_link(link, entry_asset_id)
            for link in unwrap_nodes(link_data.get("links"))
        ]
        return {
            "asset": _project_asset_compact(center),
            "peer_count": len(peers),
            "peers": peers,
        }

    @mcp.tool(
        title="Query vulnerability clusters (relational join, not computed)",
        description=(
            "Returns the per-asset → vulnerabilities join the consuming "
            "AI uses to spot common CVEs across multiple assets, "
            "exploit chains (KEV + exploit-available + high "
            "criticality), or single-patch leverage points (one CVE "
            "fixing many). Two modes:\n\n"
            "  • Pass `asset_ids`: parallel per-asset traversal of "
            "asset.plugins, returning each asset's vulns with the same "
            "schema. The AI walks the result to find shared CVEs.\n"
            "  • Pass `cve_substring` only: global plugin search "
            "(e.g. 'CVE-2023' for a year-bucket), each plugin coming "
            "with its full affectedAssets list joined.\n\n"
            "Both args may be combined for a per-asset CVE-filtered "
            "view. The server does NOT cluster server-side."
        ),
    )
    async def query_vulnerability_clusters(
        site_uuid: str | None = None,
        site_name: str | None = None,
        asset_ids: list[str] | None = None,
        cve_substring: str | None = None,
        severity_at_least: str | None = None,
        per_asset_limit: int = 100,
        global_limit: int = 100,
    ) -> dict[str, Any]:
        """Return the per-asset → vulns join, or a global CVE-substring search.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            asset_ids: List of asset UUIDs. When given, runs a parallel
                asset.plugins query per asset.
            cve_substring: CVE id or year-bucket (e.g. 'CVE-2023-25619'
                or 'CVE-2023'). Substring-matched on plugin name.
            severity_at_least: Floor: 'info' | 'low' | 'medium' |
                'high' | 'critical'.
            per_asset_limit: Per-asset result cap (default 100).
            global_limit: Global plugin search cap (default 100).
        """
        if not asset_ids and not cve_substring:
            return {
                "mode": None,
                "error": "Provide at least one of asset_ids or cve_substring.",
            }
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)

        if asset_ids:
            page_size = clamp_page_size(per_asset_limit, default=100)
            filt = _build_per_asset_plugin_filter(severity_at_least, cve_substring)
            variables_template: dict[str, Any] = {"pageSize": page_size}
            if filt is not None:
                variables_template["filter"] = filt

            async def fetch(aid: str) -> dict[str, Any]:
                vars_ = dict(variables_template, id=aid)
                d = await client.query(
                    _QUERY_PLUGINS_FOR_ASSET,
                    variables=vars_,
                    icp_machine_id=machine_id,
                )
                a = d.get("asset") or {}
                block = a.get("plugins") or {}
                return {
                    "asset_id": aid,
                    "total_count": block.get("totalCount"),
                    "vulnerabilities": [project_vuln(p) for p in (block.get("nodes") or [])],
                }

            results = await asyncio.gather(*(fetch(aid) for aid in asset_ids))
            return {
                "mode": "per_asset",
                "asset_count": len(results),
                "by_asset": results,
            }

        # cve_substring-only path: global plugin search.
        page_size = clamp_page_size(global_limit, default=100)
        parts: list[dict] = [{"field": "name", "op": "Like", "values": [f"%{cve_substring}%"]}]
        if severity_at_least:
            parts.append(expr("severity", EXPR_IN, _severity_at_least(severity_at_least)))
        global_filt = parts[0] if len(parts) == 1 else expr_and(*parts)
        data = await client.query(
            _QUERY_PLUGINS_BY_CVE,
            variables={"pageSize": page_size, "filter": global_filt},
            icp_machine_id=machine_id,
        )
        out = []
        for p in unwrap_nodes(data.get("plugins")):
            proj = project_vuln(p)
            proj["affected_assets"] = [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "vendor": a.get("vendor"),
                    "criticality": a.get("criticality"),
                }
                for a in unwrap_nodes(p.get("affectedAssets"))
            ]
            out.append(proj)
        return {
            "mode": "global_cve",
            "count": len(out),
            "vulnerabilities": out,
        }

    @mcp.tool(
        title="Query temporal patterns (event sequence, not motif analysis)",
        description=(
            "Returns events in a time window, ordered chronologically, "
            "with their classification, firing policy, and source/dest "
            "IPs joined. The AI uses this raw sequence to detect "
            "patterns (e.g. config-download + firmware-change + "
            "operating-mode-change within minutes = high-priority "
            "investigation). The server does NOT detect motifs, score "
            "patterns, or label sequences."
        ),
    )
    async def query_temporal_patterns(
        since: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        until: str | None = None,
        event_types: list[str] | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        """Return events in a time window, oldest first.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            since: ISO-8601; events at or after.
            until: Optional ISO-8601 upper bound.
            event_types: Optional list of PolicyEventType names
                (e.g. ['FirmwareVersionChange',
                'ConfigurationDownload']). Multiple values OR together.
            limit: Maximum events (default 200, max 500).
        """
        if not since:
            raise ValueError("since is required (ISO-8601 timestamp)")
        page_size = clamp_page_size(limit, default=200)
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        parts: list[dict] = [expr("time", EXPR_GREATER_EQUAL, [since])]
        if until:
            parts.append(expr("time", EXPR_LESS_EQUAL, [until]))
        if event_types:
            if len(event_types) == 1:
                parts.append(expr("type", EXPR_EQUAL, [event_types[0]]))
            else:
                parts.append({"field": "type", "op": "In", "values": list(event_types)})
        filt = parts[0] if len(parts) == 1 else expr_and(*parts)

        data = await client.query(
            _QUERY_EVENTS,
            variables={
                "pageSize": page_size,
                "filter": filt,
                "sort": [{"field": "time", "direction": "AscNullLast"}],
            },
            icp_machine_id=machine_id,
        )
        block = data.get("events") or {}
        events = [project_event(e) for e in (block.get("nodes") or [])]
        return {
            "count": len(events),
            "total_count": block.get("totalCount"),
            "events": events,
        }

    @mcp.tool(
        title="Get asset intelligence bundle (joined data, not narrative)",
        description=(
            "Returns one asset's full relational bundle in a single "
            "shot: asset core + open vulnerabilities + recent events "
            "where the asset is source or destination + 1-hop comms "
            "peers. The AI uses this bundle to write a per-asset "
            "intelligence narrative if asked. The server does NOT "
            "generate the narrative itself."
        ),
    )
    async def get_asset_intelligence(
        asset_id: str,
        recent_event_window_iso: str | None = None,
        max_peers: int = 50,
        max_vulns: int = 50,
        max_events: int = 50,
    ) -> dict[str, Any]:
        """Return asset / vulns / events / peers in one bundle.

        Args:
            asset_id: The asset's id.
            recent_event_window_iso: Optional ISO-8601 timestamp;
                events scope. Without it, the most recent
                `max_events` events are returned regardless of time.
            max_peers / max_vulns / max_events: Caps per section
                (default 50 each, max 500).
        """
        if not asset_id:
            raise ValueError("asset_id is required")

        # 1. Asset core
        asset_data = await client.query(_GET_ASSET_CORE, variables={"id": asset_id})
        center = asset_data.get("asset")
        if not center:
            return {"asset": None, "error": f"No asset with id {asset_id!r}."}

        # 2. Vulns affecting this asset (via asset.plugins)
        vuln_data = await client.query(
            _QUERY_PLUGINS_FOR_ASSET,
            variables={
                "id": asset_id,
                "pageSize": clamp_page_size(max_vulns, default=50),
            },
        )
        vuln_block = (vuln_data.get("asset") or {}).get("plugins") or {}
        vulns = [project_vuln(p) for p in (vuln_block.get("nodes") or [])]

        # 3. Events involving this asset (asset.events traversal).
        event_vars: dict[str, Any] = {
            "id": asset_id,
            "pageSize": clamp_page_size(max_events, default=50),
            "sort": [{"field": "time", "direction": "DescNullLast"}],
        }
        if recent_event_window_iso:
            event_vars["filter"] = expr("time", EXPR_GREATER_EQUAL, [recent_event_window_iso])
        event_data = await client.query(_QUERY_EVENTS_FOR_ASSET, variables=event_vars)
        event_block = (event_data.get("asset") or {}).get("events") or {}
        events = [project_event(e) for e in (event_block.get("nodes") or [])]

        # 4. Comms peers
        link_data = await client.query(
            _QUERY_LINKS_FOR_ASSET,
            variables={
                "pageSize": clamp_page_size(max_peers, default=50),
                "filter": _link_filter_for_asset(asset_id),
            },
        )
        peers = [
            _project_neighbor_link(link, asset_id) for link in unwrap_nodes(link_data.get("links"))
        ]

        return {
            "asset": _project_asset_compact(center),
            "vulnerabilities": vulns,
            "vulnerability_total": vuln_block.get("totalCount"),
            "recent_events": events,
            "events_total": event_block.get("totalCount"),
            "peers": peers,
        }
