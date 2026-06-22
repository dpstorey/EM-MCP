# SPDX-License-Identifier: Apache-2.0
"""Network topology tools: list_segments_and_zones, get_communication_paths.

Tenable OT models the operator's network as `segmentGroups` (segments)
and `zones`, plus a `links` connection that records observed L2
communication pairs. Segments and zones support compliance evidence
(IEC 62443 Zone & Conduit, NERC CIP ESP, NEI 08-09 defense-in-depth).
Links provide the graph adjacency the consuming AI walks for
attack-pathway reasoning — peer assets are returned as IDs, and the AI
calls `get_asset` on each peer to enrich.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import EXPR_EQUAL, EXPR_GREATER_EQUAL, EXPR_OR, expr, expr_and
from ._shared import clamp_page_size, unwrap_nodes

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

_SEGMENT_FIELDS = """
  id
  name
  type
  vlan
  subnet
  description
  archived
  system
  assetType
  isStaticType
  displayTag
  lastModifiedDate
  lastModifiedBy
"""

_ZONE_FIELDS = """
  id
  name
  description
  lastModifiedDate
  lastModifiedBy
"""

_QUERY_SEGMENTS = "query Q { segmentGroups(first: 500) { nodes { " + _SEGMENT_FIELDS + " } } }"

_QUERY_ZONES = "query Q { zones(first: 500) { nodes { " + _ZONE_FIELDS + " } } }"


_QUERY_LINKS = """
query Q($pageSize: Int!, $filter: LinkExpressionsParams, $sort: [LinkSortParams!]) {
  links(first: $pageSize, filter: $filter, sort: $sort) {
    pageInfo { hasNextPage endCursor }
    totalCount
    nodes {
      id
      asset1
      asset2
      traffic
      convCount
      firstConv
      lastConv
      protocols(first: 20) { nodes { name ics } }
    }
  }
}
"""


# ----------------------------------------------------------------------
# Projections
# ----------------------------------------------------------------------


def _project_segment(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "asset_type": node.get("assetType"),
        "vlan": node.get("vlan"),
        "subnet": node.get("subnet"),
        "description": node.get("description"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "is_static": node.get("isStaticType"),
        "display_tag": node.get("displayTag"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
    }


def _project_zone(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "description": node.get("description"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
    }


def _project_link(node: dict[str, Any]) -> dict[str, Any]:
    protos = unwrap_nodes(node.get("protocols"))
    return {
        "id": node.get("id"),
        "asset_a_id": node.get("asset1"),
        "asset_b_id": node.get("asset2"),
        "traffic": node.get("traffic"),
        "conversation_count": node.get("convCount"),
        "first_conversation": node.get("firstConv"),
        "last_conversation": node.get("lastConv"),
        "protocols": [p.get("name") for p in protos if p.get("name")],
        "industrial_protocols": [p.get("name") for p in protos if p.get("ics")],
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only topology tools."""

    @mcp.tool(
        title="List network segments and zones",
        description=(
            "Returns Tenable OT's segmentation: every segment (with "
            "VLAN, subnet, asset-type filter, system flag, archived "
            "flag) and every zone (a higher-level grouping of asset "
            "groups). Use this to answer compliance questions about "
            "the IEC 62443 Zone & Conduit model, NERC CIP Electronic "
            "Security Perimeters, or NEI 08-09 defense-in-depth."
        ),
    )
    async def list_segments_and_zones() -> dict[str, Any]:
        """Return all segments and zones."""
        seg_data = await client.query(_QUERY_SEGMENTS)
        zone_data = await client.query(_QUERY_ZONES)
        segments = unwrap_nodes(seg_data.get("segmentGroups"))
        zones = unwrap_nodes(zone_data.get("zones"))
        return {
            "segments": [_project_segment(s) for s in segments],
            "zones": [_project_zone(z) for z in zones],
        }

    @mcp.tool(
        title="Get communication paths for an asset",
        description=(
            "Returns observed L2 communication links involving one OT "
            "asset, with peer asset id, protocols seen, traffic / "
            "conversation count, and first/last-conversation times. "
            "Peer assets are returned as IDs only — call `get_asset` on "
            "each peer id to enrich with name / vendor / type. The "
            "consuming AI uses this as the graph adjacency for "
            "attack-path reasoning; call again on a peer's id to "
            "expand further."
        ),
    )
    async def get_communication_paths(
        asset_id: str,
        since: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        """List communication links involving one asset.

        Args:
            asset_id: The asset's id.
            since: ISO-8601; only links last-seen at or after.
            limit: Maximum results (default 200, max 500).
        """
        if not asset_id:
            raise ValueError("asset_id is required")
        page_size = clamp_page_size(limit, default=200)

        # A link is keyed by `asset1` and `asset2`; either side might be
        # the queried asset. OR the two equality clauses.
        side_match = {
            "op": EXPR_OR,
            "expressions": [
                expr("asset1", EXPR_EQUAL, [asset_id]),
                expr("asset2", EXPR_EQUAL, [asset_id]),
            ],
        }
        if since:
            filt = expr_and(side_match, expr("lastConv", EXPR_GREATER_EQUAL, [since]))
        else:
            filt = side_match

        variables: dict[str, Any] = {
            "pageSize": page_size,
            "filter": filt,
            "sort": [{"field": "lastConv", "direction": "DescNullLast"}],
        }
        data = await client.query(_QUERY_LINKS, variables=variables)
        block = data.get("links") or {}
        nodes = block.get("nodes") or []
        page_info = block.get("pageInfo") or {}
        # Fold each link so the queried asset is consistently the "self"
        # side and the peer is `peer_id`.
        peers: list[dict[str, Any]] = []
        for n in nodes:
            link = _project_link(n)
            self_side = "a" if link["asset_a_id"] == asset_id else "b"
            peer_id = link["asset_b_id"] if self_side == "a" else link["asset_a_id"]
            peers.append(
                {
                    "link_id": link["id"],
                    "peer_id": peer_id,
                    "protocols": link["protocols"],
                    "traffic": link["traffic"],
                    "conversation_count": link["conversation_count"],
                    "first_conversation": link["first_conversation"],
                    "last_conversation": link["last_conversation"],
                }
            )

        return {
            "asset_id": asset_id,
            "count": len(peers),
            "total_count": block.get("totalCount"),
            "has_more": bool(page_info.get("hasNextPage")),
            "links": peers,
        }
