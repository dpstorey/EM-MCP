# SPDX-License-Identifier: Apache-2.0
"""Asset tools: query_assets, get_asset, get_asset_vulnerabilities.

Each tool is a thin projection of Tenable OT's GraphQL `assets` /
`asset` / `plugins` surface. No analytics, no caching — every call
hits the live deployment and returns relational data the consuming
AI walks via follow-up tool calls.

Tool arguments use **natural OT vocabulary**: criticality is
"low"/"medium"/"high"/"none", asset kind is "controller"/"switch"/etc.
The `_enums` module translates these to Tenable's internal enum
values before the GraphQL goes out.
"""

from __future__ import annotations

import time
from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import (
    ASSET_KIND_VALUES,
    CRITICALITY_VALUES,
    EXPR_EQUAL,
    EXPR_IN,
    EXPR_LIKE,
    expr,
    expr_and,
    to_asset_category,
    to_asset_types,
    to_criticality_at_least,
)
from ._shared import clamp_page_size, project_vuln, unwrap_nodes
from ._sites import resolve_read_site_ids, run_multi_site_read

# ----------------------------------------------------------------------
# GraphQL fragments
# ----------------------------------------------------------------------

# Asset fields that are scalar or wrapped in StringConnection / object.
# Connections (ips, macs, segments) need explicit nodes selection.
_ASSET_BASE = """
  id
  name
  type
  superType
  category
  vendor
  model
  firmwareVersion
  os
  family
  description
  location
  purdueLevel
  criticality
  hidden
  runStatus
  extendedRunStatus
  firstSeen
  lastSeen
  lastUpdate
  lifecycleStatus
  ips(first: 50) { nodes }
  macs(first: 50) { nodes }
  segments(first: 50) { nodes { id name type } }
  risk { totalRisk pluginCount unresolvedEvents }
  customField1 customField2 customField3 customField4 customField5
  customField6 customField7 customField8 customField9 customField10
"""

_CUSTOM_FIELD_SLOTS = [f"customField{i}" for i in range(1, 11)]

_LIST_CUSTOM_FIELDS = "query Q { customFields { fieldId userDefinedName valueType } }"


class CustomFieldLabelCache:
    """Module-level cache for the {slot_id → user-defined label} mapping.

    Tenable's custom-field schema is 10 fixed slots (`customField1`..
    `customField10`); operators map them to human labels ("Plant ID",
    "CDA Type", etc.) via the `customFields` query. Asset reads use
    that map to surface values keyed by label instead of opaque slot
    name. Custom-field writes call `invalidate()` so the next read
    refetches.

    TTL keeps the cache live across burst reads without forcing a
    roundtrip per asset projection. No lock — duplicate cold-cache
    fetches are harmless.
    """

    _TTL_SECONDS = 60.0
    _slot_to_label: dict[str, str] | None = None
    _value_types: dict[str, str] | None = None
    _cache_scope: str | None = None
    _ts: float = 0.0

    @classmethod
    async def get_or_fetch(
        cls,
        client: TenableClient,
        icp_machine_id: str | None = None,
    ) -> dict[str, str]:
        cache_scope = (icp_machine_id or "").strip("/")
        now = time.monotonic()
        if (
            cls._slot_to_label is not None
            and cls._cache_scope == cache_scope
            and (now - cls._ts) < cls._TTL_SECONDS
        ):
            return cls._slot_to_label
        data = await client.query(_LIST_CUSTOM_FIELDS, icp_machine_id=icp_machine_id)
        slot_to_label: dict[str, str] = {}
        value_types: dict[str, str] = {}
        for entry in data.get("customFields") or []:
            slot = entry.get("fieldId")
            label = entry.get("userDefinedName")
            vtype = entry.get("valueType")
            if slot and label:
                slot_to_label[slot] = label
            if slot and vtype:
                value_types[slot] = vtype
        cls._slot_to_label = slot_to_label
        cls._value_types = value_types
        cls._cache_scope = cache_scope
        cls._ts = now
        return slot_to_label

    @classmethod
    def invalidate(cls) -> None:
        cls._slot_to_label = None
        cls._value_types = None
        cls._cache_scope = None
        cls._ts = 0.0

    @classmethod
    async def resolve_label_to_slot(
        cls,
        client: TenableClient,
        label: str,
        icp_machine_id: str | None = None,
    ) -> str:
        """Reverse-lookup: find which slot is configured for the given label.

        Used by write tools that accept `custom_fields={"<label>": value}`.
        Raises ValueError if the label is not configured.
        """
        slot_to_label = await cls.get_or_fetch(client, icp_machine_id=icp_machine_id)
        match = next(
            (slot for slot, name in slot_to_label.items() if name == label),
            None,
        )
        if match is None:
            known = sorted(slot_to_label.values())
            raise ValueError(f"unknown custom-field label {label!r}; configured labels are {known}")
        return match


# ----------------------------------------------------------------------
# Queries
# ----------------------------------------------------------------------

_QUERY_ASSETS = (
    "query Q($pageSize: Int!, $after: String, "
    "$filter: AssetExpressionsParams, $search: String) { "
    "assets(first: $pageSize, after: $after, filter: $filter, search: $search) { "
    "pageInfo { hasNextPage endCursor } "
    "totalCount "
    "nodes { " + _ASSET_BASE + " } "
    "} "
    "}"
)

# Single-asset fetch via the dedicated `asset(id: ID!)` query.
_GET_ASSET = "query Q($id: ID!) { asset(id: $id) { " + _ASSET_BASE + " } }"

# Vulnerabilities for one asset — traverse asset(id).plugins so the
# public UUID resolves correctly. The top-level plugins(affectedAssets)
# filter expects Tenable's internal numeric id and rejects the UUID.
_GET_ASSET_VULNS = """
query Q($id: ID!, $pageSize: Int!, $after: String) {
  asset(id: $id) {
    plugins(first: $pageSize, after: $after) {
      pageInfo { hasNextPage endCursor }
      totalCount
      nodes {
      id
      name
      source
      family
      severity
      vprScore
      vprLevel
      cvss3Score
      totalAffectedAssets
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
        exploitCodeMaturity
        pluginPubDate
        vulnPubDate
        ageOfVuln
      }
    }
    }
  }
}
"""


# ----------------------------------------------------------------------
# Filter helpers — translate natural args to Tenable's expression tree
# ----------------------------------------------------------------------


def _build_asset_filter(
    *,
    kind: str | None,
    vendor: str | None,
    name_contains: str | None,
    category: str | None,
    criticality_at_least: str | None,
    hidden: bool | None,
) -> dict | None:
    """Build a Tenable `AssetExpressionsParams` tree from natural args.
    Returns None when no filter is needed.

    Note: `risk` (totalRisk / unresolvedEvents) is not numerically
    filterable through this GraphQL surface — Tenable returns 500s
    for `Greater`/`GreaterEqual` against the `risk` field. Risk-based
    sorting is exposed instead via the `sort` argument elsewhere.
    """
    parts: list[dict] = []
    if kind:
        parts.append(expr("type", EXPR_IN, to_asset_types(kind)))
    if vendor:
        parts.append(expr("vendor", EXPR_EQUAL, [vendor]))
    if name_contains:
        # Tenable's `Like` is SQL-style: bare strings exact-match,
        # `%foo%` substring-matches. (`Contains` is in the ExprOp enum
        # but errors against `name` in practice.)
        parts.append(expr("name", EXPR_LIKE, [f"%{name_contains}%"]))
    if category:
        parts.append(expr("category", EXPR_EQUAL, [to_asset_category(category)]))
    if criticality_at_least:
        # `criticality` doesn't accept GreaterEqual; expand "at least X"
        # to an explicit list of acceptable values via `In`.
        parts.append(expr("criticality", EXPR_IN, to_criticality_at_least(criticality_at_least)))
    if hidden is not None:
        parts.append(expr("hidden", EXPR_EQUAL, [bool(hidden)]))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


def _project_asset(
    node: dict[str, Any],
    custom_field_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Trim Tenable's verbose asset record to a flat shape that's
    cheap for an LLM to scan and reason over.

    `custom_field_labels` maps slot id (`customField1`..`customField10`) to
    the operator-configured human label. Slots with a stored value are
    surfaced under their label in `custom_fields`; values stored in slots
    without a configured label appear under the slot id as a fallback so
    nothing is dropped silently.
    """
    risk = node.get("risk") or {}
    segments = unwrap_nodes(node.get("segments"))
    label_map = custom_field_labels or {}
    custom_fields: dict[str, str] = {}
    for slot in _CUSTOM_FIELD_SLOTS:
        val = node.get(slot)
        if val is None or val == "":
            continue
        key = label_map.get(slot) or slot
        custom_fields[key] = str(val)
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "super_type": node.get("superType"),
        "category": node.get("category"),
        "vendor": node.get("vendor"),
        "model": node.get("model"),
        "firmware_version": node.get("firmwareVersion"),
        "os": node.get("os"),
        "family": node.get("family"),
        "purdue_level": node.get("purdueLevel"),
        "criticality": node.get("criticality"),
        "run_status": node.get("runStatus"),
        "extended_run_status": node.get("extendedRunStatus"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
        "last_update": node.get("lastUpdate"),
        "lifecycle_status": node.get("lifecycleStatus"),
        "hidden": node.get("hidden"),
        "ips": unwrap_nodes(node.get("ips")),
        "macs": unwrap_nodes(node.get("macs")),
        "segments": [
            {"id": s.get("id"), "name": s.get("name"), "type": s.get("type")} for s in segments
        ],
        "risk": {
            "total_risk": risk.get("totalRisk"),
            "plugin_count": risk.get("pluginCount"),
            "unresolved_events": risk.get("unresolvedEvents"),
        },
        "description": node.get("description"),
        "location": node.get("location"),
        "custom_fields": custom_fields,
    }


def _qualify_asset(asset: dict[str, Any], site_uuid: str) -> dict[str, Any]:
    """Attach routing provenance and a reusable qualified reference."""
    asset_id = asset.get("id")
    return {
        **asset,
        "site_uuid": site_uuid,
        "asset_ref": {"site_uuid": site_uuid, "asset_id": asset_id},
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only asset tools."""

    @mcp.tool(
        title="Query OT assets",
        description=(
            "Returns a list of OT assets in the Tenable OT deployment, "
            "filtered by the provided criteria. Returns up to `limit` "
            "(max 500) assets with each asset's identity, classification, "
            "IPs / MACs, Purdue level, segment membership, and aggregate "
            "risk. Call `get_asset` on a returned id for the per-asset "
            "bundle, or `get_asset_vulnerabilities` for that asset's open "
            "vulnerabilities.\n\n"
            "`total_count` is the full number of assets matching the "
            "filter, independent of the page size — use it to answer "
            "'how many' questions directly. When the match exceeds one "
            "page the response sets `has_more: true` and returns an "
            "`end_cursor`; pass that as `after` to fetch the next page, "
            "repeating until `has_more` is false to walk the entire "
            "matched set.\n\n"
            "Filter values use natural OT vocabulary:\n"
            f"  • kind: one of {ASSET_KIND_VALUES}\n"
            "  • category: one of 'controller', 'network', 'iot'\n"
            f"  • criticality_at_least: one of {CRITICALITY_VALUES}\n"
            "  • vendor: equal-match on the vendor name\n"
            "  • name_contains: substring match on the asset name"
        ),
    )
    async def query_assets(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        kind: str | None = None,
        vendor: str | None = None,
        name_contains: str | None = None,
        search: str | None = None,
        category: str | None = None,
        criticality_at_least: str | None = None,
        hidden: bool | None = None,
        limit: int = 50,
        after: str | None = None,
        after_by_site: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Filter OT assets and return a projected list.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            site_uuids: Site machine-id UUIDs for a multi-site query.
                Cannot be combined with `site_uuid` or `site_name`.
            kind: Natural asset kind ("plc", "rtu", "ied", "hmi",
                "controller", "switch", "router", "firewall", "iot",
                "server", etc.). See ASSET_KIND_VALUES.
            vendor: Equal-match on the asset's vendor.
            name_contains: Substring match on the asset's `name` field
                (strict — only the name).
            search: Single-term, case-insensitive substring match
                across multiple text fields (name, vendor, model,
                etc.). Broader than `name_contains` but does NOT
                AND multiple words — pass one keyword at a time, or
                use the structured filter args (vendor + kind + ...)
                for multi-criteria narrowing.
            category: One of "controller" / "network" / "iot" — the
                high-level grouping Tenable uses.
            criticality_at_least: One of "none" / "low" / "medium" / "high".
                Returns assets at or above this criticality.
            hidden: True returns only hidden assets; False only
                visible assets; None (default) returns both.
            limit: Maximum results per page (default 50, max 500).
            after: Opaque page cursor. Omit for the first page; to
                continue, pass the `end_cursor` value from the previous
                response. Keep paging while `has_more` is true to
                retrieve every matching asset.
            after_by_site: Per-site cursors for a multi-site query, keyed
                by site UUID. Cannot be combined with `after`.
        """
        page_size = clamp_page_size(limit)
        filt = _build_asset_filter(
            kind=kind,
            vendor=vendor,
            name_contains=name_contains,
            category=category,
            criticality_at_least=criticality_at_least,
            hidden=hidden,
        )
        variables: dict[str, Any] = {"pageSize": page_size}
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
                _QUERY_ASSETS,
                variables=site_variables,
                icp_machine_id=machine_id,
            )
            block = data.get("assets") or {}
            nodes = block.get("nodes") or []
            page_info = block.get("pageInfo") or {}
            label_map = await CustomFieldLabelCache.get_or_fetch(client, icp_machine_id=machine_id)
            return {
                "site_uuid": machine_id,
                "count": len(nodes),
                "total_count": block.get("totalCount"),
                "has_more": bool(page_info.get("hasNextPage")),
                "end_cursor": page_info.get("endCursor"),
                "assets": [
                    _qualify_asset(_project_asset(node, label_map), machine_id) for node in nodes
                ],
            }

        if len(site_ids) == 1:
            return await query_site(site_ids[0])
        return await run_multi_site_read(site_ids, query_site)

    @mcp.tool(
        title="Get one OT asset",
        description=(
            "Returns the per-asset bundle for one OT asset by id: "
            "identity, classification, IPs / MACs, Purdue level, "
            "segment membership, criticality, run status, and aggregate "
            "risk. Call after `query_assets` returns an id of interest. "
            "For the asset's open vulnerabilities call "
            "`get_asset_vulnerabilities` separately."
        ),
    )
    async def get_asset(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> dict[str, Any]:
        """Fetch one asset by id.

        Args:
            asset_id: The asset's `id` field as returned by `query_assets`.
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
        """
        if not asset_id:
            raise ValueError("asset_id is required")
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        data = await client.query(
            _GET_ASSET,
            variables={"id": asset_id},
            icp_machine_id=machine_id,
        )
        node = data.get("asset")
        if not node:
            return {"asset": None, "error": f"No asset with id {asset_id!r}."}
        label_map = await CustomFieldLabelCache.get_or_fetch(client, icp_machine_id=machine_id)
        return {"asset": _qualify_asset(_project_asset(node, label_map), machine_id)}

    @mcp.tool(
        title="Get vulnerabilities for one asset",
        description=(
            "Returns the open vulnerabilities (Tenable plugins) "
            "affecting one OT asset. Each vulnerability includes CVEs, "
            "CVSS v3 score and vector, exploit availability flags "
            "(CISA KEV, exploit-available, exploited-by-malware), age, "
            "public disclosure date, and the official vendor solution. "
            "Use `query_vulnerabilities` for global vuln filtering "
            "(KEV-only, exploit-available, severity floor, etc.); this "
            "tool is asset-scoped."
        ),
    )
    async def get_asset_vulnerabilities(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        limit: int = 100,
        after: str | None = None,
    ) -> dict[str, Any]:
        """List vulnerabilities affecting one asset.

        Args:
            asset_id: The asset's `id` field as returned by `query_assets`.
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            limit: Maximum results per page (default 100, max 500).
            after: Opaque page cursor. Omit for the first page; to
                continue, pass the `end_cursor` value from the previous
                response.
        """
        if not asset_id:
            raise ValueError("asset_id is required")
        page_size = clamp_page_size(limit, default=100)
        variables: dict[str, Any] = {"id": asset_id, "pageSize": page_size}
        if after:
            variables["after"] = after
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        data = await client.query(
            _GET_ASSET_VULNS,
            variables=variables,
            icp_machine_id=machine_id,
        )
        block = (data.get("asset") or {}).get("plugins") or {}
        nodes = block.get("nodes") or []
        page_info = block.get("pageInfo") or {}
        return {
            "asset_id": asset_id,
            "site_uuid": machine_id,
            "asset_ref": {"site_uuid": machine_id, "asset_id": asset_id},
            "count": len(nodes),
            "total_count": block.get("totalCount"),
            "has_more": bool(page_info.get("hasNextPage")),
            "end_cursor": page_info.get("endCursor"),
            "vulnerabilities": [project_vuln(n) for n in nodes],
        }

    @mcp.tool(
        title="List configured custom fields",
        description=(
            "Returns the asset custom-field schema for this Tenable OT "
            "tenant. Custom fields are 10 fixed slots ('customField1'.."
            "'customField10'); operators map each slot to a human label "
            "(e.g. 'Plant ID', 'CDA Type') and a value type ('PlainText' "
            "or 'HyperLink').\n\n"
            "Call this before reading or writing custom-field values so "
            "the AI knows which labels are configured. Read tools "
            "(`get_asset`, `query_assets`) already surface values keyed "
            "by label automatically; write tools (`update_asset`, "
            "`bulk_edit_assets`) accept `custom_fields` keyed by label "
            "and translate to slots internally."
        ),
    )
    async def list_custom_fields(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
    ) -> dict[str, Any]:
        """List configured custom-field slots, labels, and value types."""
        site_ids = await resolve_read_site_ids(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
        )

        async def query_site(machine_id: str) -> dict[str, Any]:
            data = await client.query(_LIST_CUSTOM_FIELDS, icp_machine_id=machine_id)
            fields = data.get("customFields") or []
            return {
                "site_uuid": machine_id,
                "count": len(fields),
                "max_slots": 10,
                "custom_fields": [
                    {
                        "field_id": field.get("fieldId"),
                        "label": field.get("userDefinedName"),
                        "value_type": field.get("valueType"),
                    }
                    for field in fields
                ],
            }

        if len(site_ids) == 1:
            return await query_site(site_ids[0])
        return await run_multi_site_read(site_ids, query_site)
