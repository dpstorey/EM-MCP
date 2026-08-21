# SPDX-License-Identifier: Apache-2.0
"""Event tools: query_events, get_event.

Tenable OT detects events when network traffic, control-system
operations, or asset behavior matches a detection policy. Each event
ties together a time, a firing policy, source/destination assets, and
an optional finding identifier for case management.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import (
    EXPR_EQUAL,
    EXPR_GREATER_EQUAL,
    EXPR_IN,
    EXPR_LESS_EQUAL,
    expr,
    expr_and,
    to_policy_level,
)
from ._shared import clamp_page_size, project_event
from ._sites import resolve_read_site_ids, run_multi_site_read

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

_EVENT_FIELDS = """
  id
  time
  resolved
  resolvedTs
  resolvedUser
  eventType { type group description category family }
  srcIP
  dstIP
  srcMac
  dstMac
  protocol
  protocolNiceName
  port
  severity
  category
  comment
  completion
  continuous
  payloadSize
  hitId
  logId
  findingId
  type
  hasDetails
  srcAssets(first: 10) { nodes { id name } }
  dstAssets(first: 10) { nodes { id name } }
  policy { id title level }
"""


_QUERY_EVENTS = (
    "query Q($pageSize: Int!, $after: String, "
    "$filter: EventsExpressionsParams, $search: String, "
    "$sort: [EventsSortParams!]) { "
    "events(first: $pageSize, after: $after, filter: $filter, "
    "search: $search, sort: $sort) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _EVENT_FIELDS + " } "
    "} "
    "}"
)

_QUERY_ASSET_EVENTS = (
    "query Q($id: ID!, $pageSize: Int!, $after: String, "
    "$filter: EventsExpressionsParams, $sort: [EventsSortParams!]) { "
    "asset(id: $id) { "
    "events(first: $pageSize, after: $after, filter: $filter, sort: $sort) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _EVENT_FIELDS + " } "
    "} "
    "} "
    "}"
)


_GET_EVENT = "query Q($id: ID!) { event(id: $id) { " + _EVENT_FIELDS + " } }"


# Map policy-level "at least" floors to a Tenable PolicyLevel In-list.
# PolicyLevel ordinal: None < Low < Medium < High.
_POLICY_LEVEL_ORDINAL = ["none", "low", "medium", "high"]


def _to_policy_level_at_least(natural: str) -> list[str]:
    """Expand "at least medium" → list of Tenable PolicyLevel values
    matching that floor (PolicyLevel doesn't accept GreaterEqual against
    the enum reliably; In-list is the safe pattern)."""
    v = (natural or "").strip().lower()
    if v not in _POLICY_LEVEL_ORDINAL:
        raise ValueError(f"severity must be one of {_POLICY_LEVEL_ORDINAL}; got {natural!r}")
    idx = _POLICY_LEVEL_ORDINAL.index(v)
    return [to_policy_level(k) for k in _POLICY_LEVEL_ORDINAL[idx:]]


def _build_event_filter(
    *,
    severity_at_least: str | None,
    event_type: str | None,
    policy_id: str | None,
    since: str | None,
    until: str | None,
    resolved: bool | None,
    src_ip: str | None,
    dst_ip: str | None,
) -> dict | None:
    """Build an `EventsExpressionsParams` filter tree from natural args."""
    parts: list[dict] = []
    if severity_at_least:
        parts.append(expr("severity", EXPR_IN, _to_policy_level_at_least(severity_at_least)))
    if event_type:
        parts.append(expr("type", EXPR_EQUAL, [event_type]))
    if policy_id:
        parts.append(expr("policyId", EXPR_EQUAL, [policy_id]))
    if since:
        parts.append(expr("time", EXPR_GREATER_EQUAL, [since]))
    if until:
        parts.append(expr("time", EXPR_LESS_EQUAL, [until]))
    if resolved is True:
        parts.append(expr("resolved", EXPR_EQUAL, [True]))
    elif resolved is False:
        parts.append(expr("resolved", EXPR_EQUAL, [False]))
    if src_ip:
        parts.append(expr("srcIP", EXPR_EQUAL, [src_ip]))
    if dst_ip:
        parts.append(expr("dstIP", EXPR_EQUAL, [dst_ip]))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only event tools."""

    @mcp.tool(
        title="Query OT events",
        description=(
            "Returns OT detection events matching the filter criteria, "
            "newest first. Use this to investigate alert windows, "
            "policy-firing patterns, source/dest IP context, or events "
            "in a specific time window. Pass `asset_id` to retrieve events "
            "associated with one asset; do not put an asset UUID in the "
            "free-text `search` parameter. Each event includes the time, "
            "classification, severity, source/dest assets, the firing "
            "detection policy, and protocol/IP/MAC context. Call "
            "`get_event` on a returned id for full event detail.\n\n"
            "`total_count` is the full number of events matching the "
            "filter, independent of the page size — use it to answer "
            "'how many' questions directly. When the match exceeds one "
            "page the response sets `has_more: true` and returns an "
            "`end_cursor`; pass that as `after` to fetch the next page, "
            "repeating until `has_more` is false to walk the entire "
            "matched set. Event totals can be very large, so narrow with "
            "the filters (severity, time window, policy) before paging.\n\n"
            "Filter values use natural OT vocabulary:\n"
            "  • severity_at_least: one of 'none', 'low', 'medium', 'high'\n"
            "  • event_type: a PolicyEventType name like "
            "'FirmwareVersionChange', 'ConfigurationDownload', "
            "'ProgrammingUpload', 'OperatingMode'\n"
            "  • since / until: ISO-8601 timestamps for time-window scope"
        ),
    )
    async def query_events(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        severity_at_least: str | None = None,
        event_type: str | None = None,
        policy_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        resolved: bool | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        asset_id: str | None = None,
        search: str | None = None,
        limit: int = 100,
        after: str | None = None,
        after_by_site: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Filter OT events and return a time-sorted list.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            severity_at_least: One of "none" / "low" / "medium" / "high".
                Returns events at or above this severity.
            event_type: Event type name (e.g. "FirmwareVersionChange").
            policy_id: Filter to events fired by this detection policy.
            since: ISO-8601 timestamp; events at or after this time.
            until: ISO-8601 timestamp; events at or before this time.
            resolved: True returns only resolved events; False only
                unresolved; None (default) returns both.
            src_ip / dst_ip: Equal-match on the event's source / destination
                IP address.
            asset_id: Return events associated with this asset UUID by using
                the asset's event connection. Do not pass an asset UUID to
                `search`.
            search: Single-term, case-insensitive substring across event
                text fields.
            limit: Maximum results per page (default 100, max 500).
            after: Opaque page cursor. Omit for the first page; to
                continue, pass the `end_cursor` value from the previous
                response. Keep paging while `has_more` is true to
                retrieve every matching event.
        """
        page_size = clamp_page_size(limit, default=100)
        if asset_id is not None and not asset_id.strip():
            raise ValueError("asset_id cannot be empty")
        if asset_id and search:
            raise ValueError("asset_id cannot be combined with free-text search")
        filt = _build_event_filter(
            severity_at_least=severity_at_least,
            event_type=event_type,
            policy_id=policy_id,
            since=since,
            until=until,
            resolved=resolved,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )
        variables: dict[str, Any] = {
            "pageSize": page_size,
            "sort": [{"field": "time", "direction": "DescNullLast"}],
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
            query = _QUERY_EVENTS
            if asset_id:
                query = _QUERY_ASSET_EVENTS
                site_variables["id"] = asset_id
                site_variables.pop("search", None)
            data = await client.query(
                query,
                variables=site_variables,
                icp_machine_id=machine_id,
            )
            asset = data.get("asset") if asset_id else None
            if asset_id:
                block = (asset or {}).get("events") or {}
            else:
                block = data.get("events") or {}
            nodes = block.get("nodes") or []
            page_info = block.get("pageInfo") or {}
            events = []
            for node in nodes:
                event = project_event(node)
                event["site_uuid"] = machine_id
                event["event_ref"] = {
                    "site_uuid": machine_id,
                    "event_id": event.get("id"),
                }
                events.append(event)
            result: dict[str, Any] = {
                "site_uuid": machine_id,
                "count": len(nodes),
                "total_count": block.get("totalCount"),
                "has_more": bool(page_info.get("hasNextPage")),
                "end_cursor": page_info.get("endCursor"),
                "events": events,
            }
            if asset_id:
                result["asset_ref"] = {"site_uuid": machine_id, "asset_id": asset_id}
                result["asset_found"] = asset is not None
                if asset is None:
                    result["error"] = f"No asset with id {asset_id!r}."
            return result

        if len(site_ids) == 1:
            return await query_site(site_ids[0])
        return await run_multi_site_read(site_ids, query_site)

    @mcp.tool(
        title="Get one OT event",
        description=(
            "Returns full detail for a single OT event by id. Use after "
            "`query_events` returns an id of interest, or when a finding "
            "or case references a specific event."
        ),
    )
    async def get_event(
        event_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> dict[str, Any]:
        """Fetch one event's full detail.

        Args:
            event_id: The event's `id` field as returned by `query_events`.
        """
        if not event_id:
            raise ValueError("event_id is required")
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        data = await client.query(
            _GET_EVENT,
            variables={"id": event_id},
            icp_machine_id=machine_id,
        )
        node = data.get("event")
        if not node:
            return {"event": None, "error": f"No event with id {event_id!r}."}
        event = project_event(node)
        event["site_uuid"] = machine_id
        event["event_ref"] = {"site_uuid": machine_id, "event_id": event_id}
        return {"event": event}
