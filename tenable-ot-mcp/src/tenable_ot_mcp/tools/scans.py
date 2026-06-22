# SPDX-License-Identifier: Apache-2.0
"""Active-scan tools — DEFINE / read, never EXECUTE.

Active scanning sends probe traffic to OT assets and has caused
operational incidents in the wild. This server splits the workflow:

  • **Cognitive work** (define / inspect / read execution history) —
    exposed.
  • **Physical-world trigger** (`runActiveQuery`) — NOT exposed.

The AI helps an analyst design a scan job (assets, type, schedule)
and put it into Tenable OT in a defined-but-not-executing state.
A human operator then reviews the job in the Tenable OT UI and
triggers it manually. Past execution results are exposed read-only.

This is a deliberate scope boundary, not a deferral. See
`SERVER_INSTRUCTIONS` rule #12 in `mcp_app.py` and the
`project_no_active_scanning_by_ai` memory.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._shared import clamp_page_size

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

_SCAN_FIELDS = """
  id
  name
  description
  enabled
  trigger
  predefined
  category
  operation
  status
  lastExecution
  nextExecution
  createdBy
  lastEditedBy
  lastEditedDate
  lastRunBy
  assetGroup { id name }
"""

_QUERY_ACTIVE_SCANS = (
    "query Q($pageSize: Int!, $after: String) {"
    "  activeQueries(first: $pageSize, after: $after) {"
    "    pageInfo { hasNextPage endCursor }"
    "    totalCount"
    "    nodes { " + _SCAN_FIELDS + " }"
    "  }"
    "}"
)

_GET_ACTIVE_SCAN = "query Q($id: ID!) { activeQuery(id: $id) { " + _SCAN_FIELDS + " } }"

_QUERY_SCAN_EXECUTIONS = """
query Q($id: ID!, $pageSize: Int!, $after: String) {
  activeQueryExecutions(id: $id, first: $pageSize, after: $after) {
    pageInfo { hasNextPage endCursor }
    totalCount
    nodes {
      executionId
      startTime
      endTime
      elapsedTime
      status
      failureExplanation
      initiatedBy
      source
      queryDetails { id name operation }
    }
  }
}
"""


# ----------------------------------------------------------------------
# Mutations (define-side only — runActiveQuery is deliberately omitted)
# ----------------------------------------------------------------------

_M_CREATE_ACTIVE_SCAN = """
mutation M(
  $name: String!,
  $description: String,
  $enabled: Boolean!,
  $operation: OpType!,
  $assetGroup: ID!,
  $schedule: [ScheduleParams!]
) {
  createActiveQuery(
    name: $name,
    description: $description,
    enabled: $enabled,
    operation: $operation,
    assetGroup: $assetGroup,
    schedule: $schedule
  ) { id name enabled operation status }
}
"""

_M_EDIT_ACTIVE_SCAN = """
mutation M(
  $id: ID!,
  $name: String!,
  $description: String,
  $enabled: Boolean!,
  $assetGroup: ID!,
  $schedule: [ScheduleParams!]
) {
  editActiveQuery(
    id: $id,
    name: $name,
    description: $description,
    enabled: $enabled,
    assetGroup: $assetGroup,
    schedule: $schedule
  ) { id name enabled }
}
"""

_M_ENABLE_ACTIVE_SCAN = "mutation M($id: ID!) { enableActiveQuery(id: $id) { id enabled } }"
_M_DISABLE_ACTIVE_SCAN = "mutation M($id: ID!) { disableActiveQuery(id: $id) { id enabled } }"
_M_DELETE_ACTIVE_SCAN = "mutation M($id: ID!) { deleteActiveQuery(id: $id) { id name } }"


# ----------------------------------------------------------------------
# Per-type scan mutations (typed-options structs)
# ----------------------------------------------------------------------
#
# Tenable OT exposes per-type create/edit mutations alongside the
# generic createActiveQuery, each accepting a typed *OptionsParams
# struct that the generic mutation cannot (port range, mapping rate,
# SNMP query flags, asset-discovery network list / concurrency, etc.).
# These tools surface those typed knobs in natural OT vocabulary.
# Schedule on these takes [ScheduleParams!] (a list) rather than the
# scalar ScheduleParams used by createActiveQuery.

_M_CREATE_PORT_SCAN = """
mutation M(
  $name: String!, $description: String, $enabled: Boolean!,
  $assetGroup: ID!, $schedule: [ScheduleParams!],
  $options: PortScanOptionsParams!
) {
  createPortScanQuery(
    name: $name, description: $description, enabled: $enabled,
    assetGroup: $assetGroup, schedule: $schedule, options: $options
  ) { id name enabled operation status }
}
"""

_M_EDIT_PORT_SCAN = """
mutation M(
  $id: ID!, $name: String!, $description: String, $enabled: Boolean!,
  $assetGroup: ID!, $schedule: [ScheduleParams!],
  $options: PortScanOptionsParams!
) {
  editPortScanQuery(
    id: $id, name: $name, description: $description, enabled: $enabled,
    assetGroup: $assetGroup, schedule: $schedule, options: $options
  ) { id name enabled }
}
"""

_M_CREATE_SNMP_SCAN = """
mutation M(
  $name: String!, $description: String, $enabled: Boolean!,
  $assetGroup: ID!, $schedule: [ScheduleParams!],
  $options: SnmpOptionsParams!
) {
  createSnmpQuery(
    name: $name, description: $description, enabled: $enabled,
    assetGroup: $assetGroup, schedule: $schedule, options: $options
  ) { id name enabled operation status }
}
"""

_M_EDIT_SNMP_SCAN = """
mutation M(
  $id: ID!, $name: String!, $description: String, $enabled: Boolean!,
  $assetGroup: ID!, $schedule: [ScheduleParams!],
  $options: SnmpOptionsParams!
) {
  editSnmpQuery(
    id: $id, name: $name, description: $description, enabled: $enabled,
    assetGroup: $assetGroup, schedule: $schedule, options: $options
  ) { id name enabled }
}
"""

_M_CREATE_CONTROLLER_DISCOVERY_SCAN = """
mutation M(
  $name: String!, $description: String, $enabled: Boolean!,
  $schedule: [ScheduleParams!]
) {
  createControllerDiscoveryQuery(
    name: $name, description: $description, enabled: $enabled,
    schedule: $schedule
  ) { id name enabled operation status }
}
"""

_M_EDIT_CONTROLLER_DISCOVERY_SCAN = """
mutation M(
  $id: ID!, $name: String!, $description: String, $enabled: Boolean!,
  $schedule: [ScheduleParams!]
) {
  editControllerDiscoveryQuery(
    id: $id, name: $name, description: $description, enabled: $enabled,
    schedule: $schedule
  ) { id name enabled }
}
"""

_M_CREATE_ASSET_DISCOVERY_SCAN = """
mutation M(
  $name: String!, $description: String, $enabled: Boolean!,
  $schedule: [ScheduleParams!],
  $options: AssetDiscoveryOptionsParams!
) {
  createAssetDiscoveryQuery(
    name: $name, description: $description, enabled: $enabled,
    schedule: $schedule, options: $options
  ) { id name enabled operation status }
}
"""

_M_EDIT_ASSET_DISCOVERY_SCAN = """
mutation M(
  $id: ID!, $name: String!, $description: String, $enabled: Boolean!,
  $schedule: [ScheduleParams!],
  $options: AssetDiscoveryOptionsParams!
) {
  editAssetDiscoveryQuery(
    id: $id, name: $name, description: $description, enabled: $enabled,
    schedule: $schedule, options: $options
  ) { id name enabled }
}
"""

_M_CREATE_INACTIVE_PROBING_SCAN = """
mutation M(
  $name: String!, $description: String, $enabled: Boolean!,
  $assetGroup: ID!, $schedule: [ScheduleParams!],
  $options: InactiveProbingOptionsParams!
) {
  createInactiveProbingQuery(
    name: $name, description: $description, enabled: $enabled,
    assetGroup: $assetGroup, schedule: $schedule, options: $options
  ) { id name enabled operation status }
}
"""

_M_EDIT_INACTIVE_PROBING_SCAN = """
mutation M(
  $id: ID!, $name: String!, $description: String, $enabled: Boolean!,
  $assetGroup: ID!, $schedule: [ScheduleParams!],
  $options: InactiveProbingOptionsParams!
) {
  editInactiveProbingQuery(
    id: $id, name: $name, description: $description, enabled: $enabled,
    assetGroup: $assetGroup, schedule: $schedule, options: $options
  ) { id name enabled }
}
"""

# Tenable OT exposes editSubnetsDiscoveryQuery as a singleton edit (no
# create variant — the deployment ships a single subnets-discovery
# query that operators tune).
_M_EDIT_SUBNETS_DISCOVERY_SCAN = """
mutation M(
  $id: ID!, $name: String!, $description: String, $enabled: Boolean!,
  $schedule: [ScheduleParams!]
) {
  editSubnetsDiscoveryQuery(
    id: $id, name: $name, description: $description, enabled: $enabled,
    schedule: $schedule
  ) { id name enabled }
}
"""


# ----------------------------------------------------------------------
# Projections
# ----------------------------------------------------------------------


def _project_scan(node: dict[str, Any]) -> dict[str, Any]:
    ag = node.get("assetGroup") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "description": node.get("description"),
        "enabled": node.get("enabled"),
        "trigger": node.get("trigger"),
        "predefined": node.get("predefined"),
        "category": node.get("category"),
        "operation": node.get("operation"),
        "status": node.get("status"),
        "last_execution": node.get("lastExecution"),
        "next_execution": node.get("nextExecution"),
        "created_by": node.get("createdBy"),
        "last_edited_by": node.get("lastEditedBy"),
        "last_edited_date": node.get("lastEditedDate"),
        "last_run_by": node.get("lastRunBy"),
        "asset_group": ({"id": ag.get("id"), "name": ag.get("name")} if ag else None),
    }


def _project_execution(node: dict[str, Any]) -> dict[str, Any]:
    qd = node.get("queryDetails") or {}
    return {
        "execution_id": node.get("executionId"),
        "start_time": node.get("startTime"),
        "end_time": node.get("endTime"),
        "elapsed_time": node.get("elapsedTime"),
        "status": node.get("status"),
        "failure_explanation": node.get("failureExplanation"),
        "initiated_by": node.get("initiatedBy"),
        "source": node.get("source"),
        "query_id": qd.get("id"),
        "query_name": qd.get("name"),
        "query_operation": qd.get("operation"),
    }


# ----------------------------------------------------------------------
# Read tools
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only active-scan tools."""

    @mcp.tool(
        title="List active scans",
        description=(
            "Returns Tenable OT active-scan job specifications: name, "
            "description, scan operation type (PortScan, "
            "AssetDiscovery, SnmpType, etc.), category (IT / OT / "
            "Discovery), trigger (Manual / Periodic / System), enabled "
            "flag, status, and the asset group the job targets. Use "
            "this to audit what scans are configured. Predefined "
            "system scans appear with `predefined: true`. Note: this "
            "server does not expose any tool that runs a scan — that's "
            "a human-only action via the Tenable OT UI."
        ),
    )
    async def list_active_scans(limit: int = 100) -> dict[str, Any]:
        """List all active scans (defined scan jobs).

        Args:
            limit: Maximum scans to return (default 100, max 500).
        """
        page_size = clamp_page_size(limit, default=100)
        data = await client.query(_QUERY_ACTIVE_SCANS, variables={"pageSize": page_size})
        block = data.get("activeQueries") or {}
        nodes = block.get("nodes") or []
        page_info = block.get("pageInfo") or {}
        return {
            "count": len(nodes),
            "total_count": block.get("totalCount"),
            "has_more": bool(page_info.get("hasNextPage")),
            "scans": [_project_scan(n) for n in nodes],
        }

    @mcp.tool(
        title="Get one active scan",
        description=(
            "Returns the full specification for one active-scan job by "
            "id. Use after `list_active_scans` returns a job of "
            "interest, or when reading parameters before suggesting "
            "modifications."
        ),
    )
    async def get_active_scan(scan_id: str) -> dict[str, Any]:
        """Fetch one active scan.

        Args:
            scan_id: The active-scan id.
        """
        if not scan_id:
            raise ValueError("scan_id is required")
        data = await client.query(_GET_ACTIVE_SCAN, variables={"id": scan_id})
        node = data.get("activeQuery")
        if not node:
            return {"scan": None, "error": f"No active scan with id {scan_id!r}."}
        return {"scan": _project_scan(node)}

    @mcp.tool(
        title="Get past executions of an active scan",
        description=(
            "Returns past execution records for one active scan: "
            "start/end time, elapsed time, status (Completed / Failed "
            "/ Ongoing), who initiated, source (UI / API / system), "
            "and any failure explanation. Use this to audit when a "
            "scan was last run and whether it succeeded — but the "
            "underlying execution is triggered by humans, not this "
            "server."
        ),
    )
    async def get_active_scan_executions(
        scan_id: str,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List past execution records for one active scan.

        Args:
            scan_id: The active scan's id.
            limit: Maximum executions to return (default 20, max 500).
        """
        if not scan_id:
            raise ValueError("scan_id is required")
        page_size = clamp_page_size(limit, default=20)
        data = await client.query(
            _QUERY_SCAN_EXECUTIONS,
            variables={"id": scan_id, "pageSize": page_size},
        )
        block = data.get("activeQueryExecutions") or {}
        nodes = block.get("nodes") or []
        page_info = block.get("pageInfo") or {}
        return {
            "scan_id": scan_id,
            "count": len(nodes),
            "total_count": block.get("totalCount"),
            "has_more": bool(page_info.get("hasNextPage")),
            "executions": [_project_execution(n) for n in nodes],
        }


# ----------------------------------------------------------------------
# Write tools (define-side: create / edit / enable / disable / delete)
# ----------------------------------------------------------------------


# Allowed scan operation types — the OpType enum without entries that
# don't make sense to expose for AI-driven definition (Unknown, system
# enrichments, etc.).
_NATURAL_OPERATION = {
    "characteristics": "CharacteristicsType",
    "run_status": "RunStatusType",
    "snapshot": "SnapshotType",
    "snmp": "SnmpType",
    "nbstat": "NbstatQueryType",
    "identification": "IdentificationType",
    "port_scan": "PortScanQueryType",
    "wmi": "WmiType",
    "dns": "DnsType",
    "arp": "ArpType",
    "wmi_usb": "WmiUsbType",
    "asset_discovery": "AssetDiscoveryType",
    "bp_scan": "BpScanType",
    "nessus_basic_scan": "NessusBasicScanType",
    "ics_discovery": "IcsDiscovery",
    "inactive_asset_probe": "InactiveAssetProbe",
    "ping": "PingType",
    "subnets_discovery": "SubnetsDiscovery",
}
NATURAL_OPERATIONS = list(_NATURAL_OPERATION)


def _to_operation(natural: str) -> str:
    v = (natural or "").strip().lower()
    if v not in _NATURAL_OPERATION:
        raise ValueError(f"operation must be one of {NATURAL_OPERATIONS}; got {natural!r}")
    return _NATURAL_OPERATION[v]


# Natural-vocab maps for the typed *OptionsParams structs that the
# per-type create/edit mutations require. The MCP surface uses plain
# OT-operator words ("basic" / "lean" / "full_sweep"); we translate to
# Tenable's PascalCase enum spelling at wire time. See the
# `project_mcp_tool_surface_owns_its_vocabulary` memory.

_PORT_SCAN_RANGE = {
    "basic": "Basic",
    "lean": "Lean",
    "full_sweep": "FullSweep",
}
PORT_SCAN_RANGES = list(_PORT_SCAN_RANGE)

# Mapping rate is "ports probed per pause cycle" — the MCP surface
# accepts the integer count as a string ("1" / "10" / "1000"), which
# is what an operator says out loud.
_MAPPING_RATE = {
    "1": "OnePort",
    "2": "TwoPorts",
    "5": "FivePorts",
    "10": "TenPorts",
    "50": "FiftyPorts",
    "100": "HundredPorts",
    "500": "FiveHundredPorts",
    "1000": "ThousandPorts",
}
MAPPING_RATES = list(_MAPPING_RATE)

_CONCURRENT_WORKERS = {
    "10": "Ten",
    "20": "Twenty",
    "30": "Thirty",
}
CONCURRENT_WORKERS = list(_CONCURRENT_WORKERS)

_PAUSE_BETWEEN_PROBES = {
    "1s": "OneSecond",
    "2s": "TwoSeconds",
    "3s": "ThreeSeconds",
}
PAUSE_BETWEEN_PROBES = list(_PAUSE_BETWEEN_PROBES)


def _to_port_scan_range(natural: str) -> str:
    v = (natural or "").strip().lower().replace("-", "_")
    if v not in _PORT_SCAN_RANGE:
        raise ValueError(f"port_range must be one of {PORT_SCAN_RANGES}; got {natural!r}")
    return _PORT_SCAN_RANGE[v]


def _to_mapping_rate(natural: str | int) -> str:
    v = str(natural).strip()
    if v not in _MAPPING_RATE:
        raise ValueError(f"mapping_rate must be one of {MAPPING_RATES}; got {natural!r}")
    return _MAPPING_RATE[v]


def _to_concurrent_workers(natural: str | int) -> str:
    v = str(natural).strip()
    if v not in _CONCURRENT_WORKERS:
        raise ValueError(f"concurrent_workers must be one of {CONCURRENT_WORKERS}; got {natural!r}")
    return _CONCURRENT_WORKERS[v]


def _to_pause_between_probes(natural: str) -> str:
    v = (natural or "").strip().lower()
    if v not in _PAUSE_BETWEEN_PROBES:
        raise ValueError(
            f"pause_between_probes must be one of {PAUSE_BETWEEN_PROBES}; got {natural!r}"
        )
    return _PAUSE_BETWEEN_PROBES[v]


def _build_schedule(
    *,
    daily_hour: str | None,
    interval: str | None,
    interval_count: int | None,
    day_of_month: int | None,
) -> dict | None:
    """Translate natural schedule args into Tenable's ScheduleParams.

    `daily_hour` ("14:00") + `day_of_month` → Daily schedule.
    `interval` ("60s", "5m", "1h") + `interval_count` → Interval schedule.
    None → no schedule (manual trigger).
    """
    if daily_hour is None and interval is None:
        return None
    if daily_hour and interval:
        raise ValueError("provide either daily_hour or interval, not both")
    if daily_hour:
        out: dict[str, Any] = {"resolution": "Daily", "hour": daily_hour}
        if day_of_month is not None:
            out["day"] = day_of_month
        if interval_count is not None:
            out["count"] = interval_count
        return out
    out = {"resolution": "Interval", "interval": interval}
    if interval_count is not None:
        out["count"] = interval_count
    return out


def register_write_tools(mcp: Any, client: TenableClient, audit: AuditLog) -> None:
    """Register define-side active-scan write tools."""

    @mcp.tool(
        title="Define an active scan (NEW — does not run it)",
        description=(
            "Create a new active-scan definition in Tenable OT. The "
            "scan is stored DEFINED but not executed. A human operator "
            "must trigger it from the Tenable OT UI; this server "
            "deliberately does not expose `runActiveQuery`.\n\n"
            "`operation` accepts the natural names: 'port_scan', "
            "'asset_discovery', 'snmp', 'identification', 'ping', "
            "'arp', 'dns', 'wmi', 'subnets_discovery', "
            "'ics_discovery', 'inactive_asset_probe', and others "
            "matching Tenable's OpType enum.\n\n"
            "Schedule: pass `daily_hour` (e.g. '14:00') for a daily "
            "scan, or `interval`/`interval_count` (e.g. '1h', 4) for "
            "a recurring scan. Omit both for manual trigger only.\n\n"
            "WRITE — modifies Tenable OT state. Defaults to dry_run."
        ),
    )
    async def define_active_scan(
        name: str,
        operation: str,
        asset_group_id: str,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Define a new active scan.

        Args:
            name: Human-readable scan name.
            operation: Natural OpType (see description for list).
            asset_group_id: Id of the asset group to target.
            description: Optional description.
            enabled: If True, the scan is enabled at creation. Default
                False — recommended for AI-defined scans so the human
                operator reviews before enabling.
            daily_hour / interval / interval_count / day_of_month:
                Schedule shape (see description).
            dry_run: If True (default), preview without sending.
        """
        if not name or not asset_group_id:
            raise ValueError("name and asset_group_id are required")
        op_value = _to_operation(operation)
        schedule = _build_schedule(
            daily_hour=daily_hour,
            interval=interval,
            interval_count=interval_count,
            day_of_month=day_of_month,
        )
        variables: dict[str, Any] = {
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "operation": op_value,
            "assetGroup": asset_group_id,
        }
        if schedule is not None:
            variables["schedule"] = [schedule]
        return await _execute_write(
            client, audit, "define_active_scan", _M_CREATE_ACTIVE_SCAN, variables, dry_run
        )

    @mcp.tool(
        title="Edit an active-scan definition",
        description=(
            "Modify an existing active-scan definition (name, "
            "description, enabled flag, asset group, schedule). The "
            "operation type cannot be changed — for that, delete and "
            "redefine.\n\n"
            "WRITE — modifies Tenable OT state. Defaults to dry_run."
        ),
    )
    async def edit_active_scan(
        scan_id: str,
        name: str,
        asset_group_id: str,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Edit an active scan's definition.

        Args:
            scan_id: The active-scan id.
            name / description / enabled / asset_group_id / schedule:
                Same shape as `define_active_scan`.
            dry_run: If True (default), preview without sending.
        """
        if not scan_id or not name or not asset_group_id:
            raise ValueError("scan_id, name, asset_group_id are required")
        schedule = _build_schedule(
            daily_hour=daily_hour,
            interval=interval,
            interval_count=interval_count,
            day_of_month=day_of_month,
        )
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
        }
        if schedule is not None:
            variables["schedule"] = [schedule]
        return await _execute_write(
            client, audit, "edit_active_scan", _M_EDIT_ACTIVE_SCAN, variables, dry_run
        )

    @mcp.tool(
        title="Enable an active scan",
        description=(
            "Set the `enabled` flag on an active scan to true. This "
            "does NOT run the scan — only humans run scans. Enabling "
            "lets the scan participate in scheduled runs initiated by "
            "the Tenable OT UI.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def enable_active_scan(scan_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not scan_id:
            raise ValueError("scan_id is required")
        return await _execute_write(
            client,
            audit,
            "enable_active_scan",
            _M_ENABLE_ACTIVE_SCAN,
            {"id": scan_id},
            dry_run,
        )

    @mcp.tool(
        title="Disable an active scan",
        description=(
            "Set the `enabled` flag on an active scan to false. The "
            "scan stays defined but doesn't participate in scheduled "
            "runs.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def disable_active_scan(scan_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not scan_id:
            raise ValueError("scan_id is required")
        return await _execute_write(
            client,
            audit,
            "disable_active_scan",
            _M_DISABLE_ACTIVE_SCAN,
            {"id": scan_id},
            dry_run,
        )

    @mcp.tool(
        title="Delete an active-scan definition",
        description=(
            "Permanently delete an active-scan definition. Past "
            "execution history is retained.\n\nWRITE. Defaults to "
            "dry_run."
        ),
    )
    async def delete_active_scan(scan_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not scan_id:
            raise ValueError("scan_id is required")
        return await _execute_write(
            client,
            audit,
            "delete_active_scan",
            _M_DELETE_ACTIVE_SCAN,
            {"id": scan_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Per-type scan tools — typed-options structs that the generic
    # define_active_scan / edit_active_scan tools cannot express.
    # ------------------------------------------------------------------

    def _schedule_list(
        daily_hour: str | None,
        interval: str | None,
        interval_count: int | None,
        day_of_month: int | None,
    ) -> list[dict] | None:
        """Per-type mutations take `[ScheduleParams!]` (a list); wrap
        the single-schedule dict in a list, or return None for
        manual-trigger scans."""
        s = _build_schedule(
            daily_hour=daily_hour,
            interval=interval,
            interval_count=interval_count,
            day_of_month=day_of_month,
        )
        return [s] if s is not None else None

    # ---- Port scan ---------------------------------------------------

    @mcp.tool(
        title="Define a port-scan job (NEW — does not run it)",
        description=(
            "Create a port-scan job in Tenable OT. Saved DEFINED but not "
            "executed; an operator triggers it from the Tenable OT UI.\n\n"
            "  • port_range: 'basic' | 'lean' | 'full_sweep' — how many "
            "ports to probe per asset.\n"
            "  • mapping_rate: '1' | '2' | '5' | '10' | '50' | '100' | "
            "'500' | '1000' — ports probed per pause cycle.\n\n"
            "Schedule + asset_group_id args follow the same pattern as "
            "`define_active_scan`.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def define_port_scan(
        name: str,
        asset_group_id: str,
        port_range: str = "basic",
        mapping_rate: str = "10",
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name or not asset_group_id:
            raise ValueError("name and asset_group_id are required")
        variables: dict[str, Any] = {
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
            "options": {
                "portScanRange": _to_port_scan_range(port_range),
                "interval": _to_mapping_rate(mapping_rate),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client, audit, "define_port_scan", _M_CREATE_PORT_SCAN, variables, dry_run
        )

    @mcp.tool(
        title="Edit a port-scan job",
        description=(
            "Modify an existing port-scan job's name, description, "
            "enabled flag, asset group, schedule, or typed options "
            "(port_range, mapping_rate). Same arg shape as "
            "`define_port_scan`.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def edit_port_scan(
        scan_id: str,
        name: str,
        asset_group_id: str,
        port_range: str = "basic",
        mapping_rate: str = "10",
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not scan_id or not name or not asset_group_id:
            raise ValueError("scan_id, name, asset_group_id are required")
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
            "options": {
                "portScanRange": _to_port_scan_range(port_range),
                "interval": _to_mapping_rate(mapping_rate),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client, audit, "edit_port_scan", _M_EDIT_PORT_SCAN, variables, dry_run
        )

    # ---- SNMP scan ---------------------------------------------------

    @mcp.tool(
        title="Define an SNMP scan job (NEW — does not run it)",
        description=(
            "Create an SNMP scan job. Probes target assets for SNMP "
            "metadata (network interfaces, neighbors).\n\n"
            "  • query_network_interfaces: probe interface table.\n"
            "  • query_neighbors: probe SNMP neighbor table.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def define_snmp_scan(
        name: str,
        asset_group_id: str,
        query_network_interfaces: bool = True,
        query_neighbors: bool = True,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name or not asset_group_id:
            raise ValueError("name and asset_group_id are required")
        variables: dict[str, Any] = {
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
            "options": {
                "queryNetworkInterfaces": bool(query_network_interfaces),
                "queryNeighbors": bool(query_neighbors),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client, audit, "define_snmp_scan", _M_CREATE_SNMP_SCAN, variables, dry_run
        )

    @mcp.tool(
        title="Edit an SNMP scan job",
        description=(
            "Modify an existing SNMP scan job. Same arg shape as "
            "`define_snmp_scan`.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def edit_snmp_scan(
        scan_id: str,
        name: str,
        asset_group_id: str,
        query_network_interfaces: bool = True,
        query_neighbors: bool = True,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not scan_id or not name or not asset_group_id:
            raise ValueError("scan_id, name, asset_group_id are required")
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
            "options": {
                "queryNetworkInterfaces": bool(query_network_interfaces),
                "queryNeighbors": bool(query_neighbors),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client, audit, "edit_snmp_scan", _M_EDIT_SNMP_SCAN, variables, dry_run
        )

    # ---- Controller-discovery scan -----------------------------------

    @mcp.tool(
        title="Define a controller-discovery scan (NEW — does not run it)",
        description=(
            "Create a controller-discovery scan job. Tenable OT decides "
            "the scope from its known controller models; no asset-group "
            "or typed options are required.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def define_controller_discovery_scan(
        name: str,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        variables: dict[str, Any] = {
            "name": name,
            "description": description,
            "enabled": bool(enabled),
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "define_controller_discovery_scan",
            _M_CREATE_CONTROLLER_DISCOVERY_SCAN,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Edit a controller-discovery scan job",
        description=(
            "Modify an existing controller-discovery scan job's name, "
            "description, enabled flag, or schedule.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def edit_controller_discovery_scan(
        scan_id: str,
        name: str,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not scan_id or not name:
            raise ValueError("scan_id and name are required")
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "edit_controller_discovery_scan",
            _M_EDIT_CONTROLLER_DISCOVERY_SCAN,
            variables,
            dry_run,
        )

    # ---- Asset-discovery scan ---------------------------------------

    @mcp.tool(
        title="Define an asset-discovery scan (NEW — does not run it)",
        description=(
            "Create an asset-discovery scan job. Sweeps the supplied "
            "networks for previously-unseen assets.\n\n"
            "  • networks: list of CIDR subnets or IP ranges to sweep "
            "(e.g. ['10.100.0.0/16', '192.168.10.0/24']).\n"
            "  • origins: optional list of source-IP addresses the scan "
            "should originate from.\n"
            "  • concurrent_workers: '10' | '20' | '30' — parallel "
            "discovery probes.\n"
            "  • pause_between_probes: '1s' | '2s' | '3s' — gap "
            "between successive probes per worker.\n\n"
            "Asset discovery does not target a single asset group; the "
            "networks list scopes the sweep instead.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def define_asset_discovery_scan(
        name: str,
        networks: list[str] | None = None,
        origins: list[str] | None = None,
        concurrent_workers: str = "10",
        pause_between_probes: str = "1s",
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        variables: dict[str, Any] = {
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "options": {
                "networks": list(networks or []),
                "origins": list(origins or []),
                "concurrentDiscoveryWorkers": _to_concurrent_workers(concurrent_workers),
                "pauseBetweenProbes": _to_pause_between_probes(pause_between_probes),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "define_asset_discovery_scan",
            _M_CREATE_ASSET_DISCOVERY_SCAN,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Edit an asset-discovery scan job",
        description=(
            "Modify an existing asset-discovery scan job: name, "
            "description, enabled, schedule, networks, origins, "
            "concurrent_workers, pause_between_probes. Same arg shape "
            "as `define_asset_discovery_scan`.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def edit_asset_discovery_scan(
        scan_id: str,
        name: str,
        networks: list[str] | None = None,
        origins: list[str] | None = None,
        concurrent_workers: str = "10",
        pause_between_probes: str = "1s",
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not scan_id or not name:
            raise ValueError("scan_id and name are required")
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "options": {
                "networks": list(networks or []),
                "origins": list(origins or []),
                "concurrentDiscoveryWorkers": _to_concurrent_workers(concurrent_workers),
                "pauseBetweenProbes": _to_pause_between_probes(pause_between_probes),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "edit_asset_discovery_scan",
            _M_EDIT_ASSET_DISCOVERY_SCAN,
            variables,
            dry_run,
        )

    # ---- Inactive-probing scan --------------------------------------

    @mcp.tool(
        title="Define an inactive-probing scan (NEW — does not run it)",
        description=(
            "Create an inactive-probing scan job. Probes assets that "
            "have gone silent on the wire to see if they're still "
            "alive.\n\n"
            "  • concurrent_workers: '10' | '20' | '30'.\n"
            "  • pause_between_probes: '1s' | '2s' | '3s'.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def define_inactive_probing_scan(
        name: str,
        asset_group_id: str,
        concurrent_workers: str = "10",
        pause_between_probes: str = "1s",
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name or not asset_group_id:
            raise ValueError("name and asset_group_id are required")
        variables: dict[str, Any] = {
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
            "options": {
                "concurrentDiscoveryWorkers": _to_concurrent_workers(concurrent_workers),
                "pauseBetweenProbes": _to_pause_between_probes(pause_between_probes),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "define_inactive_probing_scan",
            _M_CREATE_INACTIVE_PROBING_SCAN,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Edit an inactive-probing scan job",
        description=(
            "Modify an existing inactive-probing scan job. Same arg "
            "shape as `define_inactive_probing_scan`.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def edit_inactive_probing_scan(
        scan_id: str,
        name: str,
        asset_group_id: str,
        concurrent_workers: str = "10",
        pause_between_probes: str = "1s",
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not scan_id or not name or not asset_group_id:
            raise ValueError("scan_id, name, asset_group_id are required")
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
            "assetGroup": asset_group_id,
            "options": {
                "concurrentDiscoveryWorkers": _to_concurrent_workers(concurrent_workers),
                "pauseBetweenProbes": _to_pause_between_probes(pause_between_probes),
            },
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "edit_inactive_probing_scan",
            _M_EDIT_INACTIVE_PROBING_SCAN,
            variables,
            dry_run,
        )

    # ---- Subnets-discovery (singleton edit; no create) ---------------

    @mcp.tool(
        title="Edit the subnets-discovery scan",
        description=(
            "Tenable OT ships a single subnets-discovery scan job that "
            "operators tune (no create variant — it's a singleton). "
            "Modify name, description, enabled, or schedule.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def edit_subnets_discovery_scan(
        scan_id: str,
        name: str,
        description: str | None = None,
        enabled: bool = False,
        daily_hour: str | None = None,
        interval: str | None = None,
        interval_count: int | None = None,
        day_of_month: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not scan_id or not name:
            raise ValueError("scan_id and name are required")
        variables: dict[str, Any] = {
            "id": scan_id,
            "name": name,
            "description": description,
            "enabled": bool(enabled),
        }
        sched = _schedule_list(daily_hour, interval, interval_count, day_of_month)
        if sched is not None:
            variables["schedule"] = sched
        return await _execute_write(
            client,
            audit,
            "edit_subnets_discovery_scan",
            _M_EDIT_SUBNETS_DISCOVERY_SCAN,
            variables,
            dry_run,
        )


# ----------------------------------------------------------------------
# Shared write helper (dry-run preview + audit + execute)
# ----------------------------------------------------------------------


async def _execute_write(
    client: TenableClient,
    audit: AuditLog,
    tool_name: str,
    mutation: str,
    variables: dict[str, Any],
    dry_run: bool,
) -> dict[str, Any]:
    if dry_run:
        audit.record(
            tool_name=tool_name,
            params=variables,
            dry_run=True,
            outcome="preview",
        )
        return {
            "dry_run": True,
            "tool": tool_name,
            "preview_variables": variables,
            "message": (
                "DRY RUN — no change sent to Tenable OT. Re-call with dry_run=false to apply."
            ),
        }
    try:
        result = await client.query(mutation, variables=variables)
    except Exception as exc:
        audit.record(
            tool_name=tool_name,
            params=variables,
            dry_run=False,
            outcome="error",
            error=str(exc),
        )
        raise
    audit.record(
        tool_name=tool_name,
        params=variables,
        dry_run=False,
        outcome="ok",
    )
    return {"dry_run": False, "tool": tool_name, "result": result}
