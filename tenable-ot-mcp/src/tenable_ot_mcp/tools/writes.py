# SPDX-License-Identifier: Apache-2.0
"""Write tools — gated by `write_tools_enabled` at setup time.

Every write tool follows the same safety pattern:

1. **`dry_run=True` by default.** A first call previews the change
   (returns the planned mutation params as JSON without sending it to
   Tenable OT). The consuming AI surfaces this to the user, awaits
   approval, then calls again with `dry_run=False`.

2. **Audit log on every call.** Token label, tool name, params,
   dry-run flag, and outcome land in `/data/audit.jsonl` regardless
   of dry-run.

3. **Risk-flagged in the description.** Tools that disable detection,
   delete asset records, or otherwise affect the security posture
   call that out explicitly so the consuming AI sees the risk inline
   at tool-selection time.

This module is registered only when the operator opted into write
tools at setup; otherwise these tool names never appear in the
MCP `tools/list` response.

Scope notes:
  • No active scanning is exposed here — see `scans.py` for the
    define-side scan tools, and the `project_no_active_scanning_by_ai`
    memory for the rationale.
  • Every "*Group*" mutation lives in `groups.py` — asset groups,
    email groups, schedule groups, etc. This module covers asset
    edits, custom-field schema, policy lifecycle, and asset removal.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import (
    ASSET_KIND_VALUES,
    CRITICALITY_VALUES,
    EXPR_EQUAL,
    EXPR_GREATER_EQUAL,
    EXPR_IN,
    EXPR_LESS_EQUAL,
    REMOVE_USER_DEFINED,
    USER_DEFINED_ASSET_TYPE_VALUES,
    USER_DEFINED_PURDUE_VALUES,
    VALUE_TYPE_VALUES,
    expr,
    expr_and,
    to_asset_type_setter,
    to_criticality,
    to_policy_level,
    to_purdue_setter,
    to_value_type,
)
from ._sites import current_write_site_machine_id
from .assets import _CUSTOM_FIELD_SLOTS, CustomFieldLabelCache, _build_asset_filter

# ----------------------------------------------------------------------
# Mutations
# ----------------------------------------------------------------------

# Hide / restore — the natural way to remove an asset from default
# views without losing its history. `restore_asset` brings it back.
_M_HIDE_ASSET = """
mutation M($id: ID!, $comment: String) {
  hideAsset(id: $id, comment: $comment) {
    hiddenBy
    timeHidden
    comment
    asset { id name hidden }
  }
}
"""

_M_RESTORE_ASSET = """
mutation M($id: ID!) {
  restoreAsset(id: $id) { id name hidden }
}
"""

_M_BULK_HIDE = """
mutation M($filter: AssetExpressionsParams, $search: String, $comment: String) {
  bulkHideAsset(filter: $filter, search: $search, comment: $comment) {
    totalAssets
    failedAssets
  }
}
"""

_M_BULK_RESTORE = """
mutation M($filter: AssetExpressionsParams, $search: String) {
  bulkRestoreAsset(filter: $filter, search: $search) {
    totalAssets
    failedAssets
  }
}
"""

# True asset removal — Tenable models this as marking IP addresses
# pending deletion. After the operator processes the queue, those
# entries leave inventory and re-discovery will create them fresh.
_M_REMOVE_BY_ADDRESS = """
mutation M($addresses: [String!]!) {
  setAddressesPendingDeletion(addresses: $addresses) {
    addresses
  }
}
"""

# Risk recalculation
_M_RECALC_RISK = """
mutation M($id: ID!) {
  recalculateAssetRisk(id: $id) { id status }
}
"""

_M_RECALC_ALL = """
mutation M($components: [ComponentType!]) {
  recalculateAllAssetsRisk(components: $components) {
    id
  }
}
"""

# Detection-policy lifecycle
_M_ENABLE_POLICY = "mutation M($id: ID!) { enablePolicy(id: $id) { id title disabled } }"
_M_DISABLE_POLICY = "mutation M($id: ID!) { disablePolicy(id: $id) { id title disabled } }"
_M_ARCHIVE_POLICY = "mutation M($id: ID!) { archivePolicy(id: $id) { id title } }"
_M_ENABLE_POLICIES = """
mutation M($ids: [ID!]!) {
  enablePolicies(ids: $ids) { id title disabled }
}
"""
_M_DISABLE_POLICIES = """
mutation M($ids: [ID!]!) {
  disablePolicies(ids: $ids) { id title disabled }
}
"""
_M_ARCHIVE_POLICIES = """
mutation M($ids: [ID!]!) {
  archivePolicies(ids: $ids) { id title }
}
"""

# Asset property edits — change name / type / location / description /
# purdue / criticality / customFields. Pass `_RemoveUserDefinedValue`
# on any enum field to revert to "as Tenable discovered". Free-text
# fields are cleared by passing an empty string.
_M_UPDATE_ASSET = """
mutation M(
  $id: ID!,
  $name: String,
  $type: UserDefinedAssetType,
  $location: String,
  $description: String,
  $customFields: CustomFieldValue,
  $purdueLevel: UserDefinedPurdueLevel,
  $criticality: UserDefinedCriticality
) {
  updateAssetWithRemove(
    id: $id,
    name: $name,
    type: $type,
    location: $location,
    description: $description,
    customFields: $customFields,
    purdueLevel: $purdueLevel,
    criticality: $criticality
  ) {
    id name type location description purdueLevel criticality
    customField1 customField2 customField3 customField4 customField5
    customField6 customField7 customField8 customField9 customField10
  }
}
"""

_M_BULK_EDIT_ASSETS = """
mutation M(
  $filter: AssetExpressionsParams,
  $search: String,
  $name: String,
  $type: UserDefinedAssetType,
  $location: String,
  $description: String,
  $customFields: CustomFieldValue,
  $purdueLevel: UserDefinedPurdueLevel,
  $criticality: UserDefinedCriticality,
  $segment: ID
) {
  bulkEditAssetsWithRemove(
    filter: $filter,
    search: $search,
    name: $name,
    type: $type,
    location: $location,
    description: $description,
    customFields: $customFields,
    purdueLevel: $purdueLevel,
    criticality: $criticality,
    segment: $segment
  ) {
    totalAssets
    failedAssets
  }
}
"""

# Custom-field schema management — the 10 fixed slots Tenable exposes
# for per-asset operator metadata. addCustomField allocates the next
# free slot; updateCustomField renames; deleteCustomField frees the
# slot AND wipes the stored value on every asset that had it set.
_M_ADD_CUSTOM_FIELD = """
mutation M($userDefinedName: String!, $valueType: CustomFieldValueType!) {
  addCustomField(userDefinedName: $userDefinedName, valueType: $valueType) {
    fieldId userDefinedName valueType
  }
}
"""

_M_UPDATE_CUSTOM_FIELD = """
mutation M($fieldId: String!, $userDefinedName: String!, $valueType: CustomFieldValueType!) {
  updateCustomField(fieldId: $fieldId, userDefinedName: $userDefinedName, valueType: $valueType) {
    fieldId userDefinedName valueType
  }
}
"""

_M_DELETE_CUSTOM_FIELD = """
mutation M($fieldId: String!) {
  deleteCustomField(fieldId: $fieldId) {
    fieldId
  }
}
"""

# Finding resolution — the closest thing to "acknowledge / close an
# event" in Tenable's data model. Resolves all matching findings.
_M_RESOLVE_FINDINGS = """
mutation M(
  $filter: PolicyFindingsExpressionsParams,
  $search: String,
  $comment: String
) {
  resolveFindings(filter: $filter, search: $search, comment: $comment) {
    totalResolved
  }
}
"""


# ----------------------------------------------------------------------
# Filter helpers (mirror events / policies projection patterns)
# ----------------------------------------------------------------------

_POLICY_LEVEL_ORDINAL = ["none", "low", "medium", "high"]


def _policy_level_at_least(natural: str) -> list[str]:
    v = (natural or "").strip().lower()
    if v not in _POLICY_LEVEL_ORDINAL:
        raise ValueError(
            f"severity_at_least must be one of {_POLICY_LEVEL_ORDINAL}; got {natural!r}"
        )
    idx = _POLICY_LEVEL_ORDINAL.index(v)
    return [to_policy_level(k) for k in _POLICY_LEVEL_ORDINAL[idx:]]


def _build_findings_filter(
    *,
    policy_id: str | None,
    severity_at_least: str | None,
    status: str | None,
    since: str | None,
    until: str | None,
    plugin_id: str | None,
    mitre_technique: str | None,
) -> dict | None:
    parts: list[dict] = []
    if policy_id:
        parts.append(expr("policyId", EXPR_EQUAL, [policy_id]))
    if severity_at_least:
        parts.append(expr("severity", EXPR_IN, _policy_level_at_least(severity_at_least)))
    if status:
        parts.append(expr("status", EXPR_EQUAL, [status]))
    if since:
        parts.append(expr("lastHitTime", EXPR_GREATER_EQUAL, [since]))
    if until:
        parts.append(expr("lastHitTime", EXPR_LESS_EQUAL, [until]))
    if plugin_id:
        parts.append(expr("pluginId", EXPR_EQUAL, [str(plugin_id)]))
    if mitre_technique:
        parts.append(expr("mitreTechniques", EXPR_EQUAL, [mitre_technique]))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


# ----------------------------------------------------------------------
# Asset-edit helpers
# ----------------------------------------------------------------------

# Top-level editable fields the AI can name in `clear_fields`. Custom
# fields are cleared via empty strings in the `custom_fields` arg or
# wholesale via the "custom_fields" entry below.
_CLEARABLE_TOP_FIELDS = {
    "name",
    "type",
    "kind",
    "location",
    "description",
    "purdue_level",
    "purdue",
    "criticality",
    "custom_fields",
}


async def _build_asset_edit_variables(
    client: TenableClient,
    *,
    icp_machine_id: str | None = None,
    name: str | None,
    kind: str | None,
    location: str | None,
    description: str | None,
    purdue_level: str | None,
    criticality: str | None,
    custom_fields: dict[str, str] | None,
    clear_fields: list[str] | None,
) -> dict[str, Any]:
    """Translate natural-vocab edit args into Tenable mutation variables.

    Free-text fields (name, location, description) are cleared with an
    empty string; enum fields (type, purdueLevel, criticality) are
    cleared with `_RemoveUserDefinedValue`; custom-field slot values
    are cleared with an empty string. Names in `clear_fields` take
    precedence over the corresponding set arg in the same call.
    """
    raw_clear = {f.strip().lower() for f in (clear_fields or [])}
    unknown = raw_clear - _CLEARABLE_TOP_FIELDS
    if unknown:
        raise ValueError(
            f"unknown clear_fields entries: {sorted(unknown)}; "
            f"valid entries are {sorted(_CLEARABLE_TOP_FIELDS)} "
            "(custom-field labels are cleared by passing them in "
            "`custom_fields` with an empty-string value)"
        )

    variables: dict[str, Any] = {}

    if "name" in raw_clear:
        variables["name"] = ""
    elif name is not None:
        variables["name"] = name

    if "location" in raw_clear:
        variables["location"] = ""
    elif location is not None:
        variables["location"] = location

    if "description" in raw_clear:
        variables["description"] = ""
    elif description is not None:
        variables["description"] = description

    if "type" in raw_clear or "kind" in raw_clear:
        variables["type"] = REMOVE_USER_DEFINED
    elif kind is not None:
        variables["type"] = to_asset_type_setter(kind)

    if "purdue_level" in raw_clear or "purdue" in raw_clear:
        variables["purdueLevel"] = REMOVE_USER_DEFINED
    elif purdue_level is not None:
        variables["purdueLevel"] = to_purdue_setter(purdue_level)

    if "criticality" in raw_clear:
        variables["criticality"] = REMOVE_USER_DEFINED
    elif criticality is not None:
        variables["criticality"] = to_criticality(criticality)

    cf_input: dict[str, str] = {}
    if "custom_fields" in raw_clear:
        for slot in _CUSTOM_FIELD_SLOTS:
            cf_input[slot] = ""
    if custom_fields:
        for label, value in custom_fields.items():
            slot = await CustomFieldLabelCache.resolve_label_to_slot(
                client, label, icp_machine_id=icp_machine_id
            )
            cf_input[slot] = value if value is not None else ""
    if cf_input:
        variables["customFields"] = cf_input

    return variables


# ----------------------------------------------------------------------
# Shared write helper
# ----------------------------------------------------------------------


async def _execute_write(
    client: TenableClient,
    audit: AuditLog,
    tool_name: str,
    mutation: str,
    variables: dict[str, Any],
    dry_run: bool,
    *,
    site_uuid: str | None = None,
    site_name: str | None = None,
) -> dict[str, Any]:
    machine_id = current_write_site_machine_id()
    if machine_id is None:
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
    audit_params = {**variables, "_site_uuid": machine_id}
    if dry_run:
        audit.record(
            tool_name=tool_name,
            params=audit_params,
            dry_run=True,
            outcome="preview",
        )
        return {
            "dry_run": True,
            "tool": tool_name,
            "site_uuid": machine_id,
            "preview_variables": variables,
            "message": (
                "DRY RUN — no change sent to Tenable OT. Re-call with dry_run=false to apply."
            ),
        }
    try:
        result = await client.query(mutation, variables=variables, icp_machine_id=machine_id)
    except Exception as exc:
        audit.record(
            tool_name=tool_name,
            params=audit_params,
            dry_run=False,
            outcome="error",
            error=str(exc),
        )
        raise
    audit.record(
        tool_name=tool_name,
        params=audit_params,
        dry_run=False,
        outcome="ok",
    )
    return {
        "dry_run": False,
        "tool": tool_name,
        "site_uuid": machine_id,
        "result": result,
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_write_tools(mcp: Any, client: TenableClient, audit: AuditLog) -> None:
    """Register the write-tool surface."""

    # ------------------------------------------------------------------
    # Asset hide / restore / remove / risk
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Hide an OT asset (filter from default views)",
        description=(
            "Mark one asset as hidden. Hidden assets stay in inventory "
            "(history, vulns, comms preserved) but are filtered out of "
            "default views. Use this for known-safe assets that you "
            "don't want crowding the screen — e.g. a vendor laptop "
            "permanently parked on the network. For HARDWARE that has "
            "been physically pulled, use `remove_assets_by_address` "
            "instead so re-discovery creates a fresh entry on return.\n\n"
            "WRITE — modifies Tenable OT state. Defaults to dry_run."
        ),
    )
    async def hide_asset(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        comment: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not asset_id:
            raise ValueError("asset_id is required")
        return await _execute_write(
            client,
            audit,
            "hide_asset",
            _M_HIDE_ASSET,
            {"id": asset_id, "comment": comment},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Restore a hidden OT asset",
        description=(
            "Un-hide a previously hidden asset. The asset reappears in "
            "default views with its full history intact.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def restore_asset(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not asset_id:
            raise ValueError("asset_id is required")
        return await _execute_write(
            client,
            audit,
            "restore_asset",
            _M_RESTORE_ASSET,
            {"id": asset_id},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Bulk-hide assets matching a filter",
        description=(
            "Hide every asset matching a filter or free-text search. "
            "The filter shape mirrors `query_assets` but is passed "
            "raw (Tenable AssetExpressionsParams). Use the simpler "
            "single-asset `hide_asset` unless you're confident in the "
            "filter's scope.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def bulk_hide_assets(
        site_uuid: str | None = None,
        site_name: str | None = None,
        filter: dict[str, Any] | None = None,
        search: str | None = None,
        comment: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if filter is None and not search:
            raise ValueError("provide at least filter or search")
        return await _execute_write(
            client,
            audit,
            "bulk_hide_assets",
            _M_BULK_HIDE,
            {"filter": filter, "search": search, "comment": comment},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Bulk-restore assets matching a filter",
        description=(
            "Un-hide every asset matching a filter or free-text "
            "search.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def bulk_restore_assets(
        site_uuid: str | None = None,
        site_name: str | None = None,
        filter: dict[str, Any] | None = None,
        search: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if filter is None and not search:
            raise ValueError("provide at least filter or search")
        return await _execute_write(
            client,
            audit,
            "bulk_restore_assets",
            _M_BULK_RESTORE,
            {"filter": filter, "search": search},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Remove asset entries by IP address",
        description=(
            "Mark one or more IP addresses as pending deletion in "
            "Tenable OT. After the operator processes the deletion "
            "queue, those entries leave inventory and any subsequent "
            "discovery creates fresh records.\n\n"
            "Use this for HARDWARE that has been PHYSICALLY PULLED — "
            "decommissioned PLCs, retired switches — where you want a "
            "clean re-discovery if it ever comes back. For known-safe "
            "entries you just want out of default views, use "
            "`hide_asset` instead.\n\n"
            "WRITE — destructive (entry removal). Defaults to dry_run."
        ),
    )
    async def remove_assets_by_address(
        addresses: list[str],
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not addresses:
            raise ValueError("addresses list is required and must be non-empty")
        return await _execute_write(
            client,
            audit,
            "remove_assets_by_address",
            _M_REMOVE_BY_ADDRESS,
            {"addresses": list(addresses)},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Recalculate one asset's risk score",
        description=(
            "Force Tenable OT to recompute the risk score for one "
            "asset. Useful after hiding / un-hiding, after major "
            "vulnerability resolution, or when investigating a stale "
            "score.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def recalculate_asset_risk(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not asset_id:
            raise ValueError("asset_id is required")
        return await _execute_write(
            client,
            audit,
            "recalculate_asset_risk",
            _M_RECALC_RISK,
            {"id": asset_id},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Recalculate risk across the deployment",
        description=(
            "Force a deployment-wide risk recompute. `components` is "
            "optional; pass any of 'Events', 'Vulnerabilities', "
            "'Backplane' (or omit to recompute all). This can be "
            "expensive on large deployments — coordinate with the "
            "operator.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def recalculate_all_risk(
        site_uuid: str | None = None,
        site_name: str | None = None,
        components: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _execute_write(
            client,
            audit,
            "recalculate_all_risk",
            _M_RECALC_ALL,
            {"components": components},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    # ------------------------------------------------------------------
    # Asset property edits (name, type, location, description,
    # purdueLevel, criticality, customFields)
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Edit an OT asset's properties",
        description=(
            "Edit one OT asset's operator-set properties. Pass any subset of "
            "the editable fields; omitted fields are left untouched. Names "
            "in `clear_fields` revert the corresponding property to "
            "'as Tenable discovered' (the underlying mutation passes "
            "`_RemoveUserDefinedValue` for enums and empty strings for "
            "free text).\n\n"
            "Natural-vocabulary inputs are translated to Tenable enums "
            "before the GraphQL goes out:\n"
            f"  • kind: any of {USER_DEFINED_ASSET_TYPE_VALUES} (case- and "
            "separator-insensitive — accepts 'plc', 'ot_workstation', "
            "'data_logger', etc.)\n"
            f"  • purdue_level: one of {USER_DEFINED_PURDUE_VALUES}\n"
            f"  • criticality: one of {CRITICALITY_VALUES}\n"
            "  • custom_fields: dict keyed by the operator's configured "
            "label (call `list_custom_fields` first to learn the vocabulary). "
            "Empty-string values clear the stored value on that label.\n\n"
            "Reclassifying an asset (`kind`) affects every downstream view "
            "that filters by category; changing `criticality` flows into "
            "risk scoring. Audit-logged. Defaults to dry_run."
        ),
    )
    async def update_asset(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        name: str | None = None,
        kind: str | None = None,
        location: str | None = None,
        description: str | None = None,
        purdue_level: str | None = None,
        criticality: str | None = None,
        custom_fields: dict[str, str] | None = None,
        clear_fields: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not asset_id:
            raise ValueError("asset_id is required")
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        edit_vars = await _build_asset_edit_variables(
            client,
            icp_machine_id=machine_id,
            name=name,
            kind=kind,
            location=location,
            description=description,
            purdue_level=purdue_level,
            criticality=criticality,
            custom_fields=custom_fields,
            clear_fields=clear_fields,
        )
        if not edit_vars:
            raise ValueError(
                "provide at least one editable field (name, kind, location, "
                "description, purdue_level, criticality, custom_fields) or "
                "an entry in clear_fields"
            )
        variables = {"id": asset_id, **edit_vars}
        return await _execute_write(
            client,
            audit,
            "update_asset",
            _M_UPDATE_ASSET,
            variables,
            dry_run,
            site_uuid=machine_id,
            site_name=None,
        )

    @mcp.tool(
        title="Bulk-edit OT assets matching a filter",
        description=(
            "Apply the same property edit to every asset matching a "
            "natural-vocabulary filter or free-text search. Targeting "
            "args mirror `query_assets`:\n"
            f"  • kind: one of {ASSET_KIND_VALUES} (kind subset for filtering)\n"
            "  • category: 'controller' | 'network' | 'iot'\n"
            f"  • criticality_at_least: one of {CRITICALITY_VALUES}\n"
            "  • vendor: equal-match on vendor name\n"
            "  • name_contains: substring on asset name\n"
            "  • search: single-term substring across multiple fields\n"
            "  • hidden: True/False/None\n\n"
            "Edit args are the same as `update_asset` plus `segment_id` "
            "to reassign segment membership. AT LEAST ONE targeting arg "
            "is required — bare un-filtered bulk edits are rejected.\n\n"
            "WRITE — affects many assets. Audit-logged. Defaults to dry_run."
        ),
    )
    async def bulk_edit_assets(
        site_uuid: str | None = None,
        site_name: str | None = None,
        kind: str | None = None,
        category: str | None = None,
        criticality_at_least: str | None = None,
        vendor: str | None = None,
        name_contains: str | None = None,
        search: str | None = None,
        hidden: bool | None = None,
        name: str | None = None,
        set_kind: str | None = None,
        location: str | None = None,
        description: str | None = None,
        purdue_level: str | None = None,
        criticality: str | None = None,
        custom_fields: dict[str, str] | None = None,
        segment_id: str | None = None,
        clear_fields: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        filt = _build_asset_filter(
            kind=kind,
            vendor=vendor,
            name_contains=name_contains,
            category=category,
            criticality_at_least=criticality_at_least,
            hidden=hidden,
        )
        if filt is None and not search:
            raise ValueError(
                "provide at least one targeting arg (kind, category, "
                "criticality_at_least, vendor, name_contains, hidden) or `search`; "
                "bare unfiltered bulk edits are rejected"
            )
        edit_vars = await _build_asset_edit_variables(
            client,
            icp_machine_id=machine_id,
            name=name,
            kind=set_kind,
            location=location,
            description=description,
            purdue_level=purdue_level,
            criticality=criticality,
            custom_fields=custom_fields,
            clear_fields=clear_fields,
        )
        if not edit_vars and not segment_id:
            raise ValueError(
                "provide at least one edit arg (name, set_kind, location, "
                "description, purdue_level, criticality, custom_fields, "
                "segment_id) or an entry in clear_fields"
            )
        variables: dict[str, Any] = {**edit_vars}
        if filt is not None:
            variables["filter"] = filt
        if search:
            variables["search"] = search
        if segment_id:
            variables["segment"] = segment_id
        return await _execute_write(
            client,
            audit,
            "bulk_edit_assets",
            _M_BULK_EDIT_ASSETS,
            variables,
            dry_run,
            site_uuid=machine_id,
            site_name=None,
        )

    @mcp.tool(
        title="Reset one asset's operator-set metadata",
        description=(
            "Revert every operator-set field on one asset back to 'as "
            "Tenable discovered'. Clears name, type, location, "
            "description, purdueLevel, criticality, and every "
            "custom-field slot value. Tenable's auto-classification "
            "fields (vendor, model, firmware, family) are not affected. "
            "Observed data (events, vulnerabilities, comms history) is "
            "preserved — for a full re-discovery use "
            "`remove_assets_by_address` instead.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def reset_asset_metadata(
        asset_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not asset_id:
            raise ValueError("asset_id is required")
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        edit_vars = await _build_asset_edit_variables(
            client,
            icp_machine_id=machine_id,
            name=None,
            kind=None,
            location=None,
            description=None,
            purdue_level=None,
            criticality=None,
            custom_fields=None,
            clear_fields=[
                "name",
                "type",
                "location",
                "description",
                "purdue_level",
                "criticality",
                "custom_fields",
            ],
        )
        variables = {"id": asset_id, **edit_vars}
        return await _execute_write(
            client,
            audit,
            "reset_asset_metadata",
            _M_UPDATE_ASSET,
            variables,
            dry_run,
            site_uuid=machine_id,
            site_name=None,
        )

    # ------------------------------------------------------------------
    # Custom-field schema management (the 10 named slots)
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a custom-field slot",
        description=(
            "Allocate one of Tenable's 10 custom-field slots and assign "
            "it an operator-defined label. Fails clearly if all 10 "
            "slots are already in use.\n\n"
            f"Args:\n  • name: human label (e.g. 'Plant ID', 'CDA Type').\n"
            f"  • value_type: one of {VALUE_TYPE_VALUES} (default 'PlainText'; "
            "'HyperLink' renders the value as a clickable URL in the UI).\n\n"
            "After this succeeds, set values on assets via `update_asset "
            "custom_fields={'<name>': '<value>'}`.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_custom_field(
        name: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        value_type: str = "PlainText",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name or not name.strip():
            raise ValueError("name is required")
        variables = {
            "userDefinedName": name.strip(),
            "valueType": to_value_type(value_type),
        }
        result = await _execute_write(
            client,
            audit,
            "create_custom_field",
            _M_ADD_CUSTOM_FIELD,
            variables,
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )
        if not dry_run:
            CustomFieldLabelCache.invalidate()
        return result

    @mcp.tool(
        title="Rename a custom-field slot",
        description=(
            "Change the operator-defined label and/or value type on an "
            "existing custom-field slot. Stored values are preserved.\n\n"
            "Identify the slot by either `field_id` ('customField1'..) "
            "or `current_name` (the label as configured today). One is "
            "required.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def rename_custom_field(
        new_name: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        field_id: str | None = None,
        current_name: str | None = None,
        value_type: str = "PlainText",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not new_name or not new_name.strip():
            raise ValueError("new_name is required")
        if not field_id and not current_name:
            raise ValueError("provide either field_id or current_name to identify the slot")
        if field_id and current_name:
            raise ValueError("provide only one of field_id or current_name")
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        resolved_id = field_id or await CustomFieldLabelCache.resolve_label_to_slot(
            client,
            current_name,  # type: ignore[arg-type]
            icp_machine_id=machine_id,
        )
        variables = {
            "fieldId": resolved_id,
            "userDefinedName": new_name.strip(),
            "valueType": to_value_type(value_type),
        }
        result = await _execute_write(
            client,
            audit,
            "rename_custom_field",
            _M_UPDATE_CUSTOM_FIELD,
            variables,
            dry_run,
            site_uuid=machine_id,
            site_name=None,
        )
        if not dry_run:
            CustomFieldLabelCache.invalidate()
        return result

    @mcp.tool(
        title="Delete a custom-field slot",
        description=(
            "Delete a custom-field slot. The slot is freed for reuse "
            "AND every asset that had a value stored under this slot "
            "has that value wiped — there is no undo.\n\n"
            "Identify the slot by either `field_id` ('customField1'..) "
            "or `current_name`. To guard against accidental loss, "
            "`confirm_wipes_values=True` is REQUIRED on top of "
            "`dry_run=False` — without it the call is rejected even "
            "when dry-run is off.\n\n"
            "WRITE — destructive (wipes per-asset values). Defaults to dry_run."
        ),
    )
    async def delete_custom_field(
        site_uuid: str | None = None,
        site_name: str | None = None,
        field_id: str | None = None,
        current_name: str | None = None,
        confirm_wipes_values: bool = False,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not field_id and not current_name:
            raise ValueError("provide either field_id or current_name to identify the slot")
        if field_id and current_name:
            raise ValueError("provide only one of field_id or current_name")
        if not dry_run and not confirm_wipes_values:
            raise ValueError(
                "delete_custom_field is destructive (wipes the value on every "
                "asset that had it set). Set confirm_wipes_values=True to apply."
            )
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        resolved_id = field_id or await CustomFieldLabelCache.resolve_label_to_slot(
            client,
            current_name,  # type: ignore[arg-type]
            icp_machine_id=machine_id,
        )
        variables = {"fieldId": resolved_id}
        result = await _execute_write(
            client,
            audit,
            "delete_custom_field",
            _M_DELETE_CUSTOM_FIELD,
            variables,
            dry_run,
            site_uuid=machine_id,
            site_name=None,
        )
        if not dry_run:
            CustomFieldLabelCache.invalidate()
        return result

    # ------------------------------------------------------------------
    # Detection-policy lifecycle
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Enable a detection policy",
        description=(
            "Enable one detection policy by id (Tenable's "
            "`enablePolicy`). The policy starts firing events on "
            "matching traffic.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def enable_detection_policy(
        policy_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_id:
            raise ValueError("policy_id is required")
        return await _execute_write(
            client,
            audit,
            "enable_detection_policy",
            _M_ENABLE_POLICY,
            {"id": policy_id},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Disable a detection policy",
        description=(
            "Disable one detection policy by id. The policy stops "
            "firing new events but its history and findings persist. "
            "Use to silence a noisy or known-tuning-needed policy "
            "without deleting it.\n\nDISABLES DETECTION — review the "
            "blast radius before applying.\n\nWRITE. Defaults to "
            "dry_run."
        ),
    )
    async def disable_detection_policy(
        policy_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_id:
            raise ValueError("policy_id is required")
        return await _execute_write(
            client,
            audit,
            "disable_detection_policy",
            _M_DISABLE_POLICY,
            {"id": policy_id},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Archive a detection policy",
        description=(
            "Archive (effectively delete) a detection policy. Past "
            "findings remain queryable but the policy no longer "
            "appears in active lists.\n\nWRITE — irreversible. "
            "Defaults to dry_run."
        ),
    )
    async def archive_detection_policy(
        policy_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_id:
            raise ValueError("policy_id is required")
        return await _execute_write(
            client,
            audit,
            "archive_detection_policy",
            _M_ARCHIVE_POLICY,
            {"id": policy_id},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Bulk enable detection policies",
        description=("Enable many detection policies at once.\n\nWRITE. Defaults to dry_run."),
    )
    async def enable_detection_policies(
        policy_ids: list[str],
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_ids:
            raise ValueError("policy_ids list is required and must be non-empty")
        return await _execute_write(
            client,
            audit,
            "enable_detection_policies",
            _M_ENABLE_POLICIES,
            {"ids": list(policy_ids)},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Bulk disable detection policies",
        description=(
            "Disable many detection policies at once. Like "
            "`disable_detection_policy`, this stops new events from "
            "firing — review blast radius before applying.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def disable_detection_policies(
        policy_ids: list[str],
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_ids:
            raise ValueError("policy_ids list is required and must be non-empty")
        return await _execute_write(
            client,
            audit,
            "disable_detection_policies",
            _M_DISABLE_POLICIES,
            {"ids": list(policy_ids)},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    @mcp.tool(
        title="Bulk archive detection policies",
        description=(
            "Archive (effectively delete) many detection policies at "
            "once. Past findings remain queryable.\n\n"
            "WRITE — irreversible. Defaults to dry_run."
        ),
    )
    async def archive_detection_policies(
        policy_ids: list[str],
        site_uuid: str | None = None,
        site_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_ids:
            raise ValueError("policy_ids list is required and must be non-empty")
        return await _execute_write(
            client,
            audit,
            "archive_detection_policies",
            _M_ARCHIVE_POLICIES,
            {"ids": list(policy_ids)},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )

    # ------------------------------------------------------------------
    # Findings resolution
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Resolve detection findings",
        description=(
            "Mark detection findings resolved (Tenable's "
            "`resolveFindings`). Filter values use the same natural "
            "OT vocabulary as `query_policy_findings`:\n"
            "  • severity_at_least: 'none' | 'low' | 'medium' | 'high'\n"
            "  • status: a FindingStatus value\n"
            "  • since / until: ISO-8601 timestamps on lastHitTime\n"
            "  • policy_id / plugin_id / mitre_technique: equal-match "
            "id filters\n"
            "  • search: single-term substring across finding text\n\n"
            "Pass `comment` to attach a resolution note. AT LEAST ONE "
            "filter or `search` is required — bare resolveAll is "
            "rejected.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def resolve_findings(
        site_uuid: str | None = None,
        site_name: str | None = None,
        policy_id: str | None = None,
        severity_at_least: str | None = None,
        status: str | None = None,
        since: str | None = None,
        until: str | None = None,
        plugin_id: str | None = None,
        mitre_technique: str | None = None,
        search: str | None = None,
        comment: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        filt = _build_findings_filter(
            policy_id=policy_id,
            severity_at_least=severity_at_least,
            status=status,
            since=since,
            until=until,
            plugin_id=plugin_id,
            mitre_technique=mitre_technique,
        )
        if filt is None and not search:
            raise ValueError(
                "provide at least one filter argument or `search`; bare resolve-all is rejected"
            )
        return await _execute_write(
            client,
            audit,
            "resolve_findings",
            _M_RESOLVE_FINDINGS,
            {"filter": filt, "search": search, "comment": comment},
            dry_run,
            site_uuid=site_uuid,
            site_name=site_name,
        )
