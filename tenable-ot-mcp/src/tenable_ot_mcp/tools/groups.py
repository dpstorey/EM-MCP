# SPDX-License-Identifier: Apache-2.0
"""Group surface — every "*Group*" mutation and query Tenable OT exposes.

Tenable OT has eight first-class group types, all consumed by detection
policies and security workflows:

* **AssetGroup** (polymorphic — AssetList / IpList / IpRange / TypeFamily
  / Segment / Filter / Function): the building block of policy
  scoping. Used as `srcAssetGroup` / `dstAssetGroup` on every policy
  mutation. May also surface as a UI tag when `display_tag=True`.
* **EmailGroup**: recipient list bound to one SMTP server, referenced by
  policy actions to route alert emails.
* **PortGroup** / **ProtocolGroup**: reusable port-range and
  protocol-with-port-range definitions for port and protocol policies.
  Tenable's mutations are named `*PortList` / `*ProtocolList`; the
  natural surface here uses *Group* throughout for consistency.
* **RuleGroup**: bundles of IDS rule ids referenced by IntrusionPolicy.
* **ScheduleGroup**: maintenance / business-hours windows that every
  policy mutation's `schedule` argument resolves against.
* **TagGroup**: PLC controller-tag rollups (NOT the asset-grouping-with-
  displayTag — a distinct OT concept covering tags on industrial
  controllers). Bound to tag-value policies.
* **UserGroup** / **EmUserGroup**: permission groupings for ICP-level
  and EM (Enterprise Manager) -level users. Drive role assignment and
  zone access.

Each group type gets the same five tools: `create_*`, `update_*` (or
`edit_*` where Tenable's mutation is named that way), `archive_*`,
`list_*`, `get_*`. Archived-list and other read shortcuts are added
where Tenable's schema exposes them.

Write tools follow the project-wide write safety pattern: every call
defaults to `dry_run=True`, every call hits the audit log, and risks
are called out in the tool description. See `writes.py` for the
shared `_execute_write` helper.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._shared import clamp_page_size, unwrap_nodes

# ===========================================================================
# Asset groups
# ===========================================================================
#
# `newAssetGroup` returns the `AssetGroup` *interface*. The interface's
# field set is `id name type archived system key lastModifiedDate
# lastModifiedBy displayTag isStaticType filter policies queries zones
# usedInRestrictions usageInfo` — note `description` is NOT on the
# interface (it lives on the SegmentGroup subtype only). Selecting it
# here would fail with `Cannot query field "description" on type
# "AssetGroup"`. We pass it as an input arg (mutations accept it) but
# don't echo it back — the AI already has the value it sent.

_M_NEW_ASSET_GROUP = """
mutation M(
  $name: String!,
  $type: AssetGroupType!,
  $assetsIds: [ID!],
  $ips: [String!],
  $startIp: String,
  $endIp: String,
  $assetType: AssetType,
  $family: String,
  $vlan: String,
  $description: String,
  $displayTag: Boolean,
  $filter: AssetGroupExpressionsParams
) {
  newAssetGroup(
    name: $name,
    type: $type,
    assetsIds: $assetsIds,
    ips: $ips,
    startIp: $startIp,
    endIp: $endIp,
    assetType: $assetType,
    family: $family,
    vlan: $vlan,
    description: $description,
    displayTag: $displayTag,
    filter: $filter
  ) { id name type archived displayTag }
}
"""

_M_SET_ASSET_GROUP = """
mutation M(
  $id: ID!,
  $name: String!,
  $type: AssetGroupType!,
  $assetsIds: [ID!],
  $ips: [String!],
  $startIp: String,
  $endIp: String,
  $assetType: AssetType,
  $family: String,
  $vlan: String,
  $description: String,
  $displayTag: Boolean,
  $filter: AssetGroupExpressionsParams
) {
  setAssetGroup(
    id: $id,
    name: $name,
    type: $type,
    assetsIds: $assetsIds,
    ips: $ips,
    startIp: $startIp,
    endIp: $endIp,
    assetType: $assetType,
    family: $family,
    vlan: $vlan,
    description: $description,
    displayTag: $displayTag,
    filter: $filter
  ) { id name type archived displayTag }
}
"""

_M_ARCHIVE_ASSET_GROUP = """
mutation M($id: ID!) {
  archiveAssetGroup(id: $id) { id }
}
"""

_M_BULK_SET_DISPLAY_TAG = """
mutation M($ids: [ID!]!, $status: Boolean!) {
  setAssetGroupsDisplayTag(ids: $ids, status: $status) {
    id
    status
    value
    error
  }
}
"""

# Common read shape for the AssetGroup interface. `description` is on
# SegmentGroup only — we surface it via a typed fragment so it's
# present in the result when the group happens to be a SegmentGroup
# and silently absent otherwise.
_ASSET_GROUP_FIELDS = """
  id
  name
  type
  archived
  system
  key
  lastModifiedDate
  lastModifiedBy
  displayTag
  isStaticType
  ... on SegmentGroup { description vlan }
  ... on FilterGroup { filter { field op values } }
  ... on AssetTypeFamilyGroup { assetType family }
  ... on AssetList { assets(first: 50) { totalCount nodes { id name } } }
  ... on IpList { ips { totalCount nodes } }
  ... on IpRange { startIp endIp }
"""

_Q_ASSET_GROUPS = f"""
query Q($after: String, $first: Int) {{
  assetGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_ASSET_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ARCHIVED_ASSET_GROUPS = f"""
query Q($after: String, $first: Int) {{
  archivedAssetGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_ASSET_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ASSET_GROUP = f"""
query Q($id: ID!) {{
  assetGroup(id: $id) {{
{_ASSET_GROUP_FIELDS}
  }}
}}
"""


# ===========================================================================
# Email groups
# ===========================================================================
#
# An EmailGroup is a recipient list bound to one SMTP server (referenced
# by ID). Policy actions route alert emails through these groups, so the
# email-group surface is one of the highest-leverage places to wire
# automation: change the group's recipients and every policy currently
# referencing it updates without per-policy edits.

_M_NEW_EMAIL_GROUP = """
mutation M($name: String!, $server: ID!, $recipients: [String!]!) {
  newEmailGroup(name: $name, server: $server, recipients: $recipients) {
    id name lastModifiedDate lastModifiedBy
    server { id name }
  }
}
"""

_M_SET_EMAIL_GROUP = """
mutation M($id: ID!, $name: String!, $server: ID!, $recipients: [String!]!) {
  setEmailGroup(id: $id, name: $name, server: $server, recipients: $recipients) {
    id name lastModifiedDate lastModifiedBy
    server { id name }
  }
}
"""

_M_ARCHIVE_EMAIL_GROUP = """
mutation M($id: ID!) {
  archiveEmailGroup(id: $id) { id name }
}
"""

_EMAIL_GROUP_FIELDS = """
  id
  name
  lastModifiedDate
  lastModifiedBy
  server { id name smtpServer smtpPort smtpUser sender archived }
  recipients { totalCount nodes }
"""

_Q_EMAIL_GROUPS = f"""
query Q($after: String, $first: Int) {{
  emailGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_EMAIL_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_EMAIL_GROUP = f"""
query Q($id: ID!) {{
  emailGroup(id: $id) {{
{_EMAIL_GROUP_FIELDS}
  }}
}}
"""

_Q_USED_IN_EMAIL_GROUPS = f"""
query Q($id: ID!, $after: String, $first: Int) {{
  usedInEmailGroups(id: $id, after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_EMAIL_GROUP_FIELDS}
    }}
  }}
}}
"""


# ===========================================================================
# Schedule groups
# ===========================================================================
#
# ScheduleGroup is an interface with three subtypes:
#   • TimeInterval  — a single (start, end) window. Mutation type =
#                     "IntervalGroup".
#   • RecurringGroup — weekly recurring [(day, start, end), ...] windows.
#                      Mutation type = "RecurringGroup".
#   • ScheduleFunction — a named Tenable-defined function (the operator
#                        cannot define new ones via API). Mutation type =
#                        "Function".
#
# Tenable's `newScheduleGroup.type` argument is a *String*, not an enum,
# and accepts the three values above. The MCP tool picks which value to
# send based on which inputs the caller provided.

_M_NEW_SCHEDULE_GROUP = """
mutation M(
  $name: String!,
  $type: String!,
  $start: Time,
  $end: Time,
  $schedules: [TypedIntervalParams!]
) {
  newScheduleGroup(
    name: $name, type: $type,
    start: $start, end: $end, schedules: $schedules
  ) { id name type archived }
}
"""

_M_SET_SCHEDULE_GROUP = """
mutation M(
  $id: ID!,
  $name: String!,
  $type: String!,
  $start: Time,
  $end: Time,
  $schedules: [TypedIntervalParams!]
) {
  setScheduleGroup(
    id: $id, name: $name, type: $type,
    start: $start, end: $end, schedules: $schedules
  ) { id name type archived }
}
"""

_M_ARCHIVE_SCHEDULE_GROUP = """
mutation M($id: ID!) {
  archiveScheduleGroup(id: $id) { id name }
}
"""

_SCHEDULE_GROUP_FIELDS = """
  id
  name
  type
  archived
  system
  key
  lastModifiedDate
  lastModifiedBy
  ... on TimeInterval { start end }
  ... on RecurringGroup {
    schedules(first: 50) {
      totalCount
      nodes { type start end }
    }
  }
"""

_Q_SCHEDULE_GROUPS = f"""
query Q($after: String, $first: Int) {{
  scheduleGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_SCHEDULE_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ARCHIVED_SCHEDULE_GROUPS = f"""
query Q($after: String, $first: Int) {{
  archivedScheduleGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_SCHEDULE_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_SCHEDULE_GROUP = f"""
query Q($id: ID!) {{
  scheduleGroup(id: $id) {{
{_SCHEDULE_GROUP_FIELDS}
  }}
}}
"""


# ===========================================================================
# Tag groups — PLC controller-tag rollups
# ===========================================================================
#
# A TagGroup bundles controller tags by (assetId, tagId) so a single
# TagValuePolicy can fire against all of them. `tagType` constrains the
# scalar type Tenable expects the tag values to have at evaluation
# time. The TagType enum is {Unknown, Int, Bool, Short, DInt, Long,
# Float, MultipleTagTypes}.

_TAG_TYPE_VALUES = [
    "Unknown",
    "Int",
    "Bool",
    "Short",
    "DInt",
    "Long",
    "Float",
    "MultipleTagTypes",
]

_M_NEW_TAG_GROUP = """
mutation M($name: String!, $items: [TagGroupItemParams!]!, $tagType: TagType!) {
  newTagGroup(name: $name, items: $items, tagType: $tagType) {
    id name type archived tagType
  }
}
"""

_M_SET_TAG_GROUP = """
mutation M($id: ID!, $name: String!, $items: [TagGroupItemParams!]!, $tagType: TagType!) {
  setTagGroup(id: $id, name: $name, items: $items, tagType: $tagType) {
    id name type archived tagType
  }
}
"""

_M_ARCHIVE_TAG_GROUP = """
mutation M($id: ID!) {
  archiveTagGroup(id: $id) { id name }
}
"""

_TAG_GROUP_FIELDS = """
  id
  name
  type
  tagType
  archived
  system
  key
  lastModifiedDate
  lastModifiedBy
  items(first: 100) {
    totalCount
    nodes { tagId tagType asset { id name } }
  }
"""

_Q_TAG_GROUPS = f"""
query Q($after: String, $first: Int) {{
  tagGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_TAG_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_TAG_GROUP = f"""
query Q($id: ID!) {{
  tagGroup(id: $id) {{
{_TAG_GROUP_FIELDS}
  }}
}}
"""

_Q_TAGS_FOR_TAG_GROUP = """
query Q($asset: ID, $type: TagType, $after: String, $first: Int) {
  tagsForTagGroup(asset: $asset, type: $type, after: $after, first: $first) {
    totalCount
    pageInfo { endCursor hasNextPage }
    nodes {
      asset { id name }
      tags(first: 100) {
        totalCount
        nodes { id name type address }
      }
    }
  }
}
"""


# ===========================================================================
# Rule groups — IDS rule bundles
# ===========================================================================
#
# Rule SIDs are Tenable's identifier for individual IDS rules. The
# `items` array is `[Float!]` in the schema (oddly — but that's how
# they encode Snort SID-style numeric ids). IntrusionPolicy references
# the resulting RuleGroup by id via the `ruleGroup` arg.

_M_NEW_RULE_GROUP = """
mutation M($name: String!, $items: [Float!]!) {
  newRuleGroup(name: $name, items: $items) {
    id name type archived itemsCount
  }
}
"""

_M_SET_RULE_GROUP = """
mutation M($id: ID!, $name: String!, $items: [Float!]!) {
  setRuleGroup(id: $id, name: $name, items: $items) {
    id name type archived itemsCount
  }
}
"""

_M_ARCHIVE_RULE_GROUP = """
mutation M($id: ID!) {
  archiveRuleGroup(id: $id) { id name }
}
"""

_RULE_GROUP_FIELDS = """
  id
  name
  type
  archived
  system
  key
  lastModifiedDate
  lastModifiedBy
  itemsCount
  items(first: 25) {
    totalCount
    nodes { sid rev protocol msg category enabled }
  }
"""

_Q_RULE_GROUPS = f"""
query Q($after: String, $first: Int) {{
  ruleGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_RULE_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ARCHIVED_RULE_GROUPS = f"""
query Q($after: String, $first: Int) {{
  archivedRuleGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_RULE_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_RULE_GROUP = f"""
query Q($id: ID!) {{
  ruleGroup(id: $id) {{
{_RULE_GROUP_FIELDS}
  }}
}}
"""


# ===========================================================================
# Port groups — port-range bundles for PortPolicy
# ===========================================================================
#
# Tenable's mutations are named `newPortList` / `setPortList` /
# `archivePortList` and return the `PortGroup` type. The natural MCP
# surface uses *port_group* throughout to stay consistent with the
# other group types — translation happens inside.

_M_NEW_PORT_GROUP = """
mutation M($name: String!, $items: [PortListItemParams!]!) {
  newPortList(name: $name, items: $items) {
    id name type archived
  }
}
"""

_M_SET_PORT_GROUP = """
mutation M($id: ID!, $name: String!, $items: [PortListItemParams!]!) {
  setPortList(id: $id, name: $name, items: $items) {
    id name type archived
  }
}
"""

_M_ARCHIVE_PORT_GROUP = """
mutation M($id: ID!) {
  archivePortList(id: $id) { id name }
}
"""

_PORT_GROUP_FIELDS = """
  id
  name
  type
  archived
  system
  key
  lastModifiedDate
  lastModifiedBy
  items(first: 100) {
    totalCount
    nodes { startPort endPort }
  }
"""

_Q_PORT_GROUPS = f"""
query Q($after: String, $first: Int) {{
  portGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_PORT_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ARCHIVED_PORT_GROUPS = f"""
query Q($after: String, $first: Int) {{
  archivedPortGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_PORT_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_PORT_GROUP = f"""
query Q($id: ID!) {{
  portGroup(id: $id) {{
{_PORT_GROUP_FIELDS}
  }}
}}
"""


# ===========================================================================
# Protocol groups — (protocol, port-range) bundles for ProtocolPolicy
# ===========================================================================

_M_NEW_PROTOCOL_GROUP = """
mutation M($name: String!, $items: [ProtocolListItemParams!]!) {
  newProtocolList(name: $name, items: $items) {
    id name type archived
  }
}
"""

_M_SET_PROTOCOL_GROUP = """
mutation M($id: ID!, $name: String!, $items: [ProtocolListItemParams!]!) {
  setProtocolList(id: $id, name: $name, items: $items) {
    id name type archived
  }
}
"""

_M_ARCHIVE_PROTOCOL_GROUP = """
mutation M($id: ID!) {
  archiveProtocolList(id: $id) { id name }
}
"""

_PROTOCOL_GROUP_FIELDS = """
  id
  name
  type
  archived
  system
  key
  lastModifiedDate
  lastModifiedBy
  items(first: 100) {
    totalCount
    nodes { protocol startPort endPort }
  }
"""

_Q_PROTOCOL_GROUPS = f"""
query Q($after: String, $first: Int) {{
  protocolGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_PROTOCOL_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ARCHIVED_PROTOCOL_GROUPS = f"""
query Q($after: String, $first: Int) {{
  archivedProtocolGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_PROTOCOL_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_PROTOCOL_GROUP = f"""
query Q($id: ID!) {{
  protocolGroup(id: $id) {{
{_PROTOCOL_GROUP_FIELDS}
  }}
}}
"""


# ===========================================================================
# User groups (ICP-level) and EmUserGroup (Enterprise Manager-level)
# ===========================================================================
#
# `newUserGroup` / `editUserGroup` operate on ICP-level user groups.
# `newEmUserGroup` / `editEmUserGroup` operate on Enterprise-Manager-
# level groups, which add `emLevel: Boolean!` and surface site
# pairings. `setUserGroups` / `setEmUserGroups` reassign a single
# user's group membership in one call.

_M_NEW_USER_GROUP = """
mutation M(
  $name: String!,
  $roles: [String!],
  $users: [String],
  $providersMapping: [GroupProviderParams!],
  $zones: [String!],
  $emIcpUserGroupIds: [String!]
) {
  newUserGroup(
    name: $name, roles: $roles, users: $users,
    providersMapping: $providersMapping, zones: $zones,
    emIcpUserGroupIds: $emIcpUserGroupIds
  ) { id name system }
}
"""

_M_EDIT_USER_GROUP = """
mutation M(
  $id: ID!,
  $name: String!,
  $roles: [String!],
  $users: [String],
  $providersMapping: [GroupProviderParams!],
  $zones: [String!],
  $emIcpUserGroupIds: [String!]
) {
  editUserGroup(
    id: $id, name: $name, roles: $roles, users: $users,
    providersMapping: $providersMapping, zones: $zones,
    emIcpUserGroupIds: $emIcpUserGroupIds
  ) { id name system }
}
"""

_M_ARCHIVE_USER_GROUP = """
mutation M($id: ID!) {
  archiveUserGroup(id: $id) { id name }
}
"""

_M_SET_USER_GROUPS = """
mutation M($userName: String, $newGroups: [ID!]!) {
  setUserGroups(userName: $userName, newGroups: $newGroups) {
    id userName
  }
}
"""

_M_NEW_EM_USER_GROUP = """
mutation M(
  $name: String!,
  $roles: [String!],
  $users: [String],
  $providersMapping: [GroupProviderParams!],
  $zones: [String!],
  $emIcpUserGroupIds: [String!],
  $emLevel: Boolean!
) {
  newEmUserGroup(
    name: $name, roles: $roles, users: $users,
    providersMapping: $providersMapping, zones: $zones,
    emIcpUserGroupIds: $emIcpUserGroupIds, emLevel: $emLevel
  ) { id name system emLevel }
}
"""

_M_EDIT_EM_USER_GROUP = """
mutation M(
  $id: ID!,
  $name: String!,
  $roles: [String!],
  $users: [String],
  $providersMapping: [GroupProviderParams!],
  $zones: [String!],
  $emIcpUserGroupIds: [String!]
) {
  editEmUserGroup(
    id: $id, name: $name, roles: $roles, users: $users,
    providersMapping: $providersMapping, zones: $zones,
    emIcpUserGroupIds: $emIcpUserGroupIds
  ) { id name system emLevel }
}
"""

_M_ARCHIVE_EM_USER_GROUP = """
mutation M($id: ID!) {
  archiveEmUserGroup(id: $id) { id name }
}
"""

_M_SET_EM_USER_GROUPS = """
mutation M($userName: String, $newGroups: [ID!]!) {
  setEmUserGroups(userName: $userName, newGroups: $newGroups) {
    id userName
  }
}
"""

_USER_GROUP_FIELDS = """
  id
  name
  system
  users(first: 50) { totalCount nodes { id userName fullName } }
  roles(first: 25) { totalCount nodes { id name } }
"""

_EM_USER_GROUP_FIELDS = """
  id
  name
  system
  emLevel
  users(first: 50) { totalCount nodes { id userName fullName } }
  roles(first: 25) { totalCount nodes { id name } }
"""

_Q_USER_GROUPS = f"""
query Q($after: String, $first: Int) {{
  userGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_USER_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_ARCHIVED_USER_GROUPS = f"""
query Q($after: String, $first: Int) {{
  archivedUserGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_USER_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_USER_GROUP = f"""
query Q($id: ID!) {{
  userGroup(id: $id) {{
{_USER_GROUP_FIELDS}
  }}
}}
"""

_Q_EM_USER_GROUPS = f"""
query Q($after: String, $first: Int) {{
  emUserGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_EM_USER_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_EM_ARCHIVED_USER_GROUPS = f"""
query Q($after: String, $first: Int) {{
  emArchivedUserGroups(after: $after, first: $first) {{
    totalCount
    pageInfo {{ endCursor hasNextPage }}
    nodes {{
{_EM_USER_GROUP_FIELDS}
    }}
  }}
}}
"""

_Q_EM_USER_GROUP = f"""
query Q($id: ID!) {{
  emUserGroup(id: $id) {{
{_EM_USER_GROUP_FIELDS}
  }}
}}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cidr_to_range(cidr: str) -> tuple[str, str]:
    """Expand "10.2.9.0/24" to ("10.2.9.0", "10.2.9.255").

    Used to translate the natural CIDR shorthand operators reach for
    into Tenable's IpRange (startIp / endIp) input shape.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"invalid CIDR {cidr!r}: {e}") from e
    return str(net.network_address), str(net.broadcast_address)


def _project_asset_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten the AssetGroup interface + its subtype-specific fields into
    a shape comfortable for an LLM to reason about."""
    if not node:
        return {}
    out: dict[str, Any] = {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "key": node.get("key"),
        "display_tag": node.get("displayTag"),
        "is_static_type": node.get("isStaticType"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
    }
    # Subtype-specific projections (typed-fragment fields):
    if node.get("description") is not None:
        out["description"] = node.get("description")
    if node.get("vlan") is not None:
        out["vlan"] = node.get("vlan")
    if node.get("filter") is not None:
        out["filter"] = node.get("filter")
    if node.get("assetType") is not None:
        out["asset_type"] = node.get("assetType")
        out["family"] = node.get("family")
    if node.get("assets") is not None:
        assets = node["assets"] or {}
        out["assets_total"] = assets.get("totalCount")
        out["assets_sample"] = [
            {"id": a.get("id"), "name": a.get("name")} for a in unwrap_nodes(assets)
        ]
    if node.get("ips") is not None:
        ips = node["ips"] or {}
        out["ips_total"] = ips.get("totalCount")
        out["ips"] = unwrap_nodes(ips)
    if node.get("startIp") is not None:
        out["start_ip"] = node.get("startIp")
        out["end_ip"] = node.get("endIp")
    return out


_SCHEDULE_DAY_VALUES = [
    "sunday",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "every_day",
    "weekdays",
]

_SCHEDULE_DAY_TO_TENABLE = {
    "sunday": "Sunday",
    "monday": "Monday",
    "tuesday": "Tuesday",
    "wednesday": "Wednesday",
    "thursday": "Thursday",
    "friday": "Friday",
    "saturday": "Saturday",
    "every_day": "EveryDay",
    "weekdays": "MondayToFriday",
}


def _to_schedule_day(natural: str) -> str:
    """Translate "monday" / "weekdays" / "every_day" / etc. to Tenable's
    RecurringScheduleType enum value."""
    v = (natural or "").strip().lower().replace(" ", "_")
    if v not in _SCHEDULE_DAY_TO_TENABLE:
        raise ValueError(f"day must be one of {_SCHEDULE_DAY_VALUES}; got {natural!r}")
    return _SCHEDULE_DAY_TO_TENABLE[v]


def _project_schedule_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten a ScheduleGroup, surfacing subtype-specific fields:
    one-shot windows (TimeInterval) expose `start_time`/`end_time`;
    recurring (RecurringGroup) exposes `schedules`."""
    if not node:
        return {}
    out: dict[str, Any] = {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "key": node.get("key"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
    }
    if node.get("start") is not None:
        out["start_time"] = node.get("start")
        out["end_time"] = node.get("end")
    if node.get("schedules") is not None:
        scheds = node["schedules"] or {}
        out["schedules_total"] = scheds.get("totalCount")
        out["schedules"] = [
            {"day": s.get("type"), "start": s.get("start"), "end": s.get("end")}
            for s in unwrap_nodes(scheds)
        ]
    return out


def _project_tag_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten a TagGroup with its tag-item list (capped at 100 per page)."""
    if not node:
        return {}
    items = node.get("items") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "tag_type": node.get("tagType"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "key": node.get("key"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
        "items_total": items.get("totalCount"),
        "items": [
            {
                "tag_id": it.get("tagId"),
                "tag_type": it.get("tagType"),
                "asset": (
                    {
                        "id": (it.get("asset") or {}).get("id"),
                        "name": (it.get("asset") or {}).get("name"),
                    }
                    if it.get("asset")
                    else None
                ),
            }
            for it in unwrap_nodes(items)
        ],
    }


def _project_rule_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten a RuleGroup with a preview of its included rules."""
    if not node:
        return {}
    items = node.get("items") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "key": node.get("key"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
        "items_count": node.get("itemsCount"),
        "items_preview": [
            {
                "sid": r.get("sid"),
                "rev": r.get("rev"),
                "protocol": r.get("protocol"),
                "msg": r.get("msg"),
                "category": r.get("category"),
                "enabled": r.get("enabled"),
            }
            for r in unwrap_nodes(items)
        ],
    }


def _project_port_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten a PortGroup with its port-range items (capped at 100)."""
    if not node:
        return {}
    items = node.get("items") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "key": node.get("key"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
        "items_total": items.get("totalCount"),
        "items": [
            {"start_port": i.get("startPort"), "end_port": i.get("endPort")}
            for i in unwrap_nodes(items)
        ],
    }


def _project_protocol_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten a ProtocolGroup with its (protocol, port-range) items."""
    if not node:
        return {}
    items = node.get("items") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "archived": node.get("archived"),
        "system": node.get("system"),
        "key": node.get("key"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
        "items_total": items.get("totalCount"),
        "items": [
            {
                "protocol": i.get("protocol"),
                "start_port": i.get("startPort"),
                "end_port": i.get("endPort"),
            }
            for i in unwrap_nodes(items)
        ],
    }


def _project_user_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten a UserGroup with member users (sample) and assigned roles."""
    if not node:
        return {}
    users = node.get("users") or {}
    roles = node.get("roles") or {}
    out = {
        "id": node.get("id"),
        "name": node.get("name"),
        "system": node.get("system"),
        "users_total": users.get("totalCount"),
        "users_sample": [
            {
                "id": u.get("id"),
                "username": u.get("userName"),
                "full_name": u.get("fullName"),
            }
            for u in unwrap_nodes(users)
        ],
        "roles_total": roles.get("totalCount"),
        "roles": [{"id": r.get("id"), "name": r.get("name")} for r in unwrap_nodes(roles)],
    }
    if node.get("emLevel") is not None:
        out["em_level"] = node.get("emLevel")
    return out


def _project_email_group(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten an EmailGroup node into a recipient + SMTP-server summary."""
    if not node:
        return {}
    server = node.get("server") or {}
    recipients = node.get("recipients") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "last_modified_date": node.get("lastModifiedDate"),
        "last_modified_by": node.get("lastModifiedBy"),
        "recipients_total": recipients.get("totalCount"),
        "recipients": unwrap_nodes(recipients),
        "smtp_server": {
            "id": server.get("id"),
            "name": server.get("name"),
            "host": server.get("smtpServer"),
            "port": server.get("smtpPort"),
            "user": server.get("smtpUser"),
            "sender": server.get("sender"),
            "archived": server.get("archived"),
        }
        if server
        else None,
    }


def _normalize_protocol_item(item: dict[str, Any]) -> dict[str, Any]:
    """Translate a user-supplied {protocol, start_port?, end_port?} into
    Tenable's ProtocolListItemParams shape (camelCase keys, validates
    presence of `protocol`)."""
    proto = item.get("protocol")
    if not proto:
        raise ValueError("each protocol item requires `protocol`")
    out: dict[str, Any] = {"protocol": proto}
    if item.get("start_port") is not None:
        out["startPort"] = int(item["start_port"])
    if item.get("end_port") is not None:
        out["endPort"] = int(item["end_port"])
    return out


def _normalize_providers_mapping(
    mapping: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    """Translate a user-supplied [{provider_id, external_groups}] into
    Tenable's GroupProviderParams shape."""
    if not mapping:
        return None
    out = []
    for m in mapping:
        provider_id = m.get("provider_id")
        external_groups = m.get("external_groups")
        if not provider_id:
            raise ValueError("each providers_mapping entry requires `provider_id`")
        if not external_groups:
            raise ValueError("each providers_mapping entry requires `external_groups`")
        out.append(
            {
                "providerId": provider_id,
                "externalGroups": list(external_groups),
            }
        )
    return out


# Lazy import to avoid a circular dep with writes.py during initial
# module load. _execute_write is the shared dry-run / audit gateway.
def _ew():
    from .writes import _execute_write

    return _execute_write


# ===========================================================================
# Registration — read tools
# ===========================================================================


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register every group-surface READ tool."""

    @mcp.tool(
        title="List asset groups (active)",
        description=(
            "Page through every active (non-archived) asset group in the "
            "deployment. Each entry includes its membership shape — IP "
            "list, IP range, asset-id list, filter expression, etc. — "
            "and whether it surfaces as a UI tag (`display_tag`). Use "
            "this before creating to avoid duplicating an existing group."
        ),
    )
    async def list_asset_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ASSET_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("assetGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_asset_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived asset groups",
        description=(
            "Page through archived asset groups — those that were "
            "soft-deleted via `archive_asset_group`. Group definitions "
            "and historical membership are preserved by Tenable; they "
            "just stop appearing in active views."
        ),
    )
    async def list_archived_asset_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ARCHIVED_ASSET_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("archivedAssetGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_asset_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get an asset group by id",
        description=(
            "Fetch one asset group's full record by its id. The shape "
            "varies by group subtype: an `AssetList` returns an "
            "`assets_sample` preview, an `IpRange` returns `start_ip` / "
            "`end_ip`, a `FilterGroup` returns its `filter` expression, "
            "and so on."
        ),
    )
    async def get_asset_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_ASSET_GROUP, variables={"id": group_id})
        return _project_asset_group(data.get("assetGroup") or {})

    # ------------------------------------------------------------------
    # Email groups — recipient lists for policy-action notifications
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List email groups",
        description=(
            "Page through every email group in the deployment. Each "
            "entry includes its recipients, the SMTP server it routes "
            "through, and last-modified metadata. Email groups are "
            "referenced by detection policies' actions to send alert "
            "emails."
        ),
    )
    async def list_email_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_EMAIL_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("emailGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_email_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get an email group by id",
        description=(
            "Fetch one email group with its recipient list and bound SMTP server details."
        ),
    )
    async def get_email_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_EMAIL_GROUP, variables={"id": group_id})
        return _project_email_group(data.get("emailGroup") or {})

    @mcp.tool(
        title="Find email groups that route through a given SMTP server",
        description=(
            "Given an SMTP-server id, return the email groups bound to "
            "it. Useful before retiring an SMTP server: any group "
            "returned here will lose its delivery path if the server is "
            "removed."
        ),
    )
    async def find_email_groups_using_smtp_server(
        smtp_server_id: str,
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        if not smtp_server_id:
            raise ValueError("smtp_server_id is required")
        data = await client.query(
            _Q_USED_IN_EMAIL_GROUPS,
            variables={
                "id": smtp_server_id,
                "first": clamp_page_size(limit),
                "after": after_cursor,
            },
        )
        conn = data.get("usedInEmailGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_email_group(n) for n in nodes],
        }

    # ------------------------------------------------------------------
    # Schedule groups — maintenance windows / business hours
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List schedule groups",
        description=(
            "Page through every active schedule group. Each entry "
            "surfaces its kind (one-shot TimeInterval, weekly "
            "RecurringGroup, or system ScheduleFunction) and the "
            "windows it defines. Every policy mutation's `schedule` "
            "argument resolves against one of these."
        ),
    )
    async def list_schedule_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_SCHEDULE_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("scheduleGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_schedule_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived schedule groups",
        description="Soft-deleted schedule groups, paginated.",
    )
    async def list_archived_schedule_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ARCHIVED_SCHEDULE_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("archivedScheduleGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_schedule_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a schedule group by id",
        description=(
            "Fetch one schedule group. Shape varies by kind: "
            "`TimeInterval` returns `start_time`/`end_time`; "
            "`RecurringGroup` returns a list of weekly windows under "
            "`schedules`."
        ),
    )
    async def get_schedule_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_SCHEDULE_GROUP, variables={"id": group_id})
        return _project_schedule_group(data.get("scheduleGroup") or {})

    # ------------------------------------------------------------------
    # Tag groups — PLC controller-tag rollups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List tag groups",
        description=(
            "Page through every tag group. Tag groups bundle "
            "controller tags (by asset id + tag id) so a "
            "TagValuePolicy can fire against all members. `tag_type` "
            "indicates the scalar type Tenable evaluates the tag "
            "values as."
        ),
    )
    async def list_tag_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_TAG_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("tagGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_tag_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a tag group by id",
        description="One tag group with up to 100 member items.",
    )
    async def get_tag_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_TAG_GROUP, variables={"id": group_id})
        return _project_tag_group(data.get("tagGroup") or {})

    @mcp.tool(
        title="Discover tags eligible for a tag group",
        description=(
            "List controller tags that could be added to a tag group. "
            "Filterable by asset (`asset_id`) and tag-value type "
            "(`tag_type`: one of Unknown, Int, Bool, Short, DInt, "
            "Long, Float, MultipleTagTypes). Use this before "
            "`create_tag_group` to discover what's available without "
            "guessing tag ids."
        ),
    )
    async def list_eligible_tags(
        asset_id: str | None = None,
        tag_type: str | None = None,
        limit: int = 100,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        if tag_type is not None and tag_type not in _TAG_TYPE_VALUES:
            raise ValueError(f"tag_type must be one of {_TAG_TYPE_VALUES}; got {tag_type!r}")
        data = await client.query(
            _Q_TAGS_FOR_TAG_GROUP,
            variables={
                "asset": asset_id,
                "type": tag_type,
                "first": clamp_page_size(limit, default=100, maximum=500),
                "after": after_cursor,
            },
        )
        conn = data.get("tagsForTagGroup") or {}
        nodes = unwrap_nodes(conn)
        out = []
        for n in nodes:
            asset = n.get("asset") or {}
            tags_conn = n.get("tags") or {}
            out.append(
                {
                    "asset": {"id": asset.get("id"), "name": asset.get("name")},
                    "tags_total": tags_conn.get("totalCount"),
                    "tags": [
                        {
                            "id": t.get("id"),
                            "name": t.get("name"),
                            "type": t.get("type"),
                            "address": t.get("address"),
                        }
                        for t in unwrap_nodes(tags_conn)
                    ],
                }
            )
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "asset_tags": out,
        }

    # ------------------------------------------------------------------
    # Rule groups — IDS rule bundles
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List rule groups",
        description=(
            "Page through every active rule group. A rule group is a "
            "bundle of IDS rule SIDs referenced by IntrusionPolicy. "
            "Each entry includes a preview of up to 25 included rules."
        ),
    )
    async def list_rule_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_RULE_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("ruleGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_rule_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived rule groups",
        description="Soft-deleted rule groups, paginated.",
    )
    async def list_archived_rule_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ARCHIVED_RULE_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("archivedRuleGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_rule_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a rule group by id",
        description="One rule group with the first 25 included rules.",
    )
    async def get_rule_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_RULE_GROUP, variables={"id": group_id})
        return _project_rule_group(data.get("ruleGroup") or {})

    # ------------------------------------------------------------------
    # Port groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List port groups",
        description=(
            "Page through every active port group. Port groups are "
            "reusable port-range bundles consumed by PortPolicy "
            "definitions."
        ),
    )
    async def list_port_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_PORT_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("portGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_port_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived port groups",
        description="Soft-deleted port groups, paginated.",
    )
    async def list_archived_port_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ARCHIVED_PORT_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("archivedPortGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_port_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a port group by id",
        description="One port group with up to 100 of its port-range items.",
    )
    async def get_port_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_PORT_GROUP, variables={"id": group_id})
        return _project_port_group(data.get("portGroup") or {})

    # ------------------------------------------------------------------
    # Protocol groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List protocol groups",
        description=(
            "Page through every active protocol group. Each item "
            "carries a protocol (TCP/UDP/MODBUS/S7/IEC104/DNP3/etc.) "
            "and optional port range."
        ),
    )
    async def list_protocol_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_PROTOCOL_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("protocolGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_protocol_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived protocol groups",
        description="Soft-deleted protocol groups, paginated.",
    )
    async def list_archived_protocol_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ARCHIVED_PROTOCOL_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("archivedProtocolGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_protocol_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a protocol group by id",
        description="One protocol group with up to 100 of its items.",
    )
    async def get_protocol_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_PROTOCOL_GROUP, variables={"id": group_id})
        return _project_protocol_group(data.get("protocolGroup") or {})

    # ------------------------------------------------------------------
    # User groups (ICP-level) and EmUserGroup (Enterprise Manager)
    # ------------------------------------------------------------------

    @mcp.tool(
        title="List user groups (ICP-level)",
        description=(
            "Page through every active user group at the ICP level. "
            "Each entry exposes its assigned roles and a sample of "
            "member users."
        ),
    )
    async def list_user_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_USER_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("userGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_user_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived user groups (ICP-level)",
        description="Soft-deleted user groups at the ICP level.",
    )
    async def list_archived_user_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_ARCHIVED_USER_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("archivedUserGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_user_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a user group by id (ICP-level)",
        description="One ICP-level user group with its roles and member preview.",
    )
    async def get_user_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_USER_GROUP, variables={"id": group_id})
        return _project_user_group(data.get("userGroup") or {})

    @mcp.tool(
        title="List user groups (Enterprise Manager level)",
        description=(
            "Page through every active EM-level user group. Each entry "
            "exposes `em_level` (whether the group is EM-only) plus "
            "roles and member preview."
        ),
    )
    async def list_em_user_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_EM_USER_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("emUserGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_user_group(n) for n in nodes],
        }

    @mcp.tool(
        title="List archived user groups (Enterprise Manager level)",
        description="Soft-deleted EM-level user groups.",
    )
    async def list_em_archived_user_groups(
        limit: int = 50,
        after_cursor: str | None = None,
    ) -> dict[str, Any]:
        data = await client.query(
            _Q_EM_ARCHIVED_USER_GROUPS,
            variables={"first": clamp_page_size(limit), "after": after_cursor},
        )
        conn = data.get("emArchivedUserGroups") or {}
        nodes = unwrap_nodes(conn)
        return {
            "total": conn.get("totalCount"),
            "count": len(nodes),
            "page_info": conn.get("pageInfo"),
            "groups": [_project_user_group(n) for n in nodes],
        }

    @mcp.tool(
        title="Get a user group by id (Enterprise Manager level)",
        description="One EM-level user group with its roles and member preview.",
    )
    async def get_em_user_group(group_id: str) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        data = await client.query(_Q_EM_USER_GROUP, variables={"id": group_id})
        return _project_user_group(data.get("emUserGroup") or {})


# ===========================================================================
# Registration — write tools
# ===========================================================================


def register_write_tools(mcp: Any, client: TenableClient, audit: AuditLog) -> None:
    """Register every group-surface WRITE tool. Gated by `write_tools_enabled`."""
    execute_write = _ew()

    # ------------------------------------------------------------------
    # Asset groups — the polymorphic AssetGroup surface
    # ------------------------------------------------------------------

    def _resolve_asset_group_shape(
        asset_ids: list[str] | None,
        ips: list[str] | None,
        cidr: str | None,
        start_ip: str | None,
        end_ip: str | None,
        asset_type: str | None,
        family: str | None,
        vlan: str | None,
        filter_: dict[str, Any] | None,
    ) -> tuple[str, dict[str, Any]]:
        """Pick the AssetGroupType enum + variables payload from whichever
        membership shape the caller specified. Validates that exactly one
        membership shape is provided.
        """
        shapes: list[str] = []
        if asset_ids:
            shapes.append("asset_ids")
        if ips:
            shapes.append("ips")
        if cidr or start_ip or end_ip:
            shapes.append("ip_range")
        if asset_type or family:
            shapes.append("type_family")
        if vlan:
            shapes.append("vlan")
        if filter_ is not None:
            shapes.append("filter")
        if len(shapes) > 1:
            raise ValueError(f"provide only one membership shape; got {shapes}")

        payload: dict[str, Any] = {}
        if asset_ids:
            payload["assetsIds"] = asset_ids
            return "AssetList", payload
        if ips:
            payload["ips"] = ips
            return "IpList", payload
        if cidr:
            s, e = _cidr_to_range(cidr)
            payload["startIp"] = s
            payload["endIp"] = e
            return "IpRange", payload
        if start_ip and end_ip:
            payload["startIp"] = start_ip
            payload["endIp"] = end_ip
            return "IpRange", payload
        if asset_type or family:
            if not (asset_type and family):
                raise ValueError("type_family group requires BOTH asset_type and family")
            payload["assetType"] = asset_type
            payload["family"] = family
            return "TypeFamily", payload
        if vlan:
            payload["vlan"] = vlan
            return "Segment", payload
        if filter_ is not None:
            payload["filter"] = filter_
            return "Filter", payload
        # No membership specified — default to an empty Filter the AI can
        # populate later via update_asset_group.
        return "Filter", payload

    @mcp.tool(
        title="Create an asset group (tag-like grouping)",
        description=(
            "Create a new Tenable OT asset group. Pass "
            "`display_tag=true` to surface it as a UI tag (vs. a hidden "
            "policy filter group).\n\n"
            "Pick exactly ONE membership shape:\n"
            "  • `asset_ids`: explicit list of asset ids → AssetList\n"
            "  • `ips`: list of IP addresses → IpList\n"
            "  • `cidr`: CIDR shorthand (e.g. '10.2.9.0/24') → IpRange\n"
            "  • `start_ip` + `end_ip`: explicit range → IpRange\n"
            "  • `asset_type` + `family`: Tenable AssetType + family "
            "string → TypeFamily\n"
            "  • `vlan`: a VLAN identifier → Segment\n"
            "  • `filter`: raw AssetGroupExpressionsParams expression → "
            "Filter\n"
            "If none are given, defaults to an empty Filter group the AI "
            "can populate later.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_asset_group(
        name: str,
        asset_ids: list[str] | None = None,
        ips: list[str] | None = None,
        cidr: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        asset_type: str | None = None,
        family: str | None = None,
        vlan: str | None = None,
        filter: dict[str, Any] | None = None,
        description: str | None = None,
        display_tag: bool = True,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        group_type, shape_vars = _resolve_asset_group_shape(
            asset_ids,
            ips,
            cidr,
            start_ip,
            end_ip,
            asset_type,
            family,
            vlan,
            filter,
        )
        variables: dict[str, Any] = {
            "name": name,
            "type": group_type,
            "description": description,
            "displayTag": display_tag,
        }
        variables.update(shape_vars)
        return await execute_write(
            client,
            audit,
            "create_asset_group",
            _M_NEW_ASSET_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Update an asset group's metadata or membership",
        description=(
            "Modify an existing asset group: rename, change description, "
            "change display-tag flag, or replace the membership list. "
            "Same membership shapes as `create_asset_group` — pick "
            "exactly one.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_asset_group(
        group_id: str,
        name: str,
        asset_ids: list[str] | None = None,
        ips: list[str] | None = None,
        cidr: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        asset_type: str | None = None,
        family: str | None = None,
        vlan: str | None = None,
        filter: dict[str, Any] | None = None,
        description: str | None = None,
        display_tag: bool = True,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        group_type, shape_vars = _resolve_asset_group_shape(
            asset_ids,
            ips,
            cidr,
            start_ip,
            end_ip,
            asset_type,
            family,
            vlan,
            filter,
        )
        variables: dict[str, Any] = {
            "id": group_id,
            "name": name,
            "type": group_type,
            "description": description,
            "displayTag": display_tag,
        }
        variables.update(shape_vars)
        return await execute_write(
            client,
            audit,
            "update_asset_group",
            _M_SET_ASSET_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Archive (soft-delete) an asset group",
        description=(
            "Archive an asset group. Membership and history are "
            "preserved by Tenable's archive semantics; the group stops "
            "appearing in active views and can be inspected via "
            "`list_archived_asset_groups`.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def archive_asset_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_asset_group",
            _M_ARCHIVE_ASSET_GROUP,
            {"id": group_id},
            dry_run,
        )

    @mcp.tool(
        title="Bulk toggle display-tag flag on asset groups",
        description=(
            "Turn the UI-tag flag on or off for several asset groups in "
            "one call. `status=true` surfaces them as tags; `status=false` "
            "hides them (they continue to function as policy filter "
            "groups, just not visible as UI tags).\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def bulk_set_asset_group_display_tag(
        group_ids: list[str],
        status: bool,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_ids:
            raise ValueError("group_ids is required and must be non-empty")
        return await execute_write(
            client,
            audit,
            "bulk_set_asset_group_display_tag",
            _M_BULK_SET_DISPLAY_TAG,
            {"ids": group_ids, "status": bool(status)},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Email groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create an email group (alert recipient list)",
        description=(
            "Create a named recipient list bound to one SMTP server. "
            "Detection policies reference the resulting group id in "
            "their action configuration to route alert emails. The "
            "`smtp_server_id` must be an existing configured SMTP "
            "server; this tool does not create SMTP servers.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_email_group(
        name: str,
        smtp_server_id: str,
        recipients: list[str],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        if not smtp_server_id:
            raise ValueError("smtp_server_id is required")
        if not recipients:
            raise ValueError("recipients must be non-empty")
        return await execute_write(
            client,
            audit,
            "create_email_group",
            _M_NEW_EMAIL_GROUP,
            {"name": name, "server": smtp_server_id, "recipients": recipients},
            dry_run,
        )

    @mcp.tool(
        title="Update an email group (rename, change SMTP server, or replace recipients)",
        description=(
            "Replace the email group's name, SMTP server, and recipient "
            "list in one call. Note: `recipients` is a *full replacement* "
            "— pass the complete intended list, not a delta.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_email_group(
        group_id: str,
        name: str,
        smtp_server_id: str,
        recipients: list[str],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name or not smtp_server_id:
            raise ValueError("group_id, name, and smtp_server_id are required")
        if not recipients:
            raise ValueError("recipients must be non-empty")
        return await execute_write(
            client,
            audit,
            "update_email_group",
            _M_SET_EMAIL_GROUP,
            {
                "id": group_id,
                "name": name,
                "server": smtp_server_id,
                "recipients": recipients,
            },
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) an email group",
        description=(
            "Archive an email group. Any policy action still pointing "
            "at the archived group will silently fail to deliver — "
            "audit `find_email_groups_using_smtp_server` and the "
            "policy list first.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def archive_email_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_email_group",
            _M_ARCHIVE_EMAIL_GROUP,
            {"id": group_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Schedule groups
    # ------------------------------------------------------------------

    def _build_schedule_payload(
        start_time: str | None,
        end_time: str | None,
        schedules: list[dict[str, Any]] | None,
    ) -> tuple[str, dict[str, Any]]:
        """Decide ScheduleGroup kind from the inputs supplied and return
        (kind, mutation-variables-fragment). One-shot windows produce an
        IntervalGroup, weekly schedules produce a RecurringGroup,
        nothing produces a Function."""
        has_interval = bool(start_time and end_time)
        has_recurring = bool(schedules)
        if has_interval and has_recurring:
            raise ValueError(
                "provide either (start_time, end_time) for a one-shot "
                "window OR `schedules` for a weekly recurring group — "
                "not both"
            )
        if has_interval:
            return "IntervalGroup", {"start": start_time, "end": end_time}
        if has_recurring:
            normalized = [
                {
                    "type": _to_schedule_day(s.get("day", "")),
                    "start": s["start"],
                    "end": s["end"],
                }
                for s in schedules
            ]
            return "RecurringGroup", {"schedules": normalized}
        return "Function", {}

    @mcp.tool(
        title="Create a schedule group (policy window)",
        description=(
            "Create a schedule group that policies reference via their "
            "`schedule` argument. Pick exactly ONE shape:\n"
            "  • `start_time` + `end_time`: a one-shot window → "
            "IntervalGroup\n"
            "  • `schedules`: weekly recurring windows → "
            "RecurringGroup. Each entry: "
            "{day: monday|tuesday|...|weekdays|every_day, "
            "start: HH:MM:SS, end: HH:MM:SS}\n"
            "  • neither: a system Function group placeholder\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_schedule_group(
        name: str,
        start_time: str | None = None,
        end_time: str | None = None,
        schedules: list[dict[str, Any]] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        kind, shape_vars = _build_schedule_payload(start_time, end_time, schedules)
        variables: dict[str, Any] = {"name": name, "type": kind}
        variables.update(shape_vars)
        return await execute_write(
            client,
            audit,
            "create_schedule_group",
            _M_NEW_SCHEDULE_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Update a schedule group",
        description=(
            "Rename or replace the windows of an existing schedule "
            "group. Same shape rules as `create_schedule_group`.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_schedule_group(
        group_id: str,
        name: str,
        start_time: str | None = None,
        end_time: str | None = None,
        schedules: list[dict[str, Any]] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        kind, shape_vars = _build_schedule_payload(start_time, end_time, schedules)
        variables: dict[str, Any] = {"id": group_id, "name": name, "type": kind}
        variables.update(shape_vars)
        return await execute_write(
            client,
            audit,
            "update_schedule_group",
            _M_SET_SCHEDULE_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a schedule group",
        description=(
            "Archive a schedule group. Policies still pointing at it "
            "will lose their window definition — audit first.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def archive_schedule_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_schedule_group",
            _M_ARCHIVE_SCHEDULE_GROUP,
            {"id": group_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Tag groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a tag group (PLC controller-tag rollup)",
        description=(
            "Create a tag group bundling controller tags for use by a "
            "TagValuePolicy. `items` is a list of "
            "{asset_id, tag_id, tag_type} entries — `tag_type` per "
            'item is the value type string ("Int", "Bool", '
            '"Float", etc.). The top-level `tag_type` enum '
            "constrains the group's expected scalar type at "
            "evaluation; valid values: Unknown, Int, Bool, Short, "
            "DInt, Long, Float, MultipleTagTypes. Use "
            "`list_eligible_tags` to discover available tags before "
            "calling this.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def create_tag_group(
        name: str,
        items: list[dict[str, Any]],
        tag_type: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        if not items:
            raise ValueError("items must be non-empty")
        if tag_type not in _TAG_TYPE_VALUES:
            raise ValueError(f"tag_type must be one of {_TAG_TYPE_VALUES}; got {tag_type!r}")
        normalized = [
            {
                "assetId": it["asset_id"],
                "tagId": it["tag_id"],
                "tagType": it["tag_type"],
            }
            for it in items
        ]
        return await execute_write(
            client,
            audit,
            "create_tag_group",
            _M_NEW_TAG_GROUP,
            {"name": name, "items": normalized, "tagType": tag_type},
            dry_run,
        )

    @mcp.tool(
        title="Update a tag group",
        description=(
            "Rename or replace the member items of an existing tag "
            "group. `items` is a full replacement (not a delta).\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_tag_group(
        group_id: str,
        name: str,
        items: list[dict[str, Any]],
        tag_type: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        if not items:
            raise ValueError("items must be non-empty")
        if tag_type not in _TAG_TYPE_VALUES:
            raise ValueError(f"tag_type must be one of {_TAG_TYPE_VALUES}; got {tag_type!r}")
        normalized = [
            {
                "assetId": it["asset_id"],
                "tagId": it["tag_id"],
                "tagType": it["tag_type"],
            }
            for it in items
        ]
        return await execute_write(
            client,
            audit,
            "update_tag_group",
            _M_SET_TAG_GROUP,
            {
                "id": group_id,
                "name": name,
                "items": normalized,
                "tagType": tag_type,
            },
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a tag group",
        description=(
            "Archive a tag group. Tag-value policies referencing it "
            "will lose their member list — audit first.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def archive_tag_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_tag_group",
            _M_ARCHIVE_TAG_GROUP,
            {"id": group_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Rule groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a rule group (IDS rule bundle)",
        description=(
            "Create a rule group containing the IDS rule SIDs supplied "
            "in `rule_sids`. IntrusionPolicy references the resulting "
            "rule-group id via its `ruleGroup` argument. SIDs are sent "
            "as floats (Tenable's schema convention).\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_rule_group(
        name: str,
        rule_sids: list[float],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        if not rule_sids:
            raise ValueError("rule_sids must be non-empty")
        items = [float(s) for s in rule_sids]
        return await execute_write(
            client,
            audit,
            "create_rule_group",
            _M_NEW_RULE_GROUP,
            {"name": name, "items": items},
            dry_run,
        )

    @mcp.tool(
        title="Update a rule group",
        description=(
            "Rename or replace the SID list of a rule group. "
            "`rule_sids` is a full replacement.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_rule_group(
        group_id: str,
        name: str,
        rule_sids: list[float],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        if not rule_sids:
            raise ValueError("rule_sids must be non-empty")
        items = [float(s) for s in rule_sids]
        return await execute_write(
            client,
            audit,
            "update_rule_group",
            _M_SET_RULE_GROUP,
            {"id": group_id, "name": name, "items": items},
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a rule group",
        description=(
            "Archive a rule group. IntrusionPolicies referencing it "
            "will lose their rule definition — audit first.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def archive_rule_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_rule_group",
            _M_ARCHIVE_RULE_GROUP,
            {"id": group_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Port groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a port group (port-range bundle for PortPolicy)",
        description=(
            "Create a port group from a list of "
            "{start_port, end_port} ranges. PortPolicy mutations "
            "reference the resulting id via their `portGroup` arg.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_port_group(
        name: str,
        items: list[dict[str, int]],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        if not items:
            raise ValueError("items must be non-empty")
        normalized = [
            {"startPort": int(i["start_port"]), "endPort": int(i["end_port"])} for i in items
        ]
        return await execute_write(
            client,
            audit,
            "create_port_group",
            _M_NEW_PORT_GROUP,
            {"name": name, "items": normalized},
            dry_run,
        )

    @mcp.tool(
        title="Update a port group",
        description=(
            "Rename or replace the port-range items of a port group. "
            "`items` is a full replacement.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_port_group(
        group_id: str,
        name: str,
        items: list[dict[str, int]],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        if not items:
            raise ValueError("items must be non-empty")
        normalized = [
            {"startPort": int(i["start_port"]), "endPort": int(i["end_port"])} for i in items
        ]
        return await execute_write(
            client,
            audit,
            "update_port_group",
            _M_SET_PORT_GROUP,
            {"id": group_id, "name": name, "items": normalized},
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a port group",
        description=(
            "Archive a port group. PortPolicies referencing it will "
            "lose their port definition — audit first.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def archive_port_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_port_group",
            _M_ARCHIVE_PORT_GROUP,
            {"id": group_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # Protocol groups
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a protocol group (protocol+port-range bundle)",
        description=(
            "Create a protocol group. Each item is "
            "{protocol, start_port?, end_port?}. `protocol` must be a "
            "Tenable ProtocolSuperType enum value — TCP, UDP, MODBUS, "
            "S7, IEC104, DNP3, PROFINET, CIP, ETHIP, IEC61850, etc. "
            "Port range is required for some protocols (TCP/UDP) and "
            "ignored for others.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_protocol_group(
        name: str,
        items: list[dict[str, Any]],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        if not items:
            raise ValueError("items must be non-empty")
        normalized = [_normalize_protocol_item(i) for i in items]
        return await execute_write(
            client,
            audit,
            "create_protocol_group",
            _M_NEW_PROTOCOL_GROUP,
            {"name": name, "items": normalized},
            dry_run,
        )

    @mcp.tool(
        title="Update a protocol group",
        description=(
            "Rename or replace the items of a protocol group. `items` "
            "is a full replacement.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def update_protocol_group(
        group_id: str,
        name: str,
        items: list[dict[str, Any]],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        if not items:
            raise ValueError("items must be non-empty")
        normalized = [_normalize_protocol_item(i) for i in items]
        return await execute_write(
            client,
            audit,
            "update_protocol_group",
            _M_SET_PROTOCOL_GROUP,
            {"id": group_id, "name": name, "items": normalized},
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a protocol group",
        description=(
            "Archive a protocol group. ProtocolPolicies referencing "
            "it will lose their protocol definition — audit first.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def archive_protocol_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_protocol_group",
            _M_ARCHIVE_PROTOCOL_GROUP,
            {"id": group_id},
            dry_run,
        )

    # ------------------------------------------------------------------
    # User groups (ICP-level)
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a user group (ICP-level)",
        description=(
            "Create a permission group at the ICP level. `role_ids` "
            "attach roles to the group; `user_ids` populate initial "
            "members; `zone_ids` restrict access by zone; "
            "`providers_mapping` binds external auth-provider groups "
            "to this Tenable group (each entry: {provider_id, "
            "external_groups: [strings]}); `em_icp_user_group_ids` "
            "links to EM-level groups when this ICP is paired to an "
            "EM. All are optional.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def create_user_group(
        name: str,
        role_ids: list[str] | None = None,
        user_ids: list[str] | None = None,
        zone_ids: list[str] | None = None,
        providers_mapping: list[dict[str, Any]] | None = None,
        em_icp_user_group_ids: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        variables = {
            "name": name,
            "roles": role_ids,
            "users": user_ids,
            "zones": zone_ids,
            "providersMapping": _normalize_providers_mapping(providers_mapping),
            "emIcpUserGroupIds": em_icp_user_group_ids,
        }
        return await execute_write(
            client,
            audit,
            "create_user_group",
            _M_NEW_USER_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Edit a user group (ICP-level)",
        description=(
            "Update an existing ICP-level user group's metadata or "
            "membership. All list args are full replacements (not "
            "deltas).\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def edit_user_group(
        group_id: str,
        name: str,
        role_ids: list[str] | None = None,
        user_ids: list[str] | None = None,
        zone_ids: list[str] | None = None,
        providers_mapping: list[dict[str, Any]] | None = None,
        em_icp_user_group_ids: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        variables = {
            "id": group_id,
            "name": name,
            "roles": role_ids,
            "users": user_ids,
            "zones": zone_ids,
            "providersMapping": _normalize_providers_mapping(providers_mapping),
            "emIcpUserGroupIds": em_icp_user_group_ids,
        }
        return await execute_write(
            client,
            audit,
            "edit_user_group",
            _M_EDIT_USER_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a user group (ICP-level)",
        description=(
            "Archive an ICP-level user group. Members lose group-"
            "assigned roles and zone access — audit before archiving."
            "\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def archive_user_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_user_group",
            _M_ARCHIVE_USER_GROUP,
            {"id": group_id},
            dry_run,
        )

    @mcp.tool(
        title="Reassign a user's group memberships (ICP-level)",
        description=(
            "Set the exact list of ICP-level user groups a user "
            "belongs to. `new_group_ids` is a full replacement — "
            "groups not in the list are removed, new ones are added.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def set_user_groups(
        username: str,
        new_group_ids: list[str],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not username:
            raise ValueError("username is required")
        return await execute_write(
            client,
            audit,
            "set_user_groups",
            _M_SET_USER_GROUPS,
            {"userName": username, "newGroups": new_group_ids},
            dry_run,
        )

    # ------------------------------------------------------------------
    # EM user groups (Enterprise Manager-level)
    # ------------------------------------------------------------------

    @mcp.tool(
        title="Create a user group (Enterprise Manager level)",
        description=(
            "Create a permission group at the EM level. Same args as "
            "`create_user_group` plus `em_level` (required Boolean: "
            "true = EM-only scope, false = ICP-visible via the EM/ICP "
            "pairing).\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def create_em_user_group(
        name: str,
        em_level: bool,
        role_ids: list[str] | None = None,
        user_ids: list[str] | None = None,
        zone_ids: list[str] | None = None,
        providers_mapping: list[dict[str, Any]] | None = None,
        em_icp_user_group_ids: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise ValueError("name is required")
        variables = {
            "name": name,
            "emLevel": bool(em_level),
            "roles": role_ids,
            "users": user_ids,
            "zones": zone_ids,
            "providersMapping": _normalize_providers_mapping(providers_mapping),
            "emIcpUserGroupIds": em_icp_user_group_ids,
        }
        return await execute_write(
            client,
            audit,
            "create_em_user_group",
            _M_NEW_EM_USER_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Edit a user group (Enterprise Manager level)",
        description=(
            "Update an existing EM-level user group. Note Tenable's "
            "editEmUserGroup mutation does not accept `em_level` — "
            "that flag is fixed at creation time.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def edit_em_user_group(
        group_id: str,
        name: str,
        role_ids: list[str] | None = None,
        user_ids: list[str] | None = None,
        zone_ids: list[str] | None = None,
        providers_mapping: list[dict[str, Any]] | None = None,
        em_icp_user_group_ids: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not group_id or not name:
            raise ValueError("group_id and name are required")
        variables = {
            "id": group_id,
            "name": name,
            "roles": role_ids,
            "users": user_ids,
            "zones": zone_ids,
            "providersMapping": _normalize_providers_mapping(providers_mapping),
            "emIcpUserGroupIds": em_icp_user_group_ids,
        }
        return await execute_write(
            client,
            audit,
            "edit_em_user_group",
            _M_EDIT_EM_USER_GROUP,
            variables,
            dry_run,
        )

    @mcp.tool(
        title="Archive (delete) a user group (Enterprise Manager level)",
        description=(
            "Archive an EM-level user group. Multi-site implications "
            "— check `list_em_user_groups` for membership before "
            "archiving.\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def archive_em_user_group(group_id: str, dry_run: bool = True) -> dict[str, Any]:
        if not group_id:
            raise ValueError("group_id is required")
        return await execute_write(
            client,
            audit,
            "archive_em_user_group",
            _M_ARCHIVE_EM_USER_GROUP,
            {"id": group_id},
            dry_run,
        )

    @mcp.tool(
        title="Reassign an EM user's group memberships",
        description=(
            "Set the exact list of EM-level user groups a user "
            "belongs to. Full replacement.\n\n"
            "WRITE. Defaults to dry_run."
        ),
    )
    async def set_em_user_groups(
        username: str,
        new_group_ids: list[str],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not username:
            raise ValueError("username is required")
        return await execute_write(
            client,
            audit,
            "set_em_user_groups",
            _M_SET_EM_USER_GROUPS,
            {"userName": username, "newGroups": new_group_ids},
            dry_run,
        )
