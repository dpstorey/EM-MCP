# Tool Catalog

The Tenable OT MCP Server exposes **114 tools across 11 categories**:
**48 read tools** always available, **66 write tools** that register
only when the operator enabled "Enable write tools" at setup time.

Every tool returns a JSON object the consuming AI walks via follow-up
calls. None of them precompute analyses — the server returns joined
relational data; interpretation is the consuming AI's job.

List and query tools return `total_count` — the exact number of records
matching the filter, independent of page size — alongside one page of
results. When `has_more` is true, pass the returned `end_cursor` back as
the `after` argument to fetch the next page, repeating until `has_more`
is false to walk the entire matched set.

Site-scoped reads accept `site_uuid` or `site_name`. Collection, search,
summary, and list tools additionally accept `site_uuids` for multi-site
fan-out. Their response contains one result block per site plus explicit
per-site errors; paginated searches accept `after_by_site`. Detail tools use
one site and return qualified references that retain the originating site.
Writes require exactly one explicit site and never accept `site_uuids`.

Every write tool defaults to `dry_run=True`. The first call returns
the planned mutation as JSON without sending it to Tenable OT. The
consuming AI surfaces the plan, awaits user approval, then calls
again with `dry_run=False`. Every call (preview or applied) is
recorded in `/data/audit.jsonl`.

---

## Read tools

### Asset domain

| Tool | One-line purpose |
|---|---|
| `query_assets` | Filter the asset inventory by natural OT vocabulary (`kind` like 'plc' / 'rtu' / 'switch', `category`, `criticality`, `purdue_level`, `vendor`, `name_contains`, exact CIDR `subnet`, `search`, `hidden`); returns identity, classification, IPs, segment membership, risk metrics, and custom-field values keyed by their operator-configured label. |
| `get_asset` | Full bundle for one asset by id: identity, classification, network interfaces, segments, custom fields (keyed by label), risk. |
| `get_asset_vulnerabilities` | Open vulnerabilities affecting one asset, with CVE list, CVSSv3, exploit availability, KEV / exploited-by-malware flags, age, vendor solution. |
| `list_custom_fields` | Return the asset custom-field schema: which of the 10 slots are configured, their operator-defined labels, and value type ('PlainText' / 'HyperLink'). Call before reading or writing custom fields to learn the tenant's vocabulary. |

### Vulnerability domain

| Tool | One-line purpose |
|---|---|
| `query_vulnerabilities` | Filter by CVE substring, severity floor, family, source. |
| `get_vulnerability` | One plugin by id with full affected-asset list joined. |

### Event domain

| Tool | One-line purpose |
|---|---|
| `query_events` | Filter detection events by `asset_id` / `severity_at_least` / `event_type` / `policy_id` / `since` / `until` / `resolved` / `src_ip` / `dst_ip`, newest first. `asset_id` traverses the asset's event connection; it is not a free-text search. |
| `get_event` | Full detail for one event by id. |

### Detection-policy domain

| Tool | One-line purpose |
|---|---|
| `list_detection_policies` | List configured detection policies with category, enabled flag, paused flag, level, fired-event counts (last 24h / 7d / 30d). |
| `query_policy_findings` | Per-asset findings (the rows of `policy × asset × hit-count`) filtered by policy / status / severity / time / MITRE technique / plugin id. |

### Network topology

| Tool | One-line purpose |
|---|---|
| `list_segments_and_zones` | Every configured segment (VLAN, subnet, asset-type filter) and zone — compliance evidence for IEC 62443 Zone & Conduit, NERC CIP ESP, NEI 08-09 defense-in-depth. |
| `get_communication_paths` | Observed L2 communication links involving one asset, with peer asset id, protocols, conversation count, last-seen — the graph adjacency the AI walks for attack-path reasoning. |

### Sensor health

| Tool | One-line purpose |
|---|---|
| `list_sensors` | Every Tenable OT sensor with status, connection / tunnel status, version, addressing, error state, and pending-update flags. Verifies visibility coverage before drawing conclusions from event data. |

### Correlation (relational projections, not analytics)

These tools return **joined relational data** the consuming AI walks
to reason about attack pathways, vulnerability clusters, temporal
patterns, and per-asset intelligence. The server does NOT compute the
analysis itself — no graph algorithms, no clustering, no LLM calls.

| Tool | One-line purpose |
|---|---|
| `query_attack_pathways` | Returns one asset's 1-hop comms neighborhood — the graph adjacency the AI walks. Call again on each peer's id to expand further. |
| `query_vulnerability_clusters` | Per-asset → vulnerabilities join across a list of assets, OR a global CVE-substring search returning each plugin's affected-asset list. |
| `query_temporal_patterns` | Events in a time window, oldest first, with classification, firing policy, and source/dest assets joined — the raw sequence the AI scans for motifs. |
| `get_asset_intelligence` | One asset's full bundle: core + open vulnerabilities + recent events + comms peers, in one call. |

### Summary

| Tool | One-line purpose |
|---|---|
| `summarize_environment` | One-shot snapshot: total counts and subtotals across assets (by criticality, hidden), events (resolved / unresolved), vulnerabilities (by severity), sensors, segments, zones, detection policies. |

### Active scans (read)

| Tool | One-line purpose |
|---|---|
| `list_active_scans` | All defined active-scan jobs with name, operation type, category, trigger, enabled flag, status, and target asset group. |
| `get_active_scan` | One active-scan definition by id. |
| `get_active_scan_executions` | Past execution records for one active scan: start/end time, elapsed time, status, who initiated, source, failure explanation. |

### Groups (read)

Eight first-class group concepts in Tenable OT, each with paginated
list + by-id lookup. Asset groups are polymorphic — the read tools
surface subtype-specific fields via typed fragments (IpRange returns
`start_ip`/`end_ip`, AssetList returns an asset sample, FilterGroup
returns its filter expression, SegmentGroup returns description/vlan,
AssetTypeFamilyGroup returns asset_type/family).

| Tool | One-line purpose |
|---|---|
| `list_asset_groups` / `list_archived_asset_groups` / `get_asset_group` | Asset groups with subtype-specific projection. |
| `list_email_groups` / `get_email_group` | Recipient lists for policy actions, with the SMTP server each routes through. |
| `find_email_groups_using_smtp_server` | Email groups bound to a given SMTP server id — useful before retiring that server. |
| `list_schedule_groups` / `list_archived_schedule_groups` / `get_schedule_group` | Maintenance / business-hours windows. Subtype-aware: `TimeInterval` returns `start_time`/`end_time`; `RecurringGroup` returns weekly windows. |
| `list_tag_groups` / `get_tag_group` | PLC controller-tag rollups bound to TagValuePolicy. |
| `list_eligible_tags` | Discover controller tags addable to a tag group, filterable by asset id and tag-value type. Use before `create_tag_group`. |
| `list_port_groups` / `list_archived_port_groups` / `get_port_group` | Port-range bundles consumed by PortPolicy. |
| `list_protocol_groups` / `list_archived_protocol_groups` / `get_protocol_group` | Protocol + port-range bundles consumed by ProtocolPolicy (TCP, UDP, MODBUS, S7, IEC104, DNP3, PROFINET, CIP, ETHIP, IEC61850, etc.). |
| `list_rule_groups` / `list_archived_rule_groups` / `get_rule_group` | IDS rule SID bundles consumed by IntrusionPolicy. Each entry previews up to 25 included rules. |
| `list_user_groups` / `list_archived_user_groups` / `get_user_group` | ICP-level user permission groups with assigned roles + member preview. |
| `list_em_user_groups` / `list_em_archived_user_groups` / `get_em_user_group` | Enterprise-Manager-level user groups with `em_level` flag, roles, member preview. |

---

## Write tools

Write tools register only when the operator enabled write access at
setup time. Every write tool defaults to `dry_run=True`; passing
`dry_run=False` actually sends the mutation. Both paths land in
`/data/audit.jsonl`.

### Asset state

| Tool | Effect | Risk |
|---|---|---|
| `hide_asset` | Mark one asset hidden (filter from default views; history preserved). Use for known-safe assets that clutter the screen. **Not for pulled hardware** — use `remove_assets_by_address` for that. | Low |
| `restore_asset` | Un-hide a previously hidden asset. | Low |
| `bulk_hide_assets` | Hide every asset matching a filter or search. | Low–Medium |
| `bulk_restore_assets` | Un-hide every asset matching a filter or search. | Low |
| `remove_assets_by_address` | Mark one or more IP addresses pending deletion in Tenable OT. Use for hardware that has been physically pulled. Re-discovery creates fresh records if it returns. | Medium |
| `recalculate_asset_risk` | Force Tenable OT to recompute one asset's risk score. | Low |
| `recalculate_all_risk` | Force a deployment-wide risk recompute. Optional component scope: 'Events' / 'Vulnerabilities' / 'Backplane'. | Medium |

### Asset property edits

Edit the operator-set metadata Tenable lets you override on an asset
(name, type, location, description, Purdue level, criticality, custom
fields). Discovered fields (vendor, model, firmware, family) are NOT
editable — Tenable derives them. Setting an enum field to its
`_RemoveUserDefinedValue` sentinel (exposed via `clear_fields`)
reverts that field to "as Tenable discovered".

| Tool | Effect | Risk |
|---|---|---|
| `update_asset` | Edit one asset's properties. Accepts natural OT vocabulary (`kind`='plc'/'switch'/..., `criticality`='low'/'medium'/'high', `purdue_level`='level0'..'level4'). `custom_fields` keyed by label (translates to slot internally). `clear_fields` reverts named fields to as-discovered. | Low–Medium |
| `bulk_edit_assets` | Apply the same edit to every asset matching a natural-vocabulary filter (same args as `query_assets`) or `search`. Same edit args as `update_asset` plus `segment_id` to reassign segment membership. Refuses bare unfiltered calls. | Medium |
| `reset_asset_metadata` | Revert every operator-set field on one asset back to as-discovered in a single call. Observed data (events, vulns, comms) preserved — for full re-discovery use `remove_assets_by_address`. | Low–Medium |

### Custom-field management

Tenable models per-asset operator metadata as 10 fixed string slots
(`customField1`..`customField10`); operators map each slot to a human
label and a value type. These tools manage that schema; per-asset
*values* are set via `update_asset`.

| Tool | Effect | Risk |
|---|---|---|
| `create_custom_field` | Allocate the next free slot with a chosen label and value type ('PlainText' / 'HyperLink'). Fails clearly if all 10 slots are used. | Low |
| `rename_custom_field` | Change a slot's label and/or value type. Identify the slot by `field_id` or `current_name`. Stored values preserved. | Low |
| `delete_custom_field` | Free a slot AND wipe its stored value on every asset that had it set. `confirm_wipes_values=True` required on top of `dry_run=False` — two-step intent. Irreversible. | **HIGH** |

### Groups

Eight first-class group concepts. The read counterparts are above
under **Groups (read)**.

#### Asset groups

Polymorphic — pick exactly one membership shape. The Filter type
accepts an AssetGroupExpressionsParams tree for arbitrarily complex
inclusion logic. CIDR shorthand expands to Tenable's IpRange
(`startIp`/`endIp`) input.

| Tool | Effect | Risk |
|---|---|---|
| `create_asset_group` | Create a new asset group. Membership shape (pick ONE): `asset_ids` → AssetList, `ips` → IpList, `cidr` (e.g. '10.2.9.0/24') or `start_ip` + `end_ip` → IpRange, `asset_type` + `family` → TypeFamily, `vlan` → Segment, `filter` → Filter. `display_tag=True` surfaces it as a UI tag. | Low |
| `update_asset_group` | Modify name, description, display-tag flag, or membership. Same shape rules as create. | Low |
| `archive_asset_group` | Archive (soft-delete) an asset group. | Low |
| `bulk_set_asset_group_display_tag` | Toggle the UI-tag flag on/off across many groups in one call. | Low |

#### Email groups

Recipient lists bound to one SMTP server, referenced by policy actions
to route alert emails.

| Tool | Effect | Risk |
|---|---|---|
| `create_email_group` | Create a recipient list bound to `smtp_server_id`. | Low |
| `update_email_group` | Rename, change SMTP server, or replace recipients (full replacement). | Low |
| `archive_email_group` | Archive (soft-delete). Policies still pointing at the group will silently fail to deliver — audit first. | Medium |

#### Schedule groups

Maintenance / business-hours windows referenced by every policy
mutation's `schedule` argument. Pick exactly one shape: one-shot
(`start_time` + `end_time`), weekly recurring (`schedules` of
`{day, start, end}` entries), or system Function.

| Tool | Effect | Risk |
|---|---|---|
| `create_schedule_group` | Create a one-shot IntervalGroup, a weekly RecurringGroup, or a Function placeholder. Day enum natural vocab: 'monday' / 'every_day' / 'weekdays' / etc. | Low |
| `update_schedule_group` | Rename or replace the windows. | Low |
| `archive_schedule_group` | Archive (soft-delete). Policies referencing it lose their window — audit first. | Medium |

#### Tag groups (PLC controller-tag rollups)

Distinct from asset-groups-with-displayTag — these are bundles of
controller tags ({asset, tag id, tag type}) consumed by TagValuePolicy.

| Tool | Effect | Risk |
|---|---|---|
| `create_tag_group` | Create a tag group. Top-level `tag_type` enum: Unknown / Int / Bool / Short / DInt / Long / Float / MultipleTagTypes. Use `list_eligible_tags` first. | Low |
| `update_tag_group` | Rename or replace items. | Low |
| `archive_tag_group` | Archive (soft-delete). Tag-value policies referencing it lose their member list. | Medium |

#### Rule groups (IDS rule bundles)

Bundles of IDS rule SIDs (Snort-style numeric ids) referenced by
IntrusionPolicy.

| Tool | Effect | Risk |
|---|---|---|
| `create_rule_group` | Create a rule group containing the supplied list of SIDs. | Low |
| `update_rule_group` | Rename or replace the SID list. | Low |
| `archive_rule_group` | Archive (soft-delete). IntrusionPolicies referencing it lose their rule definition. | Medium |

#### Port groups

Reusable port-range bundles consumed by PortPolicy.

| Tool | Effect | Risk |
|---|---|---|
| `create_port_group` | Create a port group from a list of `{start_port, end_port}` items. | Low |
| `update_port_group` | Rename or replace items. | Low |
| `archive_port_group` | Archive (soft-delete). | Medium |

#### Protocol groups

Reusable (protocol, port-range) bundles consumed by ProtocolPolicy.
`protocol` is a Tenable ProtocolSuperType enum value — TCP, UDP,
MODBUS, S7, IEC104, DNP3, PROFINET, CIP, ETHIP, IEC61850, MMS,
BACNET, and ~40 more.

| Tool | Effect | Risk |
|---|---|---|
| `create_protocol_group` | Create a protocol group from a list of `{protocol, start_port?, end_port?}` items. | Low |
| `update_protocol_group` | Rename or replace items. | Low |
| `archive_protocol_group` | Archive (soft-delete). | Medium |

#### User groups (ICP-level)

Permission groupings that combine `role_ids` (capabilities),
`user_ids` (members), `zone_ids` (zone access), and
`providers_mapping` (external auth-provider group bindings).

| Tool | Effect | Risk |
|---|---|---|
| `create_user_group` | Create an ICP-level user group. All list args optional. | Medium |
| `edit_user_group` | Update name, roles, users, zones, providers, EM mappings. Full replacement on each list. | Medium |
| `archive_user_group` | Archive (soft-delete). Members lose group-assigned roles and zone access. | **HIGH** |
| `set_user_groups` | Reassign one user's exact group memberships (full replacement). | Medium |

#### EM user groups (Enterprise Manager-level)

Multi-site permission groupings. Same args as ICP user groups plus
`em_level` (required Boolean at creation: true = EM-only, false =
visible to paired ICPs).

| Tool | Effect | Risk |
|---|---|---|
| `create_em_user_group` | Create an EM-level user group. | Medium |
| `edit_em_user_group` | Update name, roles, users, zones, providers, EM mappings. Note `em_level` is fixed at creation time. | Medium |
| `archive_em_user_group` | Archive (soft-delete). Multi-site implications — audit first. | **HIGH** |
| `set_em_user_groups` | Reassign one EM user's exact group memberships. | Medium |

### Detection policies

| Tool | Effect | Risk |
|---|---|---|
| `enable_detection_policy` | Turn one detection policy back on. | Low |
| `disable_detection_policy` | Turn one detection policy off. **Disables detection coverage** — review blast radius first. | **HIGH** |
| `archive_detection_policy` | Archive (effectively delete) a detection policy. Past findings remain queryable. Irreversible. | **HIGH** |
| `enable_detection_policies` | Bulk enable. | Low |
| `disable_detection_policies` | Bulk disable. **Disables detection coverage.** | **HIGH** |
| `archive_detection_policies` | Bulk archive. Irreversible. | **HIGH** |

### Findings

| Tool | Effect | Risk |
|---|---|---|
| `resolve_findings` | Mark detection findings resolved by filter (`severity_at_least` / `status` / `since` / `until` / `policy_id` / `plugin_id` / `mitre_technique` / `search`), with an optional comment. At least one filter or `search` is required. | Medium |

### Active scans (define / lifecycle)

This server **defines** scan jobs but **never executes** them. Active
scanning sends probe traffic to OT assets and has documented history
of crashing legacy PLCs/HMIs; the actual trigger stays human-only via
the Tenable OT UI. `runActiveQuery` is deliberately not exposed.

#### Generic (all OpType variants)

| Tool | Effect | Risk |
|---|---|---|
| `define_active_scan` | Define a scan of any OpType ('port_scan', 'asset_discovery', 'snmp', 'ping', 'arp', 'dns', etc.) with optional schedule and asset-group target. Use this when you don't need to set type-specific options. | Medium |
| `edit_active_scan` | Modify a scan's name, description, enabled flag, asset group, or schedule. (Operation type cannot be changed — delete and redefine.) | Medium |
| `enable_active_scan` | Set a scan's `enabled` flag true (does not run it). | Low |
| `disable_active_scan` | Set a scan's `enabled` flag false. | Low |
| `delete_active_scan` | Delete a scan definition. Past execution history retained. | Medium |

#### Per-type (typed-options structs)

These tools surface the typed `*OptionsParams` structs that the
generic mutation cannot express (port range, mapping rate, SNMP
flags, asset-discovery network list, concurrency, etc.).

| Tool | Effect | Risk |
|---|---|---|
| `define_port_scan` / `edit_port_scan` | Port-scan job with `port_range` ('basic' / 'lean' / 'full_sweep') and `mapping_rate` ('1' / '2' / '5' / '10' / '50' / '100' / '500' / '1000'). | Medium |
| `define_snmp_scan` / `edit_snmp_scan` | SNMP scan with `query_network_interfaces` and `query_neighbors` flags. | Medium |
| `define_controller_discovery_scan` / `edit_controller_discovery_scan` | Controller-discovery scan (no asset-group; Tenable OT scopes from its known controller models). | Medium |
| `define_asset_discovery_scan` / `edit_asset_discovery_scan` | Sweeps `networks` (CIDRs / IP ranges) for new assets. Tunable `concurrent_workers` ('10' / '20' / '30') and `pause_between_probes` ('1s' / '2s' / '3s'). | Medium |
| `define_inactive_probing_scan` / `edit_inactive_probing_scan` | Probe assets that have gone silent. Same concurrency knobs. | Medium |
| `edit_subnets_discovery_scan` | Tune the singleton subnets-discovery scan (no create variant). | Medium |

---

## Design principles

These cut across every tool in the catalog:

- **Stateless server.** Tenable OT data never lands on disk inside
  the container. Every tool call is a live GraphQL query to your
  Tenable OT deployment. The server holds only the encrypted setup
  config, the auto-generated TLS keypair, and the audit log.
- **Tools expose data; the AI does the analysis.** No precomputed
  attack paths, no clustering, no narratives, no LLM calls
  server-side. The AI walks relationships via follow-up tool calls.
- **Live data.** Data is as fresh as the question. No sync delay, no
  staleness — every query hits Tenable OT in real time.
- **Read-only by default.** Write tools register only when the
  operator opts in at setup. Every write tool defaults to dry-run.
- **Tool surface owns its vocabulary.** Argument names, accepted
  values, and descriptions use natural OT terms ("high",
  "controller", "level1"). A translation layer in `tools/_enums.py`
  maps to whatever the upstream vendor's API expects internally.
  Renaming an enum on Tenable's side never breaks an MCP-client
  prompt.
- **No active scanning by AI.** The AI may DEFINE scan jobs; a human
  operator triggers them from the Tenable OT UI. Hard scope
  boundary, not a deferral.
