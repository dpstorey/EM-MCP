# Tenable OT MCP Server — Tool Reference

**Server:** `tenable-ot-mcp` v1.28.1

Organised by functional category. All **Write** operations default to `dry_run`; a handful are additionally destructive or irreversible (flagged inline). Scan jobs can be *defined* but never *executed* from this server — triggering is a human-only action in the Tenable OT UI.

**Totals:** 103 tools — 47 read-only, 56 write operations.

---

## Assets & Inventory

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_assets` | Read | Returns OT assets matching filter criteria. Each asset includes type, category, criticality, IPs, risk summary, and custom fields. |
| `get_asset` | Read | Returns detailed information for one OT asset by ID. |
| `list_custom_fields` | Read | Returns configured asset custom field labels and value types for this tenant. |
| `get_asset_intelligence` | Read | Returns one asset's full bundle: core info, open vulns, recent events, and 1-hop peers. Use for per-asset intelligence drafts. No narrative auto-generated. |
| `hide_asset` | Write (dry-run) | Mark one asset as hidden. Hidden assets stay in inventory (history, vulns, comms preserved) but are filtered out of default views. Use this for known-safe assets you don't want crowding the screen — e.g. a vendor laptop permanently parked on the network. For HARDWARE physically pulled, use `remove_assets_by_address` instead so re-discovery creates a fresh entry on return. |
| `restore_asset` | Write (dry-run) | Un-hide a previously hidden asset. The asset reappears in default views with its full history intact. |
| `bulk_hide_assets` | Write (dry-run) | Hide every asset matching a filter or free-text search. The filter shape mirrors `query_assets` but is passed raw (Tenable AssetExpressionsParams). Use the simpler single-asset `hide_asset` unless you're confident in the filter's scope. |
| `bulk_restore_assets` | Write (dry-run) | Un-hide every asset matching a filter or free-text search. |
| `remove_assets_by_address` | Write — destructive (dry-run) | Mark one or more IP addresses as pending deletion in Tenable OT. After the operator processes the deletion queue, those entries leave inventory and any subsequent discovery creates fresh records. Use this for HARDWARE that has been PHYSICALLY PULLED — decommissioned PLCs, retired switches — where you want a clean re-discovery if it ever comes back. For known-safe entries you just want out of default views, use `hide_asset` instead. |
| `update_asset` | Write (dry-run) | Edit one OT asset's operator-set properties. Pass any subset of the editable fields; omitted fields are left untouched. Names in `clear_fields` revert the corresponding property to 'as Tenable discovered'. Natural-vocabulary inputs are translated to Tenable enums before the GraphQL goes out: `kind` (long list incl. 'Plc', 'Controller', 'Hmi', etc.), `purdue_level` (unknown/level0–level4), `criticality` (none/low/medium/high), `custom_fields` (dict keyed by operator's configured label — call `list_custom_fields` first; empty-string values clear the value). Reclassifying an asset (`kind`) affects every downstream view that filters by category; changing `criticality` flows into risk scoring. Audit-logged. |
| `bulk_edit_assets` | Write — many assets (dry-run) | Apply the same property edit to every asset matching a natural-vocabulary filter or free-text search. Targeting args mirror `query_assets`: `kind` (subset: 'plc', 'rtu', 'ied', 'hmi', 'controller', 'ot_compute', 'switch', 'router', 'firewall', 'gateway', 'access_point', 'iot', 'server', 'workstation', 'field_device', 'tenable_appliance', 'printer', 'camera', 'ups', 'mobile', 'medical', 'panel', 'storage'), `category` ('controller'\|'network'\|'iot'), `criticality_at_least`, `vendor`, `name_contains`, `search`, `hidden`. Edit args are the same as `update_asset` plus `segment_id` to reassign segment membership. AT LEAST ONE targeting arg is required — bare un-filtered bulk edits are rejected. Audit-logged. |
| `reset_asset_metadata` | Write (dry-run) | Revert every operator-set field on one asset back to 'as Tenable discovered'. Clears name, type, location, description, purdueLevel, criticality, and every custom-field slot value. Tenable's auto-classification fields (vendor, model, firmware, family) are not affected. Observed data (events, vulnerabilities, comms history) is preserved — for a full re-discovery use `remove_assets_by_address` instead. |
| `create_custom_field` | Write (dry-run) | Allocate one of Tenable's 10 custom-field slots and assign it an operator-defined label. Fails clearly if all 10 slots are already in use. Args: `name` (human label, e.g. 'Plant ID'), `value_type` ('PlainText' default \| 'HyperLink'). After this succeeds, set values on assets via `update_asset custom_fields={'<name>': '<value>'}`. |
| `rename_custom_field` | Write (dry-run) | Change the operator-defined label and/or value type on an existing custom-field slot. Stored values are preserved. Identify the slot by either `field_id` ('customField1'..) or `current_name`. One is required. |
| `delete_custom_field` | Write — destructive (dry-run) | Delete a custom-field slot. The slot is freed for reuse AND every asset that had a value stored under this slot has that value wiped — there is no undo. Identify the slot by either `field_id` or `current_name`. To guard against accidental loss, `confirm_wipes_values=True` is REQUIRED on top of `dry_run=False` — without it the call is rejected even when dry-run is off. |

## Risk Scoring

| Tool | Type | Description |
| :--- | :--- | :--- |
| `recalculate_asset_risk` | Write (dry-run) | Force Tenable OT to recompute the risk score for one asset. Useful after hiding/un-hiding, after major vulnerability resolution, or when investigating a stale score. |
| `recalculate_all_risk` | Write (dry-run) | Force a deployment-wide risk recompute. `components` is optional; pass any of 'Events', 'Vulnerabilities', 'Backplane' (or omit to recompute all). This can be expensive on large deployments — coordinate with the operator. |

## Vulnerabilities

| Tool | Type | Description |
| :--- | :--- | :--- |
| `get_asset_vulnerabilities` | Read | Returns vulnerabilities affecting one OT asset by ID. |
| `query_vulnerabilities` | Read | Returns Tenable plugins matching filters. Includes CVE CVSS scores exploit flags (KEV/malware). Use with `get_vulnerability`. |
| `get_vulnerability` | Read | Fetches single vulnerability by id with full affected asset list. Ideal for assessing exposure breadth of exploited vulns. |
| `query_vulnerability_clusters` | Read | Returns per-asset vulnerabilities or global CVE search (CVE-substring or asset_ids). The AI walks results to find shared CVEs or leverage points. |

## Events & Detection Policies

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_events` | Read | Returns OT detection events matching filter criteria with time, severity, policy, and asset context. |
| `get_event` | Read | Returns detailed information for one OT event by ID. |
| `list_detection_policies` | Read | Returns OT detection policies — rules that fire events. Each has level, enabled flags, event-type category, and event counts. Use to audit config or noise. |
| `query_policy_findings` | Read | Returns per-asset findings (policy × asset × hits) with first/last hit times, status, and source/dest assets. Use to spot noisy policies or MITRE mappings. |
| `query_temporal_patterns` | Read | Returns events in a time window, ordered chronologically, with their classification, firing policy, and source/dest IPs joined. The AI uses this raw sequence to detect patterns (e.g. config-download + firmware-change + operating-mode-change within minutes = high-priority investigation). The server does NOT detect motifs, score patterns, or label sequences. |
| `enable_detection_policy` | Write (dry-run) | Enable one detection policy by id (Tenable's `enablePolicy`). The policy starts firing events on matching traffic. |
| `disable_detection_policy` | Write (dry-run) | Disable one detection policy by id. The policy stops firing new events but its history and findings persist. Use to silence a noisy or known-tuning-needed policy without deleting it. DISABLES DETECTION — review the blast radius before applying. |
| `archive_detection_policy` | Write — irreversible (dry-run) | Archive (effectively delete) a detection policy. Past findings remain queryable but the policy no longer appears in active lists. |
| `enable_detection_policies` | Write (dry-run) | Enable many detection policies at once. |
| `disable_detection_policies` | Write (dry-run) | Disable many detection policies at once. Like `disable_detection_policy`, this stops new events from firing — review blast radius before applying. |
| `archive_detection_policies` | Write — irreversible (dry-run) | Archive (effectively delete) many detection policies at once. Past findings remain queryable. |
| `resolve_findings` | Write (dry-run) | Mark detection findings resolved (Tenable's `resolveFindings`). Filter values use the same natural OT vocabulary as `query_policy_findings`: `severity_at_least` ('none'\|'low'\|'medium'\|'high'), `status` (a FindingStatus value), `since`/`until` (ISO-8601 timestamps on lastHitTime), `policy_id`/`plugin_id`/`mitre_technique` (equal-match id filters), `search` (single-term substring across finding text). Pass `comment` to attach a resolution note. AT LEAST ONE filter or `search` is required — bare resolveAll is rejected. |

## Topology, Segmentation & Attack Paths

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_segments_and_zones` | Read | Returns Tenable OT's segmentation: every segment (with VLAN, subnet, asset-type filter) and zone. Use for compliance and topology reviews. |
| `get_communication_paths` | Read | Returns L2 links for one OT asset: peer id, protocols, traffic/conversation counts, and first/last conversation times. |
| `query_attack_pathways` | Read | Returns 1-hop peers with protocol and conversation counts for graph exploration. |

## Sensors & Environment Overview

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_sensors` | Read | Returns every Tenable OT sensor in the deployment with its current status, connection/tunnel status, version, addressing, error state, and whether updates are pending. Use to verify visibility coverage before drawing conclusions from query_assets/query_events — an offline sensor means absence of evidence, not evidence of absence. The `status` filter applies client-side after fetch. |
| `summarize_environment` | Read | Returns deployment counts for assets, events, vulnerabilities, sensors, topology and policies. |
| `list_paired_icps` | Read | Queries Enterprise Manager's root GraphQL endpoint and returns paired ICP appliance status, machine ids, site metadata, and version details. Use this to discover the machine id needed for EM relay URLs like https://\<em\>/\<machine_id\>/graphql. |

## Active Scans (define-only — never executed from this server)

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_active_scans` | Read | Returns Tenable OT active-scan job specifications: name, description, scan operation type (PortScan, AssetDiscovery, SnmpType, etc.), category (IT/OT/Discovery), trigger (Manual/Periodic/System), enabled flag, status, and the asset group the job targets. Use to audit what scans are configured. Predefined system scans appear with `predefined: true`. Note: this server does not expose any tool that runs a scan — that's a human-only action via the Tenable OT UI. |
| `get_active_scan` | Read | Returns the full specification for one active-scan job by id. Use after `list_active_scans` returns a job of interest, or when reading parameters before suggesting modifications. |
| `get_active_scan_executions` | Read | Returns past execution records for one active scan: start/end time, elapsed time, status (Completed/Failed/Ongoing), who initiated, source (UI/API/system), and any failure explanation. Use to audit when a scan was last run and whether it succeeded — but the underlying execution is triggered by humans, not this server. |
| `define_active_scan` | Write (dry-run) | Create a new active-scan definition in Tenable OT. The scan is stored DEFINED but not executed. A human operator must trigger it from the Tenable OT UI; this server deliberately does not expose `runActiveQuery`. `operation` accepts natural names: 'port_scan', 'asset_discovery', 'snmp', 'identification', 'ping', 'arp', 'dns', 'wmi', 'subnets_discovery', 'ics_discovery', 'inactive_asset_probe', etc. Schedule: pass `daily_hour` (e.g. '14:00') for a daily scan, or `interval`/`interval_count` (e.g. '1h', 4) for a recurring scan. Omit both for manual trigger only. |
| `edit_active_scan` | Write (dry-run) | Modify an existing active-scan definition (name, description, enabled flag, asset group, schedule). The operation type cannot be changed — for that, delete and redefine. |
| `enable_active_scan` | Write (dry-run) | Set the `enabled` flag on an active scan to true. This does NOT run the scan — only humans run scans. Enabling lets the scan participate in scheduled runs initiated by the Tenable OT UI. |
| `disable_active_scan` | Write (dry-run) | Set the `enabled` flag on an active scan to false. The scan stays defined but doesn't participate in scheduled runs. |
| `delete_active_scan` | Write (dry-run) | Permanently delete an active-scan definition. Past execution history is retained. |
| `define_port_scan` | Write (dry-run) | Create a port-scan job in Tenable OT. Saved DEFINED but not executed; an operator triggers it from the Tenable OT UI. `port_range`: 'basic'\|'lean'\|'full_sweep'. `mapping_rate`: '1'\|'2'\|'5'\|'10'\|'50'\|'100'\|'500'\|'1000'. Schedule + asset_group_id args follow the same pattern as `define_active_scan`. |
| `edit_port_scan` | Write (dry-run) | Modify an existing port-scan job's name, description, enabled flag, asset group, schedule, or typed options (port_range, mapping_rate). Same arg shape as `define_port_scan`. |
| `define_snmp_scan` | Write (dry-run) | Create an SNMP scan job. Probes target assets for SNMP metadata (network interfaces, neighbors). `query_network_interfaces`: probe interface table. `query_neighbors`: probe SNMP neighbor table. |
| `edit_snmp_scan` | Write (dry-run) | Modify an existing SNMP scan job. Same arg shape as `define_snmp_scan`. |
| `define_controller_discovery_scan` | Write (dry-run) | Create a controller-discovery scan job. Tenable OT decides the scope from its known controller models; no asset-group or typed options are required. |
| `edit_controller_discovery_scan` | Write (dry-run) | Modify an existing controller-discovery scan job's name, description, enabled flag, or schedule. |
| `define_asset_discovery_scan` | Write (dry-run) | Create an asset-discovery scan job. Sweeps the supplied networks for previously-unseen assets. `networks`: list of CIDR subnets or IP ranges (e.g. ['10.100.0.0/16', '192.168.10.0/24']). `origins`: optional list of source-IP addresses. `concurrent_workers`: '10'\|'20'\|'30'. `pause_between_probes`: '1s'\|'2s'\|'3s'. Asset discovery does not target a single asset group; the networks list scopes the sweep instead. |
| `edit_asset_discovery_scan` | Write (dry-run) | Modify an existing asset-discovery scan job: name, description, enabled, schedule, networks, origins, concurrent_workers, pause_between_probes. Same arg shape as `define_asset_discovery_scan`. |
| `define_inactive_probing_scan` | Write (dry-run) | Create an inactive-probing scan job. Probes assets that have gone silent on the wire to see if they're still alive. `concurrent_workers`: '10'\|'20'\|'30'. `pause_between_probes`: '1s'\|'2s'\|'3s'. |
| `edit_inactive_probing_scan` | Write (dry-run) | Modify an existing inactive-probing scan job. Same arg shape as `define_inactive_probing_scan`. |
| `edit_subnets_discovery_scan` | Write (dry-run) | Tenable OT ships a single subnets-discovery scan job that operators tune (no create variant — it's a singleton). Modify name, description, enabled, or schedule. |

## Asset Groups

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_asset_groups` | Read | Page through every active (non-archived) asset group in the deployment. Each entry includes its membership shape — IP list, IP range, asset-id list, filter expression, etc. — and whether it surfaces as a UI tag (`display_tag`). Use this before creating to avoid duplicating an existing group. |
| `list_archived_asset_groups` | Read | Page through archived asset groups — those that were soft-deleted via `archive_asset_group`. Group definitions and historical membership are preserved by Tenable; they just stop appearing in active views. |
| `get_asset_group` | Read | Fetch one asset group's full record by its id. The shape varies by group subtype: an `AssetList` returns an `assets_sample` preview, an `IpRange` returns `start_ip`/`end_ip`, a `FilterGroup` returns its `filter` expression, and so on. |
| `create_asset_group` | Write (dry-run) | Create a new Tenable OT asset group. Pass `display_tag=true` to surface it as a UI tag (vs. a hidden policy filter group). Pick exactly ONE membership shape: `asset_ids` → AssetList; `ips` → IpList; `cidr` → IpRange; `start_ip`+`end_ip` → IpRange; `asset_type`+`family` → TypeFamily; `vlan` → Segment; `filter` (raw AssetGroupExpressionsParams) → Filter. If none are given, defaults to an empty Filter group the AI can populate later. |
| `update_asset_group` | Write (dry-run) | Modify an existing asset group: rename, change description, change display-tag flag, or replace the membership list. Same membership shapes as `create_asset_group` — pick exactly one. |
| `archive_asset_group` | Write (dry-run) | Archive an asset group. Membership and history are preserved by Tenable's archive semantics; the group stops appearing in active views and can be inspected via `list_archived_asset_groups`. |
| `bulk_set_asset_group_display_tag` | Write (dry-run) | Turn the UI-tag flag on or off for several asset groups in one call. `status=true` surfaces them as tags; `status=false` hides them (they continue to function as policy filter groups, just not visible as UI tags). |

## Email Groups

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_email_groups` | Read | Page through every email group in the deployment. Each entry includes its recipients, the SMTP server it routes through, and last-modified metadata. Email groups are referenced by detection policies' actions to send alert emails. |
| `get_email_group` | Read | Fetch one email group with its recipient list and bound SMTP server details. |
| `find_email_groups_using_smtp_server` | Read | Given an SMTP-server id, return the email groups bound to it. Useful before retiring an SMTP server: any group returned here will lose its delivery path if the server is removed. |
| `create_email_group` | Write (dry-run) | Create a named recipient list bound to one SMTP server. Detection policies reference the resulting group id in their action configuration to route alert emails. The `smtp_server_id` must be an existing configured SMTP server; this tool does not create SMTP servers. |
| `update_email_group` | Write (dry-run) | Replace the email group's name, SMTP server, and recipient list in one call. Note: `recipients` is a *full replacement* — pass the complete intended list, not a delta. |
| `archive_email_group` | Write (dry-run) | Archive an email group. Any policy action still pointing at the archived group will silently fail to deliver — audit `find_email_groups_using_smtp_server` and the policy list first. |

## Schedule Groups

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_schedule_groups` | Read | Page through every active schedule group. Each entry surfaces its kind (one-shot TimeInterval, weekly RecurringGroup, or system ScheduleFunction) and the windows it defines. Every policy mutation's `schedule` argument resolves against one of these. |
| `list_archived_schedule_groups` | Read | Soft-deleted schedule groups, paginated. |
| `get_schedule_group` | Read | Fetch one schedule group. Shape varies by kind: `TimeInterval` returns `start_time`/`end_time`; `RecurringGroup` returns a list of weekly windows under `schedules`. |
| `create_schedule_group` | Write (dry-run) | Create a schedule group that policies reference via their `schedule` argument. Pick exactly ONE shape: `start_time`+`end_time` → IntervalGroup; `schedules` (weekly recurring windows, each {day, start, end}) → RecurringGroup; neither → system Function group placeholder. |
| `update_schedule_group` | Write (dry-run) | Rename or replace the windows of an existing schedule group. Same shape rules as `create_schedule_group`. |
| `archive_schedule_group` | Write (dry-run) | Archive a schedule group. Policies still pointing at it will lose their window definition — audit first. |

## Tag Groups & Controller Tags

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_tag_groups` | Read | Page through every tag group. Tag groups bundle controller tags (by asset id + tag id) so a TagValuePolicy can fire against all members. `tag_type` indicates the scalar type Tenable evaluates the tag values as. |
| `get_tag_group` | Read | One tag group with up to 100 member items. |
| `list_eligible_tags` | Read | List controller tags that could be added to a tag group. Filterable by asset (`asset_id`) and tag-value type (`tag_type`: one of Unknown, Int, Bool, Short, DInt, Long, Float, MultipleTagTypes). Use this before `create_tag_group` to discover what's available without guessing tag ids. |
| `create_tag_group` | Write (dry-run) | Create a tag group bundling controller tags for use by a TagValuePolicy. `items` is a list of {asset_id, tag_id, tag_type} entries — `tag_type` per item is the value type string ("Int", "Bool", "Float", etc.). The top-level `tag_type` enum constrains the group's expected scalar type at evaluation; valid values: Unknown, Int, Bool, Short, DInt, Long, Float, MultipleTagTypes. Use `list_eligible_tags` to discover available tags before calling this. |
| `update_tag_group` | Write (dry-run) | Rename or replace the member items of an existing tag group. `items` is a full replacement (not a delta). |
| `archive_tag_group` | Write (dry-run) | Archive a tag group. Tag-value policies referencing it will lose their member list — audit first. |

## Rule Groups (IDS)

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_rule_groups` | Read | Page through every active rule group. A rule group is a bundle of IDS rule SIDs referenced by IntrusionPolicy. Each entry includes a preview of up to 25 included rules. |
| `list_archived_rule_groups` | Read | Soft-deleted rule groups, paginated. |
| `get_rule_group` | Read | One rule group with the first 25 included rules. |
| `create_rule_group` | Write (dry-run) | Create a rule group containing the IDS rule SIDs supplied in `rule_sids`. IntrusionPolicy references the resulting rule-group id via its `ruleGroup` argument. SIDs are sent as floats (Tenable's schema convention). |
| `update_rule_group` | Write (dry-run) | Rename or replace the SID list of a rule group. `rule_sids` is a full replacement. |
| `archive_rule_group` | Write (dry-run) | Archive a rule group. IntrusionPolicies referencing it will lose their rule definition — audit first. |

## Port Groups

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_port_groups` | Read | Page through every active port group. Port groups are reusable port-range bundles consumed by PortPolicy definitions. |
| `list_archived_port_groups` | Read | Soft-deleted port groups, paginated. |
| `get_port_group` | Read | One port group with up to 100 of its port-range items. |
| `create_port_group` | Write (dry-run) | Create a port group from a list of {start_port, end_port} ranges. PortPolicy mutations reference the resulting id via their `portGroup` arg. |
| `update_port_group` | Write (dry-run) | Rename or replace the port-range items of a port group. `items` is a full replacement. |
| `archive_port_group` | Write (dry-run) | Archive a port group. PortPolicies referencing it will lose their port definition — audit first. |

## Protocol Groups

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_protocol_groups` | Read | Page through every active protocol group. Each item carries a protocol (TCP/UDP/MODBUS/S7/IEC104/DNP3/etc.) and optional port range. |
| `list_archived_protocol_groups` | Read | Soft-deleted protocol groups, paginated. |
| `get_protocol_group` | Read | One protocol group with up to 100 of its items. |
| `create_protocol_group` | Write (dry-run) | Create a protocol group. Each item is {protocol, start_port?, end_port?}. `protocol` must be a Tenable ProtocolSuperType enum value — TCP, UDP, MODBUS, S7, IEC104, DNP3, PROFINET, CIP, ETHIP, IEC61850, etc. Port range is required for some protocols (TCP/UDP) and ignored for others. |
| `update_protocol_group` | Write (dry-run) | Rename or replace the items of a protocol group. `items` is a full replacement. |
| `archive_protocol_group` | Write (dry-run) | Archive a protocol group. ProtocolPolicies referencing it will lose their protocol definition — audit first. |

## User Groups & Permissions (ICP-level)

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_user_groups` | Read | Page through every active user group at the ICP level. Each entry exposes its assigned roles and a sample of member users. |
| `list_archived_user_groups` | Read | Soft-deleted user groups at the ICP level. |
| `get_user_group` | Read | One ICP-level user group with its roles and member preview. |
| `create_user_group` | Write (dry-run) | Create a permission group at the ICP level. `role_ids` attach roles to the group; `user_ids` populate initial members; `zone_ids` restrict access by zone; `providers_mapping` binds external auth-provider groups to this Tenable group (each entry: {provider_id, external_groups: [strings]}); `em_icp_user_group_ids` links to EM-level groups when this ICP is paired to an EM. All are optional. |
| `edit_user_group` | Write (dry-run) | Update an existing ICP-level user group's metadata or membership. All list args are full replacements (not deltas). |
| `archive_user_group` | Write (dry-run) | Archive an ICP-level user group. Members lose group-assigned roles and zone access — audit before archiving. |
| `set_user_groups` | Write (dry-run) | Set the exact list of ICP-level user groups a user belongs to. `new_group_ids` is a full replacement — groups not in the list are removed, new ones are added. |

## User Groups & Permissions (EM-level)

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_em_user_groups` | Read | Page through every active EM-level user group. Each entry exposes `em_level` (whether the group is EM-only) plus roles and member preview. |
| `list_em_archived_user_groups` | Read | Soft-deleted EM-level user groups. |
| `get_em_user_group` | Read | One EM-level user group with its roles and member preview. |
| `create_em_user_group` | Write (dry-run) | Create a permission group at the EM level. Same args as `create_user_group` plus `em_level` (required Boolean: true = EM-only scope, false = ICP-visible via the EM/ICP pairing). |
| `edit_em_user_group` | Write (dry-run) | Update an existing EM-level user group. Note Tenable's editEmUserGroup mutation does not accept `em_level` — that flag is fixed at creation time. |
| `archive_em_user_group` | Write (dry-run) | Archive an EM-level user group. Multi-site implications — check `list_em_user_groups` for membership before archiving. |
| `set_em_user_groups` | Write (dry-run) | Set the exact list of EM-level user groups a user belongs to. Full replacement. |

---

## Category Summary

| Category | Read | Write | Total |
| :--- | :---: | :---: | :---: |
| Assets & Inventory | 4 | 13 | 17 |
| Risk Scoring | 0 | 2 | 2 |
| Vulnerabilities | 4 | 0 | 4 |
| Events & Detection Policies | 5 | 7 | 12 |
| Topology, Segmentation & Attack Paths | 3 | 0 | 3 |
| Sensors & Environment Overview | 3 | 0 | 3 |
| Active Scans (define-only) | 3 | 16 | 19 |
| Asset Groups | 3 | 4 | 7 |
| Email Groups | 3 | 3 | 6 |
| Schedule Groups | 3 | 3 | 6 |
| Tag Groups & Controller Tags | 3 | 3 | 6 |
| Rule Groups (IDS) | 3 | 3 | 6 |
| Port Groups | 3 | 3 | 6 |
| Protocol Groups | 3 | 3 | 6 |
| User Groups — ICP-level | 3 | 4 | 7 |
| User Groups — EM-level | 3 | 4 | 7 |
| **Total** | **47** | **56** | **103** |
