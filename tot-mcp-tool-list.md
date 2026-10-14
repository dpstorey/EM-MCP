# Tenable OT MCP Server — Tool Reference

Generated from source (`tenable-ot-mcp`). **136 tools** — 56 read, 80 write (write tools take `dry_run`).

## assets

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_assets` | Read | Returns a list of OT assets in the Tenable OT deployment, filtered by the provided criteria. |
| `get_asset` | Read | Returns the per-asset bundle for one OT asset by id: identity, classification, IPs / MACs, Purdue level, segment membership, criticality, run status, and aggregate risk. |
| `get_asset_vulnerabilities` | Read | Returns the open vulnerabilities (Tenable plugins) affecting one OT asset. |
| `list_custom_fields` | Read | Returns the asset custom-field schema for this Tenable OT tenant. |

## attack_vector

| Tool | Type | Description |
| :--- | :--- | :--- |
| `get_attackers_view` | Read | Batch attack-path analysis using Tenable OT/EM's own server-side attack-vector computation (slow: one job per asset). |

## correlation

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_attack_pathways` | Read | Returns the asset's 1-hop network neighborhood: the asset itself plus a list of peer-asset IDs it has communicated with, with the protocols and conversation count of each link. |
| `query_vulnerability_clusters` | Read | Returns the per-asset → vulnerabilities join the consuming AI uses to spot common CVEs across multiple assets, exploit chains (KEV + exploit-available + high criticality), or single-patch leverage points (one CVE fixing many). |
| `query_temporal_patterns` | Read | Returns events in a time window, ordered chronologically, with their classification, firing policy, and source/dest IPs joined. |
| `get_asset_intelligence` | Read | Returns one asset's full relational bundle in a single shot: asset core + open vulnerabilities + recent events where the asset is source or destination + 1-hop comms peers. |

## em

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_paired_icps` | Read | Queries Enterprise Manager's root GraphQL endpoint and returns paired ICP appliance status, machine ids, site metadata, and version details. |

## events

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_events` | Read | Returns OT detection events matching the filter criteria, newest first. |
| `get_event` | Read | Returns full detail for a single OT event by id. |

## groups

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_asset_groups` | Read | Page through every active (non-archived) asset group in the deployment. |
| `list_archived_asset_groups` | Read | Page through archived asset groups — those that were soft-deleted via `archive_asset_group`. |
| `get_asset_group` | Read | Fetch one asset group's full record by its id. |
| `list_email_groups` | Read | Page through every email group in the deployment. |
| `get_email_group` | Read | Fetch one email group with its recipient list and bound SMTP server details. |
| `find_email_groups_using_smtp_server` | Read | Given an SMTP-server id, return the email groups bound to it. |
| `list_schedule_groups` | Read | Page through every active schedule group. |
| `list_archived_schedule_groups` | Read | Soft-deleted schedule groups, paginated. |
| `get_schedule_group` | Read | Fetch one schedule group. |
| `list_tag_groups` | Read | Page through every tag group. |
| `get_tag_group` | Read | One tag group with up to 100 member items. |
| `list_eligible_tags` | Read | List controller tags that could be added to a tag group. |
| `list_rule_groups` | Read | Page through every active rule group. |
| `list_archived_rule_groups` | Read | Soft-deleted rule groups, paginated. |
| `get_rule_group` | Read | One rule group with the first 25 included rules. |
| `list_port_groups` | Read | Page through every active port group. |
| `list_archived_port_groups` | Read | Soft-deleted port groups, paginated. |
| `get_port_group` | Read | One port group with up to 100 of its port-range items. |
| `list_protocol_groups` | Read | Page through every active protocol group. |
| `list_archived_protocol_groups` | Read | Soft-deleted protocol groups, paginated. |
| `get_protocol_group` | Read | One protocol group with up to 100 of its items. |
| `list_user_groups` | Read | Page through every active user group at the ICP level. |
| `list_archived_user_groups` | Read | Soft-deleted user groups at the ICP level. |
| `get_user_group` | Read | One ICP-level user group with its roles and member preview. |
| `list_em_user_groups` | Read | Page through every active EM-level user group. |
| `list_em_archived_user_groups` | Read | Soft-deleted EM-level user groups. |
| `get_em_user_group` | Read | One EM-level user group with its roles and member preview. |
| `create_asset_group` | Write | Create a new Tenable OT asset group. |
| `update_asset_group` | Write | Modify an existing asset group: rename, change description, change display-tag flag, or replace the membership list. |
| `archive_asset_group` | Write | Archive an asset group. |
| `bulk_set_asset_group_display_tag` | Write | Turn the UI-tag flag on or off for several asset groups in one call. |
| `create_email_group` | Write | Create a named recipient list bound to one SMTP server. |
| `update_email_group` | Write | Replace the email group's name, SMTP server, and recipient list in one call. |
| `archive_email_group` | Write | Archive an email group. |
| `create_schedule_group` | Write | Create a schedule group that policies reference via their `schedule` argument. |
| `update_schedule_group` | Write | Rename or replace the windows of an existing schedule group. |
| `archive_schedule_group` | Write | Archive a schedule group. |
| `create_tag_group` | Write | Create a tag group bundling controller tags for use by a TagValuePolicy. |
| `update_tag_group` | Write | Rename or replace the member items of an existing tag group. |
| `archive_tag_group` | Write | Archive a tag group. |
| `create_rule_group` | Write | Create a rule group containing the IDS rule SIDs supplied in `rule_sids`. |
| `update_rule_group` | Write | Rename or replace the SID list of a rule group. |
| `archive_rule_group` | Write | Archive a rule group. |
| `create_port_group` | Write | Create a port group from a list of {start_port, end_port} ranges. |
| `update_port_group` | Write | Rename or replace the port-range items of a port group. |
| `archive_port_group` | Write | Archive a port group. |
| `create_protocol_group` | Write | Create a protocol group. |
| `update_protocol_group` | Write | Rename or replace the items of a protocol group. |
| `archive_protocol_group` | Write | Archive a protocol group. |
| `create_user_group` | Write | Create a permission group at the ICP level. |
| `edit_user_group` | Write | Update an existing ICP-level user group's metadata or membership. |
| `archive_user_group` | Write | Archive an ICP-level user group. |
| `set_user_groups` | Write | Set the exact list of ICP-level user groups a user belongs to. |
| `create_em_user_group` | Write | Create a permission group at the EM level. |
| `edit_em_user_group` | Write | Update an existing EM-level user group. |
| `archive_em_user_group` | Write | Archive an EM-level user group. |
| `set_em_user_groups` | Write | Set the exact list of EM-level user groups a user belongs to. |

## policies

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_detection_policies` | Read | Returns OT detection policies — the rules that fire events. |
| `query_policy_findings` | Read | Returns per-asset findings for one or more detection policies — i.e. |
| `list_policy_exclusions` | Read | Returns the active exclusions (tuning rules) for a specific detection policy. |

## policy_create

| Tool | Type | Description |
| :--- | :--- | :--- |
| `describe_policy_type` | Read | List the detection-policy types the create_*_policy tools cover, or give the arguments and valid `event` values for one type. |
| `get_policy` | Read | Fetch a single detection policy by id (title, level, disabled, event details). |
| `create_conversation_policy` | Write | Create a protocol policy that alerts on a CONVERSATION from `src` to `dst` (direction matters: src initiates) using the protocols in `protocol_group_id`. |
| `create_activity_policy` | Write | Create a policy for engineering activity (downloads, uploads, start/stop, firmware...) from `src` to `dst`. |
| `create_asset_policy` | Write | Create a policy for asset changes on assets in `src` (new asset discovered, inactive, firmware change, ...). |
| `create_port_policy` | Write | Create a policy that alerts when assets in `src` expose an open port in `port_group_id` (event OpenPort). |
| `create_ids_src_dst_policy` | Write | Create an IDS-style policy for events between `src` and `dst` (scans, RDP, DNP3 function codes, ...). |
| `create_ids_general_policy` | Write | Create a general IDS policy that alerts on IP address conflicts (event IpConflict). |
| `create_intrusion_policy` | Write | Create a policy that alerts when intrusion rules in `rule_group_id` hit between `src` and `dst` (event IntrusionDetected). |
| `create_spike_policy` | Write | Create a statistical spike policy. |
| `create_rediscovered_asset_policy` | Write | Create a policy that alerts when an asset in `src` reappears after `inactivity_seconds` of silence (event RediscoveredAsset). |
| `create_tag_value_policy` | Write | Create a policy that alerts on an unauthorized write (event UnauthorizedTagWrite) to controller tags in `tag_group_id` on assets in `src`; `min_value`/`max_value` give the allowed range, or set `any_value`. |
| `update_policy` | Write | Replace an existing detection policy's configuration via the matching set*Policy mutation. |

## scans

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_active_scans` | Read | Returns Tenable OT active-scan job specifications: name, description, scan operation type (PortScan, AssetDiscovery, SnmpType, etc.), category (IT / OT / Discovery), trigger (Manual / Periodic / System), enabled flag, status, and the asset group the job tar… |
| `get_active_scan` | Read | Returns the full specification for one active-scan job by id. |
| `get_active_scan_executions` | Read | Returns past execution records for one active scan: start/end time, elapsed time, status (Completed / Failed / Ongoing), who initiated, source (UI / API / system), and any failure explanation. |
| `define_active_scan` | Write | Create a new active-scan definition in Tenable OT. |
| `edit_active_scan` | Write | Modify an existing active-scan definition (name, description, enabled flag, asset group, schedule). |
| `enable_active_scan` | Write | Set the `enabled` flag on an active scan to true. |
| `disable_active_scan` | Write | Set the `enabled` flag on an active scan to false. |
| `delete_active_scan` | Write | Permanently delete an active-scan definition. |
| `define_port_scan` | Write | Create a port-scan job in Tenable OT. |
| `edit_port_scan` | Write | Modify an existing port-scan job's name, description, enabled flag, asset group, schedule, or typed options (port_range, mapping_rate). |
| `define_snmp_scan` | Write | Create an SNMP scan job. |
| `edit_snmp_scan` | Write | Modify an existing SNMP scan job. |
| `define_controller_discovery_scan` | Write | Create a controller-discovery scan job. |
| `edit_controller_discovery_scan` | Write | Modify an existing controller-discovery scan job's name, description, enabled flag, or schedule. |
| `define_asset_discovery_scan` | Write | Create an asset-discovery scan job. |
| `edit_asset_discovery_scan` | Write | Modify an existing asset-discovery scan job: name, description, enabled, schedule, networks, origins, concurrent_workers, pause_between_probes. |
| `define_inactive_probing_scan` | Write | Create an inactive-probing scan job. |
| `edit_inactive_probing_scan` | Write | Modify an existing inactive-probing scan job. |
| `edit_subnets_discovery_scan` | Write | Tenable OT ships a single subnets-discovery scan job that operators tune (no create variant — it's a singleton). |

## sensors

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_sensors` | Read | Returns every Tenable OT sensor in the deployment with its current status, connection / tunnel status, version, addressing, error state, and whether updates are pending. |

## status

| Tool | Type | Description |
| :--- | :--- | :--- |
| `tenable_ot_status` | Read | Reports whether this server can currently reach the Tenable OT Security appliance it fronts. |

## summary

| Tool | Type | Description |
| :--- | :--- | :--- |
| `summarize_environment` | Read | Returns a one-shot snapshot of the operator's OT environment — total counts and useful subtotals across assets, events, vulnerabilities, sensors, topology, and policies. |
| `get_classification_summary` | Read | Reports asset data quality: the percentage of assets that are positively classified (higher is better). |

## topology

| Tool | Type | Description |
| :--- | :--- | :--- |
| `list_segments_and_zones` | Read | Returns Tenable OT's segmentation: every segment (with VLAN, subnet, asset-type filter, system flag, archived flag) and every zone (a higher-level grouping of asset groups). |
| `get_communication_paths` | Read | Returns observed L2 communication links involving one OT asset, with peer asset id, protocols seen, traffic / conversation count, and first/last-conversation times. |

## vuln_findings

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_vulnerability_findings` | Read | Returns per-(asset x vulnerability) finding records — the instances of a Tenable plugin actually being detected on a specific asset, as opposed to `query_vulnerabilities`' plugin catalog view. |

## vulns

| Tool | Type | Description |
| :--- | :--- | :--- |
| `query_vulnerabilities` | Read | Returns Tenable plugins (vulnerabilities) matching the filter criteria. |
| `get_vulnerability` | Read | Returns one Tenable plugin (vulnerability) by id, plus the full list of OT assets currently affected. |

## writes

| Tool | Type | Description |
| :--- | :--- | :--- |
| `hide_asset` | Write | Mark one asset as hidden. |
| `restore_asset` | Write | Un-hide a previously hidden asset. |
| `bulk_hide_assets` | Write | Hide every asset matching a filter or free-text search. |
| `bulk_restore_assets` | Write | Un-hide every asset matching a filter or free-text search. |
| `remove_assets_by_address` | Write | Mark one or more IP addresses as pending deletion in Tenable OT. |
| `recalculate_asset_risk` | Write | Force Tenable OT to recompute the risk score for one asset. |
| `recalculate_all_risk` | Write | Force a deployment-wide risk recompute. |
| `update_asset` | Write | Edit one OT asset's operator-set properties. |
| `bulk_edit_assets` | Write | Apply the same property edit to every asset matching a natural-vocabulary filter or free-text search. |
| `reset_asset_metadata` | Write | Revert every operator-set field on one asset back to 'as Tenable discovered'. |
| `create_custom_field` | Write | Allocate one of Tenable's 10 custom-field slots and assign it an operator-defined label. |
| `rename_custom_field` | Write | Change the operator-defined label and/or value type on an existing custom-field slot. |
| `delete_custom_field` | Write | Delete a custom-field slot. |
| `enable_detection_policy` | Write | Enable one detection policy by id (Tenable's `enablePolicy`). |
| `disable_detection_policy` | Write | Disable one detection policy by id. |
| `archive_detection_policy` | Write | Archive (effectively delete) a detection policy. |
| `enable_detection_policies` | Write | Enable many detection policies at once. |
| `disable_detection_policies` | Write | Disable many detection policies at once. |
| `archive_detection_policies` | Write | Archive (effectively delete) many detection policies at once. |
| `create_activity_exclusion` | Write | Add a tuning exclusion for a network/activity policy (e.g., 'Connections TO external network'). |
| `create_conversation_exclusion` | Write | Add a tuning exclusion for an unauthorized conversation policy (e.g., 'HTTP Communications to Controllers'). |
| `delete_exclusion` | Write | Remove a tuning exclusion from a detection policy. |
| `resolve_findings` | Write | Mark detection findings resolved (Tenable's `resolveFindings`). |
