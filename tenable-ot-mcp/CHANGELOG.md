# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.5.2] - 2026-08-24

### Changed
- **Banner project URL** — points at `https://github.com/dpstorey/EM-MCP`,
  this fork's home, instead of the upstream
  `gitlab.com/jwalley/tenable-ot-mcp`.

### Fixed
- **`MCP_DEBUG_GRAPHQL=1` now actually shows pagination state** — the
  request-side log previously printed only the GraphQL variable *names*
  (`vars_keys=[...]`), never their values, so it couldn't show whether
  `after` actually changed between calls. It now logs the full
  `variables` dict (no secrets live there — the API key is only ever
  added in `_headers()`). A matching response-side log line reports
  `totalCount`, `nodeCount`, the first/last node id on the page, and
  `hasNextPage`/`endCursor`, so a debug run can show at a glance whether
  successive calls advanced or re-fetched the same page.

## [0.5.1] - 2026-08-24

### Added
- **`query_vulnerability_findings`** — per-(asset x plugin) vulnerability
  finding records (first/last hit, fixed-at, lifecycle status), the
  vulnerability-side analog of `query_policy_findings`. Field and filter
  names were confirmed against a live Tenable OT/EM 4.7.44 instance via
  GraphQL schema introspection.

### Fixed
- **`site_uuid` / `site_uuids` validation** — malformed site identifiers
  are now rejected before the request reaches Tenable, with an error
  message that tells the caller to re-fetch the value from
  `list_paired_icps` rather than guess, truncate, or retype it.
- **Clearer non-JSON-response diagnostics** — the "Tenable OT/EM returned
  non-JSON response" error now includes the response content-type, a
  body snippet, and (when the request was relayed through a site-scoped
  ICP) a hint to check the relay routing versus a direct `tenable_url`
  mismatch.

## [0.5.0] - 2026-08-21

### Added
- **Multi-site reads** — collection, search, list, and summary tools accept
  `site_uuids`, with per-site provenance, pagination, and partial-error
  reporting.
- **CIDR-based asset searches** — `query_assets` accepts `subnet` for native
  IPv4 and IPv6 CIDR-range filtering.
- **Asset-scoped event searches** — `query_events` accepts `asset_id` to
  retrieve events through the asset’s event connection.
- **Site-qualified references** — asset, event, vulnerability, policy, scan,
  group, and topology results retain their originating site for follow-up
  calls.

### Changed

- **Explicit single-site writes** — every write requires exactly one
  `site_uuid` or `site_name`; site arrays are not accepted for writes.
- **Single-site detail reads** — entity and detail tools require one explicit
  site selector.
- Multi-site pagination uses independent per-site cursors through
  `after_by_site`.

### Fixed

- Corrected site routing and pagination for `get_asset` and
  `get_asset_vulnerabilities`.
- Prevented asset UUIDs from being misused as free-text event searches.

## [0.4.5] 

### Added
- **Asset-scoped event queries** — `query_events(asset_id=...)` now traverses
  the asset's event connection while preserving filters and pagination.
- **Native CIDR asset filtering** — `query_assets(subnet=...)` validates CIDR
  input and translates it to Tenable's native inclusive IP-range filter.
- **Multi-site read fan-out** — collection, search, list, and summary tools
  accept `site_uuids` and query the selected ICPs with bounded concurrency.
  Responses retain per-site provenance, pagination state, and partial errors.
- **Qualified entity references** — asset, vulnerability, event, policy, scan,
  group, and topology results retain their originating site for safe follow-up
  detail calls.

### Changed
- **Explicit single-site writes** — every write tool now exposes exactly one
  `site_uuid` / `site_name` selector, routes mutations to that ICP, and records
  the resolved site in audit entries. Site arrays and implicit mutable site
  context are not supported for writes.
- Site-scoped detail reads consistently require a singular site selector;
  Enterprise Manager root inventory and connection status remain unscoped.

[Unreleased]: https://gitlab.com/jwalley/tenable-ot-mcp/-/compare/v0.4.1...main

## [0.4.1] - 2026-06-03

### Added
- **Cursor pagination on `query_assets`, `query_events`, and
  `query_vulnerabilities`** — each read tool now accepts an `after` page
  cursor and returns `end_cursor` alongside `has_more`. Walk a filtered
  result set larger than one page by passing the previous response's
  `end_cursor` as `after` until `has_more` is false. The GraphQL layer
  already selected the cursor; the tools now surface it. `total_count`
  continues to report the exact match count regardless of page size, so
  "how many" questions never required pagination.

### Changed
- Realigned the project version to **0.4.1** across `pyproject.toml`,
  `src/tenable_ot_mcp/__init__.py`, and the README changelog, which had
  drifted to 0.3.1 / 0.3.4 / 0.3.3 respectively.

[0.4.1]: https://gitlab.com/jwalley/tenable-ot-mcp/-/compare/v0.3.0...v0.4.1

## [0.3.0] - 2026-05-13

### Added
- **Full coverage of every group concept Tenable OT exposes** — eight first-class
  group types, each with create / update (or edit) / archive write tools plus
  paginated list, by-id get, and where Tenable exposes them, archived-list
  reads. Total addition: ~54 new tools, ~108 of the 114-tool surface in one new
  `tools/groups.py` module.
- **EmailGroup tools** — `create_email_group` / `update_email_group` /
  `archive_email_group`, `list_email_groups` / `get_email_group`, and
  `find_email_groups_using_smtp_server` for impact analysis before retiring
  an SMTP server. Recipient lists bound to SMTP servers, consumed by policy
  action configuration.
- **ScheduleGroup tools** — `create_schedule_group` / `update_schedule_group` /
  `archive_schedule_group`, plus `list_schedule_groups` /
  `list_archived_schedule_groups` / `get_schedule_group`. Polymorphic: choose
  one-shot windows (`start_time` + `end_time`), weekly recurring (`schedules`
  of `{day, start, end}` entries with natural day vocab — 'monday' /
  'every_day' / 'weekdays' / etc.), or system Function. Read tools surface
  subtype-specific fields via typed fragments.
- **TagGroup tools** — `create_tag_group` / `update_tag_group` /
  `archive_tag_group`, plus reads and the `list_eligible_tags` discovery
  helper that pages controller tags available to bundle. These are PLC
  controller-tag rollups (distinct from asset-grouping-with-displayTag);
  bound to TagValuePolicy.
- **RuleGroup tools** — `create_rule_group` / `update_rule_group` /
  `archive_rule_group`, plus reads. IDS rule SID bundles consumed by
  IntrusionPolicy; each read entry previews up to 25 included rules.
- **PortGroup and ProtocolGroup tools** — full CRUD + reads. Port-range and
  (protocol, port-range) bundles consumed by PortPolicy / ProtocolPolicy.
  ProtocolGroup items accept any of Tenable's ~50 ProtocolSuperType enum
  values (TCP, UDP, MODBUS, S7, IEC104, DNP3, PROFINET, CIP, ETHIP,
  IEC61850, etc.). Note Tenable's mutations are named `newPortList` /
  `newProtocolList`; the MCP surface uses `*_port_group` / `*_protocol_group`
  for cross-type consistency.
- **UserGroup and EmUserGroup tools** — `create_user_group` /
  `edit_user_group` / `archive_user_group` and EM-level variants for
  permission management. Args cover roles, user membership, zone access,
  and external auth-provider group bindings. `set_user_groups` /
  `set_em_user_groups` reassign a single user's group memberships in one
  call (full replacement).
- **Asset-group surface expanded to full Tenable parity** — the existing
  `create_asset_group` / `update_asset_group` tools now expose every
  `newAssetGroup` argument and every `AssetGroupType` enum value, including:
  `start_ip` / `end_ip` (IpRange), `asset_type` + `family` (TypeFamily),
  `vlan` (Segment), and `filter` (Filter expression tree). New `cidr`
  shorthand expands a CIDR like `10.2.9.0/24` to Tenable's IpRange shape.
  The 9 `AssetGroupType` enum values are now selectable; previously only 3
  were generated.
- **`bulk_set_asset_group_display_tag`** — toggle the UI-tag flag on or off
  across many asset groups in one call (wraps Tenable's
  `setAssetGroupsDisplayTag`).
- **Asset-group read tools** — `list_asset_groups` / `get_asset_group` /
  `list_archived_asset_groups`. Surface subtype-specific fields via typed
  fragments.

### Fixed
- **`create_asset_group` / `update_asset_group` no longer fail with
  `Cannot query field "description" on type "AssetGroup"`.** Tenable's
  `AssetGroup` is a polymorphic interface and `description` is only on
  the `SegmentGroup` subtype — selecting it on the abstract type fails
  GraphQL validation. The mutations now omit `description` from the
  return selection (it's input-only as far as the MCP is concerned).
  Read tools surface `description` via a typed `... on SegmentGroup`
  fragment where it's actually present.
- **`bulk_edit_assets` no longer fails with `Cannot query field "id" on
  type "BulkOpAssetsResult"`.** The pre-existing return selection of
  `{id name}` matched neither `BulkOpAssetsResult`'s shape (which is
  `{totalAssets, failedAssets}`) nor what the bulk-hide/bulk-restore
  siblings already used. Fixed to `{totalAssets, failedAssets}`.
- **`recalculate_asset_risk` no longer fails with `Cannot query field
  "name" on type "Job"`.** The pre-existing return selection of `{id
  name}` assumed an Asset return — but `recalculateAssetRisk` returns
  `Job`. Fixed to `{id status}`.
- **`define_active_scan` / `edit_active_scan` no longer fail with
  `Variable "$schedule" of type "ScheduleParams" used in position
  expecting type "[ScheduleParams!]"`.** Tenable's `createActiveQuery` /
  `editActiveQuery` mutations declare `schedule: [ScheduleParams!]`
  (array), not the scalar these tools were sending. Both schema and
  call sites updated to wrap the schedule in a single-element list.
  The per-type scan tools (`define_port_scan` etc.) were already
  correct; this was specific to the generic pair.

### Validated
- Every group-domain GraphQL mutation and query in this release was
  introspected against the Tenable OT schema. Both read shapes and
  every write mutation were live-verified against the dev TOTS
  deployment via two QA passes — first dry-run-preview-only against
  every tool's Python wrapper, then a deeper pass that sent each
  write mutation directly to Tenable's GraphQL endpoint with sentinel
  variables and classified the response. The five schema-mismatch
  bugs above were caught during the deeper pass and fixed before
  release.

[0.3.0]: https://gitlab.com/jwalley/tenable-ot-mcp/-/compare/v0.2.0...v0.3.0

## [0.2.0] - 2026-05-11

### Added
- **Asset property editing** — `update_asset`, `bulk_edit_assets`, `reset_asset_metadata`
  expose Tenable's `updateAssetWithRemove` / `bulkEditAssetsWithRemove` mutations
  through the natural-vocabulary tool surface. Operators can now fix names,
  reclassify types, set criticality / Purdue level, and assign custom-field
  values via any MCP-compatible AI client. `clear_fields` reverts an override
  to "as Tenable discovered".
- **Custom-field schema management** — `list_custom_fields`, `create_custom_field`,
  `rename_custom_field`, `delete_custom_field` manage Tenable's 10 fixed
  per-asset metadata slots. `delete_custom_field` requires
  `confirm_wipes_values=True` on top of `dry_run=False` because freeing a
  slot wipes its stored value on every asset that had it set.
- **Custom-field values surface in asset reads** — `query_assets` and
  `get_asset` now project custom-field values keyed by the operator's
  configured label, not the opaque slot id, via a 60-second module-level
  label cache that invalidates on any custom-field write.

### Fixed
- **`server.py` setup form** — narrow `FormData.get()` values via
  `isinstance(val, str)` before calling `.strip()`. A multipart POST with a
  file part named the same field would have crashed at runtime.
- **`main.py` uvicorn launch** — call `uvicorn.run(...)` with explicit named
  args in two branches (with/without TLS) instead of splatting a
  `dict[str, object]` whose splatted values failed mypy's per-parameter
  checks.

[0.2.0]: https://gitlab.com/jwalley/tenable-ot-mcp/-/compare/v0.1.0...v0.2.0

## [0.1.0] - 2026-05-08

First public release. **Open beta — please report bugs at
<https://gitlab.com/jwalley/tenable-ot-mcp/-/issues>** with steps to
reproduce when you can. Every tool has been live-verified against a
real Tenable OT deployment, but field exposure has been limited so
far.

MCP server exposing the Tenable OT Security GraphQL API to any
MCP-compatible AI client (Eymbr AI, Claude.ai / Claude Desktop,
ChatGPT, Cursor, Windsurf, custom agents).

### Tools

53 tools across 10 domains, all live-verified against a Tenable OT
deployment. Read tools register unconditionally; write tools register
only when the operator opts in at setup time and default to
`dry_run=true`.

- **Asset domain** — `query_assets`, `get_asset`, `get_asset_vulnerabilities`
- **Vulnerability domain** — `query_vulnerabilities`, `get_vulnerability`
- **Event domain** — `query_events`, `get_event`
- **Detection policies** — `list_detection_policies`, `query_policy_findings`
- **Network topology** — `list_segments_and_zones`, `get_communication_paths`
- **Sensor health** — `list_sensors`
- **Correlation (relational projections, not server-side analytics)** —
  `query_attack_pathways`, `query_vulnerability_clusters`,
  `query_temporal_patterns`, `get_asset_intelligence`
- **Summary** — `summarize_environment`
- **Active scans (define / inspect, never execute)** —
  `list_active_scans`, `get_active_scan`, `get_active_scan_executions`,
  the generic `define_active_scan` / `edit_active_scan` pair, per-type
  pairs with typed options (`define_port_scan` / `edit_port_scan`,
  `define_snmp_scan` / `edit_snmp_scan`,
  `define_controller_discovery_scan` / `edit_controller_discovery_scan`,
  `define_asset_discovery_scan` / `edit_asset_discovery_scan`,
  `define_inactive_probing_scan` / `edit_inactive_probing_scan`,
  `edit_subnets_discovery_scan`), and the lifecycle
  `enable_active_scan` / `disable_active_scan` / `delete_active_scan`.
  The server deliberately does not expose any tool that runs a scan —
  that's a human-only action via the Tenable OT UI, because active
  scanning has caused operational incidents on legacy PLCs in the wild.
- **Writes (opt-in, dry-run-default, audit-logged)** — hide / restore /
  remove assets, recalculate risk, asset-group CRUD (Tenable's
  organizational tags), single + bulk policy enable / disable /
  archive, resolve findings.

### Architecture

- **Stateless container.** Tenable OT data never lands on disk inside
  the server. Every tool call is a live GraphQL query.
- **Tools expose data; the AI does the analysis.** Correlation tools
  return joined relational data (assets and their links, vulns and
  their plugins, events and their policies). Attack-pathway analysis,
  vulnerability clustering, temporal correlation, and per-asset
  narratives are the AI's job — not the server's.
- **Natural-vocabulary tool surface.** Tools accept natural OT terms
  (`high`, `plc`, `controller`, `level1`) and translate to Tenable's
  internal enums (`HighCriticality`, `OtDevice`, etc.) inside. Future-
  proofs for Tenable enum renames and stays interoperable across
  multi-vendor backends.

### Security

- **HTTPS by default.** A self-signed certificate is auto-generated
  into the data volume on first start (covers `localhost`, `127.0.0.1`,
  `::1`, plus anything in `MCP_TLS_HOSTNAME`). Operators can replace
  with a CA-signed cert by dropping `cert.pem` / `key.pem` into the
  data volume, or set `MCP_TLS_CERT` / `MCP_TLS_KEY` to alternative
  paths. `MCP_TLS_DISABLE=1` falls back to plain HTTP for deployments
  with a TLS-terminating reverse proxy in front.
- **Single-token bearer auth.** A single token is issued at setup time
  and presented in the `Authorization: Bearer <token>` header.
  Capabilities follow `write_tools_enabled` from the setup wizard;
  there is no separate read/write token split (matches the model used
  by every production MCP server in the wild).
- **Encrypted config at rest.** `/data/config.enc` (Fernet, AES-128 +
  HMAC-SHA256) holds the Tenable OT URL, the Tenable OT API key, the
  bearer token, and the setup flags. The encryption key file
  (`/data/config.key`) is generated once on first start and never
  rotated by the server.
- **Append-only audit log.** Every write-tool invocation (including
  dry-run previews) is recorded in `/data/audit.jsonl` with timestamp,
  tool, parameters, dry-run flag, outcome, upstream Tenable OT status,
  and any error message. The server never reads this file back.
- **Apache 2.0 OSS hygiene.** SPDX headers on every source file,
  LICENSE / NOTICE / SECURITY / CONTRIBUTING / CODE_OF_CONDUCT in
  place, GitLab CI publishes the multi-arch image with SBOM,
  provenance, Trivy CVE scan, and cosign keyless signing on every
  tagged release.

### Standards

- Streamable HTTP transport (per the MCP spec).
- RFC 9728 OAuth 2.0 Protected Resource Metadata at
  `/.well-known/oauth-protected-resource`. With an empty
  `authorization_servers` list, this signals to compliant MCP clients
  that the server uses a static bearer token issued out-of-band rather
  than an OAuth flow.

### Setup

- First-run wizard at `/setup` that verifies connectivity to Tenable
  OT before saving config and generating the bearer token.
- Setup-complete page polls `/healthz` after the operator clicks
  Finish so the wizard waits for the post-restart MCP endpoint to
  come up.

[0.1.0]: https://gitlab.com/jwalley/tenable-ot-mcp/-/releases/v0.1.0
