---
name: report-generation
description: Generating downloadable/branded/compliance reports via Tenable OT Print MCP, plus report retention/purge. Use for "report", "export", "download", "purge reports", or any Tenable OT Print MCP tool.
always-apply: false
---

# Report Generation

Use only when the user explicitly requests an HTML report, downloadable file,
branded report, or compliance report. Use Tenable OT Print MCP for this —
never author report HTML or Python yourself, and never run a
report-generation script through Workspace Shell MCP.

Site-scope language alone ("use this ICP for searches and reports") is
**not** a request to generate a report — only an explicit ask triggers this
skill. If a `submit_report_job` call fails validation (e.g. a missing
`asset_id`), do not resubmit the same call unchanged — fix the specific
parameter, or stop and tell the user the error instead of retrying blind.

Module choice: an "asset report" (all assets in a subnet or site) is module
`asset_inventory`; a "vulnerability findings report" is `vulnerability_findings`.
`risk_profile` is for ONE asset and needs `asset_id`; do not use it for a fleet.
Pass `site_name` (never a typed UUID) and `subnet` as returned by the user.

1. Establish the selected site(s) (site selection is handled in the base
   agent instructions — reuse the site already chosen in this conversation).
2. If unsure which report module fits the request, call `list_report_types`
   (and `list_available_columns` for a module with selectable columns,
   `list_themes` for available banners/colors).
3. Gather the data the chosen module needs — asset IDs, site UUIDs, and any
   other identifiers — the same way you would for a chat answer, with the
   same site-routing and pagination rules.
4. For `risk_profile` reports, check `list_risk_grade_scales` for an
   already-saved grading table (e.g. `"RAISE"`) before asking the user to
   repaste one. If none exists yet and the user provides one, save it once
   with `save_risk_grade_scale` so later reports can reference it by name
   (`risk_grade_scale_name`) instead of resending the whole table.
5. Call `submit_report_job` with the module, resolved parameters, and (if
   requested) a theme. Include only retrieved data — never invent or
   placeholder a value; Tenable OT Print MCP renders missing values as `-`.
6. Report back the exact output path(s) it returns. Do not re-verify the
   file's contents yourself (no `grep`/`sed`/`ls` checks) — rendering and
   validation are the server's responsibility, not yours.
7. Stop after delivery. Do not generate another report unless explicitly
   requested.

## Report retention / purge

- `set_report_retention_policy(mode, value)` saves a rule (`mode` one of
  `count`, `days`, `weeks`, `months`) — e.g. "keep the newest 10 reports"
  is `mode="count", value=10`.
- `get_report_retention_policy()` shows the currently saved rule, if any.
- `purge_reports(dry_run=true)` (the default) previews what the saved rule
  would delete — call this first and show the user what would go.
- Only call `purge_reports(dry_run=false)` after the user explicitly
  confirms, having seen the preview. This is a write — a delete is a
  write like any other; require explicit confirmation immediately before
  execution.
- If the user says something like "purge reports" or "trim reports" with
  no rule saved yet, ask what rule to save first — do not guess a default.

## Common Mistakes

- Never author report HTML or Python yourself, or run a report script through Workspace Shell MCP — use Tenable OT Print MCP's `submit_report_job`.
- Never reproduce the RAISE scoring matrix from memory in a chat answer — call `risk_profile` with `risk_grade_scale_name`.
- Never call `purge_reports` with `dry_run=false` without an explicit user confirmation on the preview.
- Never treat "use this ICP/site for searches and reports" as an implicit request to run a report.
- Never resubmit an identical `submit_report_job` call after it fails validation — fix the parameter or stop and report the error.
