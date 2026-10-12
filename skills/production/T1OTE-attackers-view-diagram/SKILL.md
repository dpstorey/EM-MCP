---
name: t1ote-attackers-view-diagram
description: "Running get_attackers_view: batch server-computed attack-path analysis, paused/no_path_found handling, RAISE lookup, and the mandatory Mermaid diagram. Use for 'attacker's view', 'attack path', or any get_attackers_view call."
always-apply: false
---

# Attackers View and Attack Path Diagram

> **Every Attackers View reply ends with the tool's own Mermaid diagram.**
> Order: run the tool, report counts, look up RAISE, render the Asset
> Summary table, then paste the `mermaid` field from the tool result
> verbatim. The reply is not done until the diagram is in it.
> Exceptions: if the user asked for the raw tool result, show that and skip
> the table, narrative and diagram; if the user does not want a diagram,
> call the tool with `include_diagram=false`.

**Counts and table (copy, never recount).**
- Quote counts straight from the result: `path_found` and `no_path_found`
  lengths, `processed_count`, `timeouts`, `errors`, and `summary`. Do not
  recount or estimate.
- The table has one row per distinct node in the diagram, hop assets
  included, sorted by score, highest first. End it with
  `Table rows: N of N diagram nodes`. Copy names and descriptions from the
  step 2 table or `get_asset` exactly; never retype from memory.
- If the user says to continue through no-path assets, pass
  `force_through=true` on the first call.

> ⚠️ `query_attack_pathways` and `get_attackers_view` are different tools.
> `query_attack_pathways` returns one asset's raw 1-hop comms neighbors —
> instant, no computation, the model does the path-finding itself.
> `get_attackers_view` triggers Tenable's own server-side attack-vector
> computation (generate → poll → fetch) across a batch of assets and
> returns already-computed, risk-ranked paths plus fleet-level analysis.
> Slow (seconds to minutes per asset), not free. Use `query_attack_pathways`
> for a quick single-asset neighbor check; use `get_attackers_view` when the
> user wants an actual attack path, or a CIDR/fleet-level view.

- **Site routing alone is NOT enough for this tool** — it also requires
  `cidrs` or `asset_ids`. Always pass `site_name` (exact name from
  `list_paired_icps`, e.g. `site_name="London"`) together with the scope.
- **Scope: use `cidrs`.** If the user's assets came from a subnet
  (e.g. `10.253.0.0/20`), pass that same CIDR as `cidrs=["10.253.0.0/20"]`;
  the server finds the assets itself. Set `max_assets` to at least the
  number of assets in scope (default is 50). Do NOT copy asset ids out of
  earlier results into `asset_ids`: hand-copied UUIDs get corrupted and
  those assets silently fail. Use `asset_ids` only for a short, explicit
  list the user named.
- Before running against a large scope, tell the user how many assets are
  in play and that this costs real time per asset (one mutation + poll +
  read each).
- Site-scope language alone ("use London ICP for searches and reports") is
  **not** a request to run this tool or generate a report — only an
  explicit ask ("generate an attackers view", "run a report") triggers
  either. Do not call `get_attackers_view` or `submit_report_job`
  speculatively off a scope-setting instruction.

## MANDATORY CHECK — before reporting results or calling this tool again

1. Inspect `paused`. If `true`, STOP. Do not call the tool again yet.
2. Report `paused_reason` and the counts so far (`path_found`,
   `no_path_found`, `timeouts`, `errors`) to the user in plain language.
3. Ask explicitly whether to continue through `remaining_asset_ids` or
   stop here. Only resume — and only if the user says to — by calling
   `get_attackers_view` with the SAME `cidrs`, `site_name` and
   `max_assets`, plus `offset=<next_offset from the result>` and
   `force_through=true`. Never retype `remaining_asset_ids`.
4. A `no_path_found` result (e.g. "asset not accessible - no
   conversations") is retrieved fact, not a failure — report it the same
   way you'd report zero events found. **Never** omit, soften, or retry
   it within the same turn; it will not change without new live traffic.
5. Quote every count and figure exactly from the result (`path_found`, `no_path_found`, `summary.*`); never recount or estimate them.
6. Report `summary.chokepoints`, `summary.riskiest_targets`, and
   `summary.stalest_paths` when present — that fleet-level synthesis is
   the point of this tool. Don't discard it for a flat list of raw paths.
7. Your reply is not complete until it contains, in this order: (a) the
   counts / paused report, (b) the diagram from "Attack Path Diagram"
   below, (c) the Asset Summary table. The diagram comes before the long
   table so it is never lost if the reply is cut short.

If a tool call fails validation (a required parameter missing, etc.),
do not resubmit the same call unchanged. Fix the specific missing/invalid
parameter, or if you can't determine it, stop and tell the user the error
instead of retrying blind.

## RAISE for Attackers View assets

`get_attackers_view` returns attack-path topology only — it does not carry
RAISE. To add it:

1. If a RAISE Asset Summary table from `raise_table` is already in this
   conversation, take each asset's grades, score, type and description from
   that table, matched by asset name. Do not call `get_asset` for any asset
   that is in the table.
2. For asset ids that are not in that table (hop assets outside the subnet,
   or every asset when no table exists), call `get_asset` once per asset, with
   the same `site_name` used for the Attackers View call. Collect these from
   the target(s) plus every `summary.chokepoints` entry (or every hop asset,
   if the user wants full path detail).
3. For assets you looked up, read `custom_fields["R"]`, `["A"]`, `["I"]`, `["S"]`, `["E"]` off each
   response, per the t1ote-raise-fatality-flag skill. Never derive a grade from
   `risk.total_risk` or invent one.
4. Render using the exact same Asset Summary table format and
   fatality-flag rules from t1ote-raise-fatality-flag — Attackers View does not
   get a different table shape.

## Attack Path Diagram

The tool draws it for you. Unless you passed `include_diagram=false`, the
result has a `mermaid` field: a ready-made `flowchart LR` of every
`path_found`, with chokepoints already highlighted (and any assets you asked
it to flag, see below). It is a required output whether or not the user asked for a
diagram.

- Paste `mermaid` verbatim inside a ```mermaid code fence, right after the
  counts and before the Asset Summary table. Do not redraw, rename, reorder, add, or remove anything.
  Output it ONCE. If you write a closing summary later (e.g. after
  generating reports), do not paste it again; say "diagram above".
- **Flagging.** The server knows nothing about RAISE. To highlight
  fatality-level assets in the diagram, pass `flag_field="S"` and
  `flag_values=["D","E"]` (the Safety grade rule from t1ote-raise-fatality-flag)
  on the `get_attackers_view` call. Pass both or neither; if the site uses a
  different field or scale, pass that instead. Flagged assets get a ⚠ in the
  diagram.
- `mermaid_flagged_asset_ids` lists the assets the server flagged. Your table
  flags by the same S rule. If the two disagree, say so; do not edit the
  diagram.
- If `mermaid` is null, tell the user why (`mermaid_note`). Do not
  hand-draw a replacement.
- If the user does not want a diagram, pass `include_diagram=false` when you
  call the tool.

## Common Mistakes

- Never confuse `query_attack_pathways` (instant, single-asset, no computation) with `get_attackers_view` (server-computed, batch, slow).
- Never silently continue past `paused: true` — report `paused_reason` and ask before resuming.
- Never treat a `no_path_found` outcome as an error to retry — report it as retrieved fact.
- Never leave RAISE columns blank/omitted in an Attackers View table: take them from the step-2 RAISE table, or from `get_asset` `custom_fields` for assets not in it.
- Never treat "use this ICP/site for searches and reports" as an implicit request to run an attackers view or a report.
- Never resubmit an identical tool call after it fails validation — fix the parameter or stop and report the error.
- Never finish an Attackers View reply without the diagram (unless the user asked for the raw result or no diagram), and never offer it as an optional next step.
- Never redraw, edit, or extend the `mermaid` field, and never add a second diagram, ASCII art, or arrow chain.
