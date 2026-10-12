---
name: t1ote-raise-fatality-flag
description: RAISE grading (R/A/I/S/E) rules and the mandatory fatality-flag check, plus the fixed Asset Summary table format. Apply whenever any asset table, detailed profile, or RAISE grade is rendered, from any source (asset search, attacker's view, reports).
always-apply: true
---

# RAISE Grading and Fatality Flag

RAISE contains five independent A–E grades (R, A, I, S, E). Each dimension is scored
on its own A–E scale — **A is always lowest/best risk, E is always highest/worst
risk** for that dimension.

> ⚠️ "Grade A" (best risk) and "Category A" (Financial Cost) are different things.
> The letter A appears in both the grade scale and as the name of the Financial
> dimension — do not confuse them.

- Each of R, A, I, S, E is graded independently.
- **Never** derive one category from another, and **never** derive a grade from
  `risk.total_risk`.
- Render missing or invalid grades as `-`.
- Never reproduce the full RAISE scoring matrix (the grade-to-description text)
  from memory in a chat answer. It is saved server-side as the `"RAISE"`
  risk grade scale on Tenable OT Print MCP — for any full RAISE detail or
  description text, call `submit_report_job(module="risk_profile",
  risk_grade_scale_name="RAISE", ...)` and let it do the lookup. This keeps
  grade descriptions consistent and out of this skill.

## Where grades come from

RAISE grades live in Tenable custom fields labeled literally `R`, `A`, `I`, `S`,
`E`. `get_asset` surfaces them generically as `custom_fields["R"]`, `["A"]`,
`["I"]`, `["S"]`, `["E"]`. A present field shows its letter; an absent one
renders `-`. Never derive a grade from `risk.total_risk` or invent one.

Some tools (e.g. `get_attackers_view`) return topology only, with no RAISE —
if the user wants RAISE for those assets, call `get_asset` on each one
(same `site_uuid` as the originating call) and read `custom_fields` as above.

## Site column

`Site` is the site/ICP name resolved for this query (the exact `name` from `list_paired_icps`, e.g. `London`; the example rows below use `London` only as a sample) — via `list_paired_icps`, or otherwise already established from the `site_uuid` in scope for this call. It is never the asset's own `location` custom field (a separate per-asset attribute, e.g. `"LAB"`) — the two can coincidentally look alike, but they come from different sources. If the site name hasn't been resolved yet in this conversation, resolve it before rendering the table rather than defaulting to a per-asset field.

## RAISE grade extraction (MANDATORY CHECK)

**BEFORE rendering ANY asset table or detailed profile, read all five dimensions — R, A, I, S, E — from every asset's `custom_fields`.** This is a separate mandatory pass from the fatality check below, not a side effect of it: checking S for a fatality grade does not excuse skipping R, A, I, and E. A dimension actually present in `custom_fields` must appear in its own column; only a dimension genuinely absent from `custom_fields` renders as `-`. Run this pass for every asset in scope, not only the ones that turn out to be fatality-flagged — the two rows that need a fatality flag are not the only rows that need real grades.

## Fatality flag (MANDATORY CHECK)

**BEFORE rendering ANY asset table or detailed profile, scan EVERY row's `S` grade.**

Under the RAISE matrix, **BOTH of the following are fatality-level,
independently — check each asset against both, not just one:**

- **Safety (S) grade D** — "Very severe, fatality"
- **Safety (S) grade E** — "Disaster, multiple fatalities"

An asset is flagged if its S grade is D, **or** if its S grade is E — these
are two separate trigger conditions, not "D and then also somehow E."
Grade E is not a lesser case that D already covers; check for it
explicitly, the same as D. (This is tied to the RAISE matrix specifically —
if a saved `risk_grade_scale` under a different name/methodology is ever used
instead, check that table's own S column for "fatality"/"fatalities"
rather than assuming D/E.)

**Common Error:** Forgetting to check assets with S=E because they are not the
primary focus of the query or appear less critical than other assets.
**Do not skip any row.**

When a fatality-level grade is present:

- In the Asset Summary table, prefix that asset's `Asset` cell with
  `⚠️ FATALITY RISK — ` (e.g. `⚠️ FATALITY RISK — REACTOR`), in addition to
  its normal S column grade.
- In a Detailed asset profile, call out the specific dimension and grade
  under "RAISE detail" as a fatality-level safety risk requiring immediate
  attention, even if the user didn't ask for a risk narrative.
- If any asset in a multi-asset result has a fatality-level grade, say so
  plainly in your response text — before or after the table, not only
  inside a cell — so it can't be missed by skimming a long table.

## Asset Summary table format

**Ready-made table (required).** Do not build the table yourself and do not
call `query_assets` first: the code fetches the assets itself, so they never
pass through you. For any RAISE summary of a subnet or site, call the tool
`run_tools_with_bash` once with these arguments, using the exact site name (as
in `list_paired_icps`) and the CIDR from the user's request, and changing
nothing else:

```
{"code": "eval \"$(python3 /mnt/data/raise_table.py --bash-init)\"; raise_table \"London\" \"10.253.0.0/20\"",
 "tool_manifest": ["query_assets_mcp_tenable-ot-em"]}
```

`tool_manifest` is its own argument of the tool call, never text inside
`code`. Leave `timeout` out.

The tool result is hidden in a collapsed panel, so the user cannot see it
unless you write it out. After the call, your chat reply for this step must
contain the complete table: copy the tool output character for character,
from the first table line to the final `raise_table v…` line, before anything
else you write. A summary, a count or a list of the flagged assets is never a
substitute for the table. Never retype an asset name from memory; copy it.
Keep the `Rows:`, `Fatality-flagged` and version lines: they prove the table
is complete and current. After the copied output you may add only the step
marker the user asked for (for example `Step 2 complete`). Do not add a
second fatality list, commentary or a closing sentence, and do not re-sort,
re-type or complete any row. If the `Rows:` line reports a MISMATCH, say so
and do not present the table as complete.

If the call prints an `ERROR:` line, returns an error, or prints nothing, say
so in one line with the error text and stop. Do not try another way to get the
data: no other tools, no `bash_tool`, no `python3`, no report jobs, and never
build the table by hand.

The header row below is fixed. Reproduce it exactly — same 11 columns, same
names, same order, same left-to-right position for R, A, I, S, E. Never
rename, merge, reorder, drop, or add a column.

**Before generating the table, verify that every asset with S=D or S=E has the "⚠️ FATALITY RISK — " prefix in the Asset column.**

```markdown
| Site | Asset | IP Address | Asset Type | Numerical Risk Score | Description | R | A | I | S | E |
|---|---|---|---|---:|---|:---:|:---:|:---:|:---:|:---:|
| London | ⚠️ FATALITY RISK — REACTOR | 10.253.10.244 | PLC | 52.4 | - | A | D | C | D | E |
| London | ⚠️ FATALITY RISK — PMC-01 | 10.253.10.252 | Controller | 33.5 | - | B | B | B | E | A |
| London | I/O #204 | 10.253.10.10 | I/O | 34.0 | - | - | - | - | - | - |
```

Map returned name, IPs, type, `risk.total_risk` to one decimal, description or `-`, and independent RAISE grades.

Keep rows short:

- Sort rows by `Numerical Risk Score`, highest first, unless the user asked for another order.
- `IP Address`: show the first IP only.
- `Description`: at most 40 characters; cut longer text at 40 and end with `…`. Use `-` when empty.

Rules:

- **Scope:** for a RAISE summary of a subnet, site or asset list, the table has one row for EVERY asset in that scope (all of them, not only the fatality or chokepoint ones). Never replace it with a shortened table or prose. If you cannot list every asset, say which ones are missing and why. The attackers view has its own table of the assets on the found paths; it does not replace this one.
- R, A, I, S, E are five separate columns in the header row above, each holding exactly one character (a letter grade or `-`). There is no sixth "RAISE" column and no merged column.
- Do not combine the five grades into one cell or one column under any label — not `"R:B, A:B, I:B, S:E, E:A"`, not `"B/B/B/A/E"`, not a column titled `"RAISE Grades"` or `"RAISE Grades (R/A/I/S/E)"` or any other combined phrasing. If you find yourself writing a slash, colon, or comma between grade letters, stop — that means they were merged into one column and need to be split back into the five columns above.
- A missing or ungraded dimension is exactly `-` (one hyphen character) in its own R/A/I/S/E cell — never "Not available", "N/A", "None", "Unknown", or any other word.
- Apply this per cell, not per row: an asset with some dimensions graded and others not shows real grades and `-` side by side in the same row, exactly as in the example above.
- Do not add columns that are not in the header row (e.g. `Vendor`), and do not drop `Site` or `Description` to make room for one.
- `Asset Type`: show the value the tool returned, except upper-case these three: `Plc` → `PLC`, `Io` → `I/O`, `Hmi` → `HMI`. Leave every other value unchanged (e.g. `OtServer`, `NetworkDevice`).
- The separator row must have exactly as many `---`/`:---:`/`---:` groups as the header has columns (11, for this table). Keep the alignment markers (`:---:` for R/A/I/S/E, `---:` for the numeric score) rather than collapsing them to plain `---` — dropping them has been observed to cause a miscounted, mismatched separator row that breaks table rendering.
- `⚠️ FATALITY RISK — ` prefixed to `REACTOR`'s and `PMC-01`'s `Asset` cells above is intentional, not an error. Note they trigger on *different* grades (`REACTOR` on S:D, `PMC-01` on S:E) — both grades flag independently, side by side in the same table. It applies only to the `Asset` column, alongside the normal RAISE grade columns, never in place of them.

Do not wrap the completed table in a code fence or artifact container.

## Common Mistakes

- Never skip checking any row's S grade for fatality flag — scan EVERY asset, not just the most prominent ones.
- Never leave RAISE columns blank/omitted without checking each asset's `custom_fields` via `get_asset` first.
- Never combine the five RAISE grades into one cell or column.
- Never drop the alignment colons on the R/A/I/S/E separator-row cells.

