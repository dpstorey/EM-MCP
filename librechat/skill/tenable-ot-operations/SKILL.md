---
name: tenable-ot-operations
description: Use for all Tenable OT and Tenable One requests that select an ICP, query assets, vulnerabilities or events, manage result limits, preserve filters, or perform read or write operations through tot-mcp.
---

# Tenable OT Operations

Use `tot-mcp` as the sole source of live Tenable OT and Tenable One data.

## Non-negotiable rules

1. Never invent assets, vulnerabilities, CVEs, addresses, hostnames, events, ICPs, counts, or tool results.
2. Do not use model knowledge as a substitute for data that should come from `tot-mcp`.
3. Preserve every user-supplied filter, search term, scope, ICP choice, and result limit. Never silently broaden a query.
4. Set `hidden=false` unless the user explicitly asks for hidden assets. Prefix every displayed hidden asset with `[Hidden]`.
5. State clearly when data is unavailable, incomplete, or a tool call fails.
6. Keep facts separate from analysis. Label any necessary assumption explicitly.
7. Do not recommend remediation unless the retrieved evidence supports it.

## ICP selection

Before the first asset, vulnerability, or event query in a session:

1. Check whether an ICP has already been selected.
2. If an ICP is selected, reuse it unless the user asks to change it.
3. If no ICP is selected:
   - Query Enterprise Manager for available ICPs.
   - Show the returned names and IDs in a markdown table.
   - Ask the user to choose one.
   - Stop. Do not run the requested data query until the choice is confirmed.

Do not infer an ICP from geography or previous knowledge unless the user or current session has explicitly selected it.

## Read-query workflow

For each asset, vulnerability, or event request:

1. Build the query using the user's exact filters.
2. Apply any explicit user limit, such as `num_assets=50`, as a hard upper bound.
3. Run a count request first using `limit=1` and the same filters.
4. Read `total_count` and follow the matching branch below.

### Result handling

- **0-10 results:** Retrieve and return the complete result set inline.
- **11-500 results:**
  - Tell the user the exact count.
  - If `continue=false`, ask for confirmation before multi-page retrieval and stop.
  - If `continue=true`, retrieve automatically.
  - Cache the complete JSON result at `/llm-scratch/asset_query_cache.json`.
  - Return a concise inline summary rather than printing every record.
- **More than 500 results:**
  - Tell the user the exact count.
  - Suggest useful narrowing filters such as network, asset type, criticality, or time range.
  - Ask for explicit confirmation or narrower scope.
  - Stop before retrieving the dataset.

If an explicit user limit is lower than `total_count`, use the requested limit when deciding how many records to retrieve, but still report the full matching count when useful.

## Pagination

When retrieval is authorised:

1. Request no more than 500 records per page.
2. Preserve the identical filters on every page.
3. Continue until `has_more=false` or the user's explicit limit is reached.
4. Check for duplicate or missing pages before presenting totals.

## Continue flag

- Initialise `continue=false`.
- Set it to `true` only when the user explicitly says `set continue flag`.
- With `continue=false`, request confirmation before any multi-page retrieval.
- With `continue=true`, read-only retrieval of up to 500 records may proceed automatically.
- The flag never authorises write operations or retrieval beyond 500 records.

## Write operations

Before any action that changes data, configuration, or system state:

1. Describe the exact proposed action and scope.
2. Ask for explicit user confirmation.
3. Stop until confirmation is received.

Never treat a prior general approval or the continue flag as approval for a write operation.
