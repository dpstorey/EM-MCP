---
name: asset-event-search-patterns
description: CIDR subnet asset searches, asset-scoped event searches, the retrieval/pagination pattern, and result-count handling. Always apply — nearly every query_assets/query_events call depends on these rules.
always-apply: true
---

# Asset and Event Search Patterns

## CIDR subnet searches

For an actual subnet, use `query_assets.subnet`.

Example:

```json
{
  "site_uuids": ["SITE-UUID-1", "SITE-UUID-2"],
  "subnet": "10.253.10.128/25",
  "limit": 100
}
```

Rules:

- Never put CIDR notation in `query_assets.search`.
- `search="10.253.10."` is textual and is not a subnet query.
- `subnet="10.253.10.128/25"` performs structured CIDR filtering.
- Subnet may be combined with vendor, kind, category, criticality, or hidden filters.
- Inspect results and errors for every requested site.

Set `hidden=false` by default when supported. Only include hidden assets
when explicitly requested. Prefix displayed hidden assets with `[Hidden]`.

## Event searches

For events associated with an asset, use `query_events.asset_id` with the
asset's originating site:

```json
{
  "site_uuid": "ASSET-SITE-UUID",
  "asset_id": "ASSET-UUID",
  "resolved": false,
  "limit": 500
}
```

Rules:

- Never put an asset UUID in `query_events.search`.
- Do not combine `asset_id` with free-text `search`.
- Preserve requested time, severity, type, policy, and resolved-state filters.
- If no time window was requested, do not invent one.
- Continue pagination when all events are requested.
- Compare `risk.unresolved_events`, `total_count`, and retrieved length separately.
- Do not claim those counts agree without checking.
- Never claim an asset has no events after only searching its UUID as free text — that is not the same as an `asset_id`-scoped query.

Preserve timestamps exactly. Flag significantly future-dated events as
possible device, sensor, clock, or data-quality anomalies.

## Retrieval pattern

For each request:

1. Apply the exact user scope and site selection.
2. Use structured parameters such as `subnet` and `asset_id`.
3. Include explicit site routing.
4. Read count and pagination data from the relevant tool.
5. Handle results:
   - 0: report no match; do not substitute another record.
   - 1–50: retrieve and present the requested results.
   - Over 50: report the count and ask whether to retrieve all unless already requested.
6. Inspect all multi-site results and errors.
7. Continue pagination until the requested scope is complete.
8. Retain record IDs and `site_uuid` for follow-up detail calls.

Do not use an asset query to estimate the count of an event or vulnerability query.

## Common Mistakes

- Never pass CIDR through `query_assets.search`; use `subnet`.
- Never pass an asset UUID through `query_events.search`; use `asset_id`.
- Never combine `query_events.asset_id` with free-text `search`.
- Never invent an event time window.
- Never ignore future timestamps.
- Never claim that an asset has no events after searching its UUID as free text.
