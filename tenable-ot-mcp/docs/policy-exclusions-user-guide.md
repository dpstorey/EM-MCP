# Tenable OT MCP — Policy Exclusions User Guide

_Reference for the policy-tuning / exclusion tools in `tenable-ot-mcp`. Current as of 2026-08-28._

Detection policies (e.g. "Connections TO external network", "HTTP Communications to Controllers") fire on real traffic patterns, but some of that traffic is authorized baseline noise — a known vendor telemetry link, a trusted external DNS resolver, routine NTP. An **exclusion** is a standing tuning rule on one policy that suppresses matching traffic so it stops generating findings, without disabling the policy for everything else.

Four tools cover the exclusion lifecycle: list what's already excluded, create a new exclusion on either of the two policy families that support one, and delete one that's no longer needed.

| Tool | Type | Purpose |
|---|---|---|
| `list_policy_exclusions` | read | Show the active exclusions on one policy. |
| `create_activity_exclusion` | write | Add an exclusion to a network/activity policy. |
| `create_conversation_exclusion` | write | Add an exclusion to an unauthorized-conversation policy. |
| `delete_exclusion` | write | Remove an existing exclusion from a policy. |

All four sit alongside the existing policy tools (`list_detection_policies`, `query_policy_findings`) in `policies.py` / `writes.py`, and follow this server's standard conventions: read tools accept `site_uuid`/`site_name`/`site_uuids`; write tools accept `site_uuid`/`site_name` (exactly one site, no fan-out) and default to `dry_run=true`.

---

## `list_policy_exclusions` — see what's already excluded

```
list_policy_exclusions(policy_id, site_uuid=None, site_name=None, site_uuids=None)
```

| Argument | Type | Required | Notes |
|---|---|---|---|
| `policy_id` | string | yes | The detection policy to inspect. |
| `site_uuid` / `site_name` | string | no | Target one ICP. Auto-resolves if only one site is paired. |
| `site_uuids` | array | no | Fan out across multiple sites. Cannot be combined with `site_uuid`/`site_name`. |

Returns `policy_id`, `policy_title`, `count`, and `exclusions` — each exclusion node carries `id`, `type`, `comment`, `created`, `createdBy`, plus type-specific fields (`srcIp`/`dstIp` for an activity exclusion, a joined `assets` list for an asset exclusion). The `id` field is what you pass to `delete_exclusion`.

Always check this before creating a new exclusion — it avoids proposing a duplicate tuning rule for traffic that's already excluded.

---

## `create_activity_exclusion` / `create_conversation_exclusion` — add an exclusion

```
create_activity_exclusion(policy_id, src_ip=None, dst_ip=None, comment=None,
                           src_assets=None, dst_assets=None,
                           site_uuid=None, site_name=None, dry_run=True)

create_conversation_exclusion(policy_id, src_ip=None, dst_ip=None, comment=None,
                               src_assets=None, dst_assets=None,
                               site_uuid=None, site_name=None, dry_run=True)
```

Same signature, same behavior — the only difference is which Tenable mutation each one calls, because Tenable models activity-policy tuning and conversation-policy tuning as two separate exclusion types:

| Use this tool for policies like… | Not this one |
|---|---|
| `create_activity_exclusion` — "Connections TO external network", "Connections FROM external network" and other network/activity policies | `create_conversation_exclusion` |
| `create_conversation_exclusion` — "HTTP Communications to Controllers" and other unauthorized-conversation policies | `create_activity_exclusion` |

Calling the wrong one for a given policy's category is the most likely way this pair of tools misbehaves — check the policy's category (via `list_detection_policies`) if you're not sure which family it belongs to.

| Argument | Type | Required | Notes |
|---|---|---|---|
| `policy_id` | string | yes | The policy to add the exclusion to. |
| `src_ip` / `dst_ip` | string | no | Match on a specific source/destination IP. |
| `src_assets` / `dst_assets` | array of asset IDs | no | Match on specific source/destination assets, as an alternative or supplement to IP. |
| `comment` | string | no, but strongly recommended | Freeform justification. Not enforced by the tool, but every existing exclusion pattern (and the `tenable-policy-tuner` skill below) treats this as mandatory — a future analyst needs to know *why* the traffic was excluded. |
| `site_uuid` / `site_name` | string | no | Target site. Auto-resolves on a single-site deployment. |
| `dry_run` | bool | no, default `true` | See "Dry-run and safety" below. |

The exact matching semantics of combining IP and asset fields together are Tenable's own GraphQL mutation behavior (`newActivityExclusion` / `newConversationExclusion`), not something this wrapper computes — if the precise interaction isn't obvious from a test call's result, check Tenable OT's own policy-tuning UI/docs for how the platform itself interprets a combined filter.

---

## `delete_exclusion` — remove an exclusion

```
delete_exclusion(policy_id, exclusion_id, site_uuid=None, site_name=None, dry_run=True)
```

| Argument | Type | Required | Notes |
|---|---|---|---|
| `policy_id` | string | yes | The policy the exclusion belongs to. |
| `exclusion_id` | string | yes | From `list_policy_exclusions`' `id` field — not the policy id. |
| `site_uuid` / `site_name` | string | no | Target site. |
| `dry_run` | bool | no, default `true` | See below. |

Once deleted, the policy resumes firing on traffic that was previously suppressed — confirm that's actually wanted (traffic patterns can outlive the reason they were tuned out).

---

## Dry-run and safety

Every write tool here defaults to `dry_run=true`, matching every other write tool in this server: the first call returns the planned mutation as JSON without sending it to Tenable OT. Only call again with `dry_run=false` after the plan has been shown to and approved by whoever's asking for the change. Every call — preview or applied — is recorded in `/data/audit.jsonl`.

There's currently no `create_asset_exclusion` tool — an asset-type exclusion can be listed and deleted through these tools, but not created through this server today. Creating one still requires Tenable's own UI/API until that tool is added.

---

## Recommended workflow — the `tenable-policy-tuner` skill

`skills/tenable-policy-tuner.md` packages these tools into a guided threat-hunting workflow for an AI client that supports skills, rather than expecting an operator to call each tool by hand. It enforces a strict order:

1. **Observe** — `query_policy_findings` to pull recent hits for a policy and inspect the traffic.
2. **Identify** — separate genuine anomalies from high-frequency benign pairs (known vendor telemetry, routine NTP, etc.).
3. **Verify** — `list_policy_exclusions` to confirm the benign traffic isn't already excluded.
4. **Consult (mandatory)** — present the findings and proposed exclusions to the user; explicitly ask for confirmation before proceeding. The skill will not move to the next step without it.
5. **Execute** — `create_activity_exclusion` (or `create_conversation_exclusion`), with a specific `comment`, `dry_run=false` only once approved.

`delete_exclusion` is the rollback path if a tuning rule turns out to be wrong.

The skill's core rule is worth keeping even outside the skill itself: **never create an exclusion without an explicit human decision on that specific traffic** — the tools make it easy to suppress noise, but suppressing the wrong thing hides a real signal.

---

## Known gotchas, worth remembering

- **Activity vs. conversation is not interchangeable** — pick the tool that matches the policy's category, not whichever name sounds closer to the traffic you're describing.
- **`exclusion_id` ≠ `policy_id`** — `delete_exclusion` needs the exclusion's own id from `list_policy_exclusions`, not the policy's id.
- **No asset-exclusion creation yet** — `AssetExclusion` nodes are readable/deletable but not creatable through this server.
- **`comment` isn't enforced but should never be skipped** — an exclusion with no rationale is a future audit problem.
- **`dry_run` defaults to `true` everywhere** — same rule as every other write tool in this server; always show the preview and get a decision before re-calling with `dry_run=false`.
