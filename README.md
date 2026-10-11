## Enterprise Manager version of John Walley's Tenable OT MCP

**Version**: 0.5.3 (based on GitLab tenable-ot-mcp v0.4.5)  
**Upstream**: https://gitlab.com/jwalley/tenable-ot-mcp  
**Modified**: 2026-08-24

### EM-Specific Enhancements

- **Site routing**: All query tools support `site_uuid` / `site_name` parameters for EM relay
- **Short descriptions**: Reduced tool descriptions for faster MCP tool loading
- **Machine ID caching**: Automatic site name → machine ID resolution and caching
- **EM root queries**: `list_paired_icps` bypasses relay, queries EM directly
- **Subnet queries**: Assets can be queried by subnet, e.g. 10.253.10.128/25
- **Findings**: Vulnerability and policy findings can be queried

### Quick Start

Build the container:
```bash 
docker compose up -d --build --force-recreate tenable-ot
```
Verify
```bash
docker compose ps tenable-ot
docker compose logs --tail=100 tenable-ot
```
Suggested agent prompts are available in `prompt/`. Some smaller MOE models require more reinforcement.

The `prompt/` directory provides a simple unified prompt for smaller models such as Holo and Qwen 3.6-35B-A3B. Newer models such as Qwen 3.8-flash-next and Qwen 3.8-27B, as well as larger models such as Mistral-Medium-3.5-128, Claude and ChatGPT, can make use of the additional skills in `~/skills`.

### Tool List
A categorized tool list document is available in file `tot-mcp-tool-list.md`.

### Example Session
EXAMPLE_SESSION.md is a transcript of an example session with a Tenable OT system using demonstration data and a locally executing LLM (HCompany's Holo-35B-A3B) running on 2 Nvidia A6000's - it will give you a good sense of the capabilities of the MCP.

### Recent Updates (v0.5.0)

- Updated to upstream v0.4.5 baseline
- Added field selection infrastructure for vulnerability queries (reduces bandwidth)
- Version synchronization with upstream releases



### T1OTE Skills

Skills live in `skills/production/` (released) and `skills/staging/` (work in progress). Live copies are served from the LibreChat `skill/` folder and must match production.

| Skill | Loading | Purpose |
|---|---|---|
| `T1OTE-core-identity-and-routing` | always-apply | Identity, tool map, code-tool rules, skill loading order |
| `T1OTE-raise-fatality-flag` | always-apply | RAISE table via `raise_table.py` in `run_tools_with_bash` (`query_assets` only, `tool_manifest` as its own argument) |
| `T1OTE-asset-event-search-patterns` | always-apply | Asset and event search patterns |
| `T1OTE-attackers-view-diagram` | on demand | Attacker's view: counts and table are copied from the tool result, never recounted; RAISE grades come from the step 2 table (`get_asset` only for assets not in it); `force_through=true` when the user says to continue through no-path assets; Mermaid diagram pasted verbatim |
| `T1OTE-detailed-profile-and-analysis` | on demand | Detailed asset profile and analysis |
| `T1OTE-report-generation` | on demand | `asset_inventory` and `vulnerability_findings` reports; no discovery calls; always RAISE risk-grade columns |

Promote a skill by moving its folder from `staging/` to `production/` and syncing the live copy.
