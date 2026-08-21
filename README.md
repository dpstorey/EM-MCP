## Enterprise Manager version of John Walley's Tenable OT MCP

**Version**: 1.28.1 (based on GitLab tenable-ot-mcp v0.4.5)  
**Upstream**: https://gitlab.com/jwalley/tenable-ot-mcp  
**Modified**: 2026-07-27

### EM-Specific Enhancements

- **Site routing**: All query tools support `site_uuid` / `site_name` parameters for EM relay
- **Short descriptions**: Reduced tool descriptions for faster MCP tool loading
- **Machine ID caching**: Automatic site name → machine ID resolution and caching
- **EM root queries**: `list_paired_icps` bypasses relay, queries EM directly

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
Use the prompt in `prompt/AGENT.md` 

### Tool List
A categorized tool list document is available in file `tot-mcp-tool-list.md`.

### Recent Updates (v1.1)

- Updated to upstream v0.4.5 baseline
- Added field selection infrastructure for vulnerability queries (reduces bandwidth)
- Version synchronization with upstream releases

See `ANALYSIS.md` for detailed change log and architecture recommendations

