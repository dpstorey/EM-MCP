# Tenable One OT Exposure MCP v1.1 Analysis Report

**Date:** 2026-07-27  
**Base Version:** EM-MCP-1.0 (based on GitLab tenable-ot-mcp v0.4.1)  
**Target Version:** EM-MCP-1.1 (updated to v0.4.5)  
**Analyst:** Claude Code (Sonnet 4.5)

---

## Executive Summary

This analysis reviews the Tenable One OT Exposure MCP server (originally forked from John Walley's tenable-ot-mcp), compares it against the upstream GitLab source (v0.4.5), evaluates Tenable OT API capabilities for potential enhancements, and provides architectural recommendations for splitting administrative vs. data query functions.

### Key Findings

1. **Version Gap**: Local source was at v0.4.1; GitLab upstream is at v0.4.5 (4 patch releases behind)
2. **Notable Enhancements in Upstream**:
   - Field selection whitelist for vulnerability queries (v0.4.5)
   - `tenable_ot_status` connectivity check tool (v0.4.2)
   - Lean default field set reduces bandwidth by ~4KB/vulnerability
3. **API Capabilities**: Tenable OT GraphQL API supports extensive filtering including CIDR-based queries through `IpSegmentArgs`
4. **Architecture**: Current monolithic design is appropriate; splitting is NOT recommended

---

## 1. Upstream Changes Analysis (v0.4.1 → v0.4.5)

### Version 0.4.5 (2026-07-21)

**Field Selection for Vulnerability Queries**
- Added whitelisted `fields` parameter to `query_vulnerabilities`
- Default lean column set excludes `description` and `solution` (~4KB per row)
- Whitelist registry maps natural names → GraphQL fields
- Prevents injection, reduces bandwidth for triage use cases

**Implementation**: 
```python
_FIELD_REGISTRY: dict[str, tuple[str | None, str | None]] = {
    "plugin_id": ("id", None),
    "description": (None, "description"),  # ~2KB
    "solution": (None, "solution"),          # ~2KB
    # ... 20+ fields total
}
```

**Status**: ✅ **APPLIED** - Field registry and helper functions added to `vulns.py`

---

### Version 0.4.4 (2026-07-17)

**Documentation Corrections**
- Tool count updated: **115 tools** (49 read, 66 write) 
- Bearer token terminology corrected (singular throughout)
- Multi-arch image support documented (`linux/amd64` + `linux/arm64`)

**Status**: ✅ **NOTED** - Documentation-only changes

---

### Version 0.4.3 (2026-07-17)

**Branding Updates**
- Setup wizard rebranded to eymbr visual identity
- Brand assets packaged under `src/tenable_ot_mcp/assets/`

**Status**: ⚠️ **NOT APPLICABLE** - Enterprise Manager fork maintains different branding

---

### Version 0.4.2 (2026-07-07)

**New Tool: `tenable_ot_status`**
- Appliance connectivity health check
- Reports: status, URL, latency, error reasons
- Useful for troubleshooting EM relay issues

**Status**: ✅ **APPLIED** - Copied from upstream source

**Implementation**:
- Added `connection_status()` method to `TenableClient`
- Copied `tools/status.py` from upstream
- Registered in `tools/__init__.py`
- Reports: connected (bool), tenable_url, latency_ms, error (string when disconnected)

---

### Version 0.3.0 (2026-05-13) - Critical Bugfixes

These were already incorporated into EM-MCP-1.0:

✅ `create_asset_group`/`update_asset_group`: Fixed GraphQL schema mismatch  
✅ `bulk_edit_assets`: Corrected return type  
✅ `recalculate_asset_risk`: Fixed return selection  
✅ `define_active_scan`/`edit_active_scan`: Fixed schedule parameter type  

---

## 2. Tenable OT API Capabilities Review

### CIDR Filtering Support

**Status**: ✅ **ALREADY AVAILABLE** via existing `query_assets` filter expressions

The Tenable OT GraphQL schema provides CIDR filtering through:

1. **`IpSegmentArgs`**: IP range specification for network-based queries
2. **`AssetExpressionsParams`**: Asset filtering with field-based expressions
3. **`NetworkUpdateInput`**: Network configuration with CIDR support

### Current MCP Implementation

The existing `query_assets` tool supports IP-based filtering via the expression builder:

```python
# From tools/_enums.py
expr("ips", EXPR_IN, ["10.2.9.0/24"])  # CIDR notation supported
```

**Example Use Case**:
```python
assets = await query_assets(
    site_uuid="abc-123",
    ips=["192.168.1.0/24", "10.0.0.0/8"]
)
```

### Missing API Functions (Potential Additions)

Based on API documentation review, the following capabilities exist in the API but are NOT exposed in the MCP:

1. **Asset Relationships - BACnet Specific**
   - `AssetRelationship` interface with `BacnetRelationshipDetails`
   - Useful for building control system dependency maps

2. **Attack Vector Analysis** 
   - `AttackVector` and `AttackVectorStep` for attack path queries
   - Currently available via `query_attack_pathways` but could be enhanced

3. **OT Agent Management**
   - Agent deployment, health monitoring, configuration
   - Relevant for distributed sensor deployments

4. **License Management**
   - License activation, capacity tracking
   - Administrative function for EM deployments

5. **Credential Management (Enhanced)**
   - Currently basic hide/restore/remove for assets
   - Could expose SNMP v2/v3, basic auth credential CRUD
   - **Security Note**: Requires careful audit logging

### Recommendation Priority

| Function | Priority | Rationale |
|----------|----------|-----------|
| `tenable_ot_status` | **HIGH** | Troubleshooting EM relay connectivity |
| BACnet relationship queries | **MEDIUM** | Niche use case, building automation focused |
| OT Agent management | **MEDIUM** | Useful for distributed deployments |
| Enhanced credential CRUD | **LOW** | Security-sensitive, audit overhead |
| License management | **LOW** | Rare operational need |

---

## 3. Enterprise Manager Enhancements

### Current EM Capabilities

The fork maintains critical EM-specific features:

1. **Site Routing**: `site_uuid` / `site_name` parameters on all query tools
2. **Machine ID Resolution**: Automatic cache of site name → machine ID
3. **EM Root Queries**: `list_paired_icps` bypasses relay, queries EM directly
4. **Short Descriptions**: Reduced tool descriptions for faster loading

### EM-Specific Gaps

**Multi-Site Bulk Operations**
- Current tools operate on one site at a time
- Bulk operations across multiple ICPs would require orchestration at client level

**Example Enhancement**:
```python
async def query_assets_multi_site(
    site_names: list[str],
    filters: dict
) -> dict[str, list]:
    """Query assets across multiple sites in parallel."""
    results = {}
    for site in site_names:
        results[site] = await query_assets(
            site_name=site,
            **filters
        )
    return results
```

**Recommendation**: Implement as higher-level tool or document pattern for AI agents to use

---

## 4. Architecture Analysis: Split vs. Monolithic

### Current Architecture

**Monolithic MCP Server**
- 115 tools in one service
- Read tools: always registered (49 tools)
- Write tools: opt-in at setup (66 tools)
- Single bearer token with capability flags

### Splitting Proposal Evaluation

**Option A: Administrative MCP + Data Query MCP**

#### Administrative Functions (26 tools)
- Asset group CRUD (8 tools)
- Email group CRUD (3 tools)
- Schedule group CRUD (3 tools)  
- Tag group CRUD (3 tools)
- Rule group CRUD (3 tools)
- Port/Protocol group CRUD (6 tools)

**Total**: ~26 write tools

#### Data Query Functions (89 tools)
- Assets (3 read + 3 write)
- Vulnerabilities (2 read)
- Events (2 read)
- Policies (2 read + 3 write)
- Topology (2 read)
- Sensors (1 read)
- Correlation (4 read)
- Scans (6 read + 15 write)
- Custom fields (4 write)
- Summary (1 read)
- EM (1 read)

**Total**: ~89 tools (49 read + 40 write)

### Recommendation: **DO NOT SPLIT**

#### Rationale

1. **Natural Coupling**: Asset management queries immediately follow administrative group creation
   ```python
   # Common pattern:
   create_asset_group(name="Critical PLCs", type="filter", ...)
   query_assets(group_id="new-group-id")  # Need data MCP immediately
   ```

2. **Authentication Overhead**: 
   - Two MCPs = two bearer tokens to manage
   - Two connection pools
   - Two setup wizards or shared config complexity

3. **Tool Discovery Burden**:
   - AI agents would need to know which MCP has which capability
   - Current design: one `list_tools()` call returns everything
   - Split design: Must query two MCPs, merge tool lists

4. **Write Tool Gating Already Exists**:
   - Current `write_tools_enabled` flag at setup provides separation
   - Read-only deployments already exclude 66 write tools
   - Splitting gains no additional security boundary

5. **Operational Complexity**:
   - Two containers to deploy, monitor, update
   - Two healthcheck endpoints
   - Two audit logs to aggregate

6. **API Semantic Coherence**:
   - Tenable OT itself treats these as one unified GraphQL API
   - Splitting would create artificial boundary not present in upstream

### Alternative: Enhanced Tool Categorization

Instead of splitting, improve tool discovery via metadata:

```python
@mcp.tool(
    title="Create asset group",
    category="administrative",
    subcategory="asset_groups",
    requires_write=True,
)
```

This allows AI agents to:
- Filter tools by category without splitting services
- Understand write vs. read without parsing descriptions
- Build specialized interfaces without architectural split

---

## 5. Applied Changes Summary

### Files Modified

1. **`src/tenable_ot_mcp/__init__.py`**
   - Updated `__version__ = "0.4.5"`

2. **`src/tenable_ot_mcp/tenable_client.py`**
   - Added `import time`
   - Added `async def connection_status()` method

3. **`src/tenable_ot_mcp/tools/status.py`** *(NEW FILE)*
   - Copied from upstream v0.4.5
   - Registers `tenable_ot_status` read tool

4. **`src/tenable_ot_mcp/tools/__init__.py`**
   - Added `status` module import
   - Registered `status.register_read_tools()`

5. **`src/tenable_ot_mcp/tools/vulns.py`**
   - Added `_FIELD_REGISTRY` whitelist (24 fields)
   - Added `_LIST_DEFAULT_FIELDS` lean default set
   - Added `_resolve_fields()` validator
   - Added `_build_selection()` GraphQL builder

### Integration Status

⚠️ **Partial Implementation** - Field selection infrastructure added but NOT integrated into `query_vulnerabilities` function signature/logic.

**Reason**: Without access to live Tenable OT instance for testing, full integration risks breaking existing functionality. The infrastructure is in place for completion.

**Next Steps**:
1. Add `fields: list[str] | None = None` parameter to `query_vulnerabilities`
2. Replace static `_QUERY_VULNS` with dynamic query builder
3. Test against live EM deployment
4. Verify backward compatibility (omitted `fields` → default lean set)

---

## 6. Recommendations

### Immediate (Priority 1)

1. ✅ **~~Implement `tenable_ot_status` Tool~~** - COMPLETED
   - Copied from GitLab v0.4.5 source
   - Critical for EM relay troubleshooting

2. **Complete Field Selection Integration**
   - Finish `query_vulnerabilities` signature update
   - Test against live deployment
   - Estimated effort: 1-2 hours + testing

3. **Update README.md**
   - Document EM-specific enhancements
   - Clarify fork relationship with upstream
   - Note short descriptions for faster tool loading

### Short Term (Priority 2)

4. **Add Multi-Site Query Helper**
   - Document pattern for parallel site queries
   - Consider higher-level tool for common use case

5. **Enhanced Tool Metadata**
   - Add category/subcategory fields
   - Improves AI agent tool discovery
   - No architectural changes required

### Long Term (Priority 3)

6. **BACnet Relationship Queries**
   - If building automation use cases emerge
   - Low priority unless specifically requested

7. **Upstream Sync Process**
   - Establish periodic review of GitLab releases
   - Maintain changelog of EM-specific deviations

---

## 7. Compatibility Matrix

| Component | EM-MCP-1.0 | EM-MCP-1.1 | GitLab v0.4.5 |
|-----------|------------|------------|---------------|
| Tenable OT API | ✅ | ✅ | ✅ |
| Enterprise Manager | ✅ | ✅ | ⚠️ Limited |
| Site routing (site_name/uuid) | ✅ | ✅ | ⚠️ Basic |
| Field selection (vulns) | ❌ | ⚠️ Partial | ✅ |
| tenable_ot_status | ❌ | ✅ | ✅ |
| Short descriptions | ✅ | ✅ | ❌ |
| 115 tools | ✅ | ✅ | ✅ |

---

## 8. Testing Recommendations

Before deploying EM-MCP-1.1 to production:

1. **Connectivity Tests**
   - EM root endpoint: `list_paired_icps`
   - ICP relay endpoint: `query_assets(site_name="Site-A")`
   - Machine ID caching: verify resolution and cache behavior

2. **Field Selection Tests** (once integrated)
   - Default fields: `query_vulnerabilities()` returns lean set
   - Custom fields: `query_vulnerabilities(fields=["plugin_id", "description"])`
   - Invalid fields: raises `ValueError` with valid options

3. **Backward Compatibility**
   - All existing query patterns work unchanged
   - No breaking changes to existing tools
   - Bearer token auth unchanged

4. **Performance Tests**
   - Large result sets with pagination
   - Multi-site queries (serial vs. parallel timing)
   - Field selection bandwidth comparison

---

## 9. Conclusion

The EM-MCP-1.1 update brings the local fork closer to upstream parity while maintaining critical Enterprise Manager enhancements. The monolithic architecture should be preserved—the existing write tool gating provides adequate separation without the operational overhead of splitting services.

Key priorities:
1. Complete `tenable_ot_status` implementation for troubleshooting
2. Finish field selection integration to reduce bandwidth
3. Maintain documentation of EM-specific features for future maintainers

The Tenable OT API already exposes CIDR filtering capabilities through existing expression builders—no new tools needed for network-based queries.

---

**Report prepared for**: David Storey  
**System**: M4 Max Mac (48GB), dual RTX 3090s  
**Context**: OT/ICS security, air-gapped deployments, local LLM infrastructure
