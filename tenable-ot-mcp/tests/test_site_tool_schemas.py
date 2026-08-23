# SPDX-License-Identifier: Apache-2.0
"""Contract tests for site selectors exposed through MCP tool signatures."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from tenable_ot_mcp.tools import register_read_tools, register_write_tools


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **_kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeClient:
    async def resolve_site_machine_id(
        self,
        *,
        site_uuid: str | None,
        site_name: str | None,
    ) -> str:
        if site_uuid:
            return site_uuid
        if site_name:
            return f"resolved-{site_name}"
        raise ValueError("site_uuid or site_name is required")


class FakeAudit:
    def record(self, **_kwargs: Any) -> None:
        pass


def _parameters(fn: Any) -> set[str]:
    return set(inspect.signature(fn).parameters)


def test_all_site_scoped_reads_expose_a_site_selector() -> None:
    mcp = FakeMCP()
    register_read_tools(mcp, FakeClient(), FakeAudit())  # type: ignore[arg-type]

    em_root_tools = {"list_paired_icps", "tenable_ot_status"}
    for name, fn in mcp.tools.items():
        if name in em_root_tools:
            continue
        parameters = _parameters(fn)
        assert {"site_uuid", "site_name"} <= parameters, name


def test_collection_reads_expose_site_arrays() -> None:
    mcp = FakeMCP()
    register_read_tools(mcp, FakeClient(), FakeAudit())  # type: ignore[arg-type]

    collection_tools = {
        "query_assets",
        "list_custom_fields",
        "query_vulnerabilities",
        "query_events",
        "summarize_environment",
        "list_detection_policies",
        "query_policy_findings",
        "query_vulnerability_findings",
        "list_sensors",
        "list_active_scans",
        "list_segments_and_zones",
        "query_vulnerability_clusters",
        "query_temporal_patterns",
        "list_asset_groups",
        "list_email_groups",
        "list_schedule_groups",
        "list_tag_groups",
        "list_rule_groups",
        "list_port_groups",
        "list_protocol_groups",
        "list_user_groups",
        "list_em_user_groups",
    }
    for name in collection_tools:
        assert "site_uuids" in _parameters(mcp.tools[name]), name


def test_all_writes_require_one_site_and_never_expose_site_arrays() -> None:
    mcp = FakeMCP()
    register_write_tools(mcp, FakeClient(), FakeAudit())  # type: ignore[arg-type]

    for name, fn in mcp.tools.items():
        parameters = _parameters(fn)
        assert {"site_uuid", "site_name"} <= parameters, name
        assert "site_uuids" not in parameters, name


async def test_legacy_scan_write_routes_one_site_and_rejects_missing_site() -> None:
    mcp = FakeMCP()
    register_write_tools(mcp, FakeClient(), FakeAudit())  # type: ignore[arg-type]

    preview = await mcp.tools["enable_active_scan"](
        scan_id="scan-1", site_uuid="site-a", dry_run=True
    )
    assert preview["site_uuid"] == "site-a"

    with pytest.raises(ValueError, match="site_uuid or site_name is required"):
        await mcp.tools["enable_active_scan"](scan_id="scan-1", dry_run=True)
