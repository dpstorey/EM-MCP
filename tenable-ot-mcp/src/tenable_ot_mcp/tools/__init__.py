# SPDX-License-Identifier: Apache-2.0
"""Tool registration entry points.

Each tool module registers a group of related tools (assets, vulns,
events, etc.) and exposes a `register_*` function. The aggregator
functions below are called by `mcp_app.build_mcp_app`.

Read tools are always registered. Write tools register only when the
operator enabled them at setup time.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient


def register_read_tools(mcp: Any, client: TenableClient, audit: AuditLog) -> None:
    """Register all read-only tools."""
    from . import (
        assets,
        correlation,
        em,
        events,
        groups,
        policies,
        scans,
        sensors,
        status,
        summary,
        topology,
        vuln_findings,
        vulns,
    )

    assets.register_read_tools(mcp, client, audit)
    vulns.register_read_tools(mcp, client, audit)
    vuln_findings.register_read_tools(mcp, client, audit)
    events.register_read_tools(mcp, client, audit)
    policies.register_read_tools(mcp, client, audit)
    topology.register_read_tools(mcp, client, audit)
    sensors.register_read_tools(mcp, client, audit)
    correlation.register_read_tools(mcp, client, audit)
    summary.register_read_tools(mcp, client, audit)
    scans.register_read_tools(mcp, client, audit)
    groups.register_read_tools(mcp, client, audit)
    status.register_read_tools(mcp, client, audit)
    em.register_read_tools(mcp, client, audit)


def register_write_tools(mcp: Any, client: TenableClient, audit: AuditLog) -> None:
    """Register all write tools (gated by `write_tools_enabled` in config)."""
    from . import groups, scans, writes

    writes.register_write_tools(mcp, client, audit)
    scans.register_write_tools(mcp, client, audit)
    groups.register_write_tools(mcp, client, audit)
