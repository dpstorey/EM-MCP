# SPDX-License-Identifier: Apache-2.0
"""Regression tests for site-routed single-asset reads."""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools.assets import CustomFieldLabelCache, register_read_tools

# `site_uuids` (plural) is validated as well-formed UUIDs by the real
# `_normalise_site_ids` (unlike singular `site_uuid`, which routes through
# the mocked `FakeClient.resolve_site_machine_id` below and never touches
# that validation), so fixtures exercising it need UUID-shaped ids.
SITE_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SITE_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **_kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeClient:
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self.responses = responses
        self.resolve_calls: list[dict[str, str | None]] = []
        self.query_calls: list[dict[str, Any]] = []

    async def resolve_site_machine_id(
        self,
        *,
        site_uuid: str | None,
        site_name: str | None,
    ) -> str:
        self.resolve_calls.append({"site_uuid": site_uuid, "site_name": site_name})
        return site_uuid or f"resolved-{site_name}"

    async def query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        icp_machine_id: str | None = None,
    ) -> dict[str, Any]:
        self.query_calls.append(
            {
                "query": query,
                "variables": variables,
                "icp_machine_id": icp_machine_id,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture(autouse=True)
def clear_custom_field_cache() -> None:
    CustomFieldLabelCache.invalidate()


async def test_get_asset_vulnerabilities_routes_site_and_paginates() -> None:
    client = FakeClient(
        [
            {
                "asset": {
                    "plugins": {
                        "nodes": [],
                        "totalCount": 501,
                        "pageInfo": {"hasNextPage": True, "endCursor": "next-page"},
                    }
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset_vulnerabilities"](
        asset_id="asset-1",
        site_uuid="site-uuid",
        limit=500,
        after="current-page",
    )

    assert client.resolve_calls == [{"site_uuid": "site-uuid", "site_name": None}]
    assert client.query_calls[0]["variables"] == {
        "id": "asset-1",
        "pageSize": 500,
        "after": "current-page",
    }
    assert client.query_calls[0]["icp_machine_id"] == "site-uuid"
    assert result["has_more"] is True
    assert result["end_cursor"] == "next-page"


async def test_get_asset_routes_site_for_asset_and_custom_fields() -> None:
    client = FakeClient(
        [
            {"asset": {"id": "asset-1", "name": "PLC 1"}},
            {"customFields": []},
            {"asset": {"backplane": None}},
            {"asset": {"details": {}}},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](asset_id="asset-1", site_name="Plant A")

    assert client.resolve_calls == [{"site_uuid": None, "site_name": "Plant A"}]
    assert [call["icp_machine_id"] for call in client.query_calls] == ["resolved-Plant A"] * 4
    assert result["asset"]["id"] == "asset-1"
    assert result["asset"]["asset_ref"] == {
        "site_uuid": "resolved-Plant A",
        "asset_id": "asset-1",
    }


async def test_query_assets_fans_out_and_preserves_site_provenance() -> None:
    client = FakeClient(
        [
            {
                "assets": {
                    "nodes": [{"id": "asset-a", "name": "PLC A"}],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-a"},
                }
            },
            {"customFields": []},
            {
                "assets": {
                    "nodes": [{"id": "asset-b", "name": "PLC B"}],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_assets"](
        site_uuids=[SITE_A, SITE_B, SITE_A],
        after_by_site={SITE_A: "previous-a"},
    )

    assert result["sites_requested"] == 2
    assert result["sites_succeeded"] == 2
    assert result["sites_failed"] == 0
    by_site = {entry["site_uuid"]: entry for entry in result["results"]}
    assert by_site[SITE_A]["assets"][0]["asset_ref"] == {
        "site_uuid": SITE_A,
        "asset_id": "asset-a",
    }
    assert by_site[SITE_B]["assets"][0]["site_uuid"] == SITE_B
    asset_queries = [call for call in client.query_calls if "assets(" in call["query"]]
    assert asset_queries[0]["variables"]["after"] == "previous-a"
    assert "after" not in asset_queries[1]["variables"]


async def test_query_assets_translates_subnet_to_native_ip_range() -> None:
    client = FakeClient(
        [
            {
                "assets": {
                    "nodes": [{"id": "asset-1", "ips": {"nodes": ["10.253.10.244"]}}],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_assets"](
        site_uuid="site-a",
        subnet="10.253.10.128/25",
    )

    assert client.query_calls[0]["variables"]["filter"] == {
        "field": "ips",
        "op": "Between",
        "values": ["10.253.10.128", "10.253.10.255"],
    }
    assert result["assets"][0]["ips"] == ["10.253.10.244"]


async def test_query_assets_rejects_invalid_subnet() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="invalid subnet CIDR"):
        await mcp.tools["query_assets"](site_uuid="site-a", subnet="10.253.10.999/25")


async def test_multi_site_read_returns_partial_failures() -> None:
    client = FakeClient(
        [
            RuntimeError("site unavailable"),
            {
                "assets": {
                    "nodes": [],
                    "totalCount": 0,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_assets"](site_uuids=[SITE_A, SITE_B])

    assert result["sites_succeeded"] == 1
    assert result["sites_failed"] == 1
    assert result["errors"] == [{"site_uuid": SITE_A, "error": "site unavailable"}]


async def test_multi_site_selector_rejects_conflicting_inputs() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cannot be combined"):
        await mcp.tools["query_assets"](
            site_uuid="site-a",
            site_uuids=["site-b"],
        )


async def test_list_custom_fields_routes_across_sites() -> None:
    client = FakeClient(
        [
            {
                "customFields": [
                    {
                        "fieldId": "customField1",
                        "userDefinedName": "Plant",
                        "valueType": "PlainText",
                    }
                ]
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["list_custom_fields"](site_uuids=[SITE_A, SITE_B])

    assert result["sites_succeeded"] == 2
    assert [call["icp_machine_id"] for call in client.query_calls] == [
        SITE_A,
        SITE_B,
    ]


async def test_get_asset_includes_backplane_modules() -> None:
    client = FakeClient(
        [
            {"asset": {"id": "plc-1", "name": "REACTOR"}},
            {"customFields": []},
            {
                "asset": {
                    "backplane": {
                        "id": "bp-1",
                        "name": "Chassis 1",
                        "size": 2,
                        "assets": {
                            "totalCount": 3,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [
                                {
                                    "id": "plc-1",
                                    "slot": 0,
                                    "type": "Controller",
                                    "model": "1769-L19ER-BB1B",
                                    "firmwareVersion": "35.011",
                                    "ips": {"nodes": ["10.0.0.5"]},
                                },
                                {"id": "io-2", "slot": 2, "type": "I/O Module"},
                                {"id": "io-1", "slot": 1, "type": "I/O Module", "firmwareVersion": "35.011"},
                            ],
                        },
                    }
                }
            },
            {"asset": {"details": {}}},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](asset_id="plc-1", site_uuid="site-uuid")

    bp = result["asset"]["backplane"]
    assert (bp["id"], bp["size"], bp["module_count"], bp["has_more"]) == ("bp-1", 2, 3, False)
    assert [(m["slot"], m["asset_id"]) for m in bp["modules"]] == [
        (0, "plc-1"),
        (1, "io-1"),
        (2, "io-2"),
    ]
    assert bp["modules"][0]["model"] == "1769-L19ER-BB1B"
    assert bp["modules"][0]["ips"] == ["10.0.0.5"]
    assert bp["modules"][1]["firmware_version"] == "35.011"
    assert client.query_calls[2]["variables"] == {"id": "plc-1", "pageSize": 100}


async def test_get_asset_backplane_null_when_not_on_backplane() -> None:
    client = FakeClient(
        [
            {"asset": {"id": "pc-1"}},
            {"customFields": []},
            {"asset": {"backplane": None}},
            {"asset": {"details": {}}},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](asset_id="pc-1", site_uuid="site-uuid")

    assert result["asset"]["backplane"] is None
    assert "backplane_error" not in result["asset"]


async def test_get_asset_survives_backplane_query_failure() -> None:
    from tenable_ot_mcp.tenable_client import TenableError

    client = FakeClient(
        [
            {"asset": {"id": "pc-1", "name": "HMI"}},
            {"customFields": []},
            TenableError("Cannot query field 'slot' on type 'BackplaneEdge'"),
            {"asset": {"details": {}}},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](asset_id="pc-1", site_uuid="site-uuid")

    assert result["asset"]["id"] == "pc-1"
    assert result["asset"]["backplane"] is None
    assert "BackplaneEdge" in result["asset"]["backplane_error"]


def test_hardware_state_decoding() -> None:
    from tenable_ot_mcp.tools.assets import _decode_hardware_state, _project_asset

    assert _decode_hardware_state("EndOfLife") == "End Of Life"
    assert _decode_hardware_state("Discontinued") == "Discontinued"
    assert _decode_hardware_state("Active") == "Active"
    assert _decode_hardware_state("UnknownState") is None
    assert _decode_hardware_state(None) is None
    assert _decode_hardware_state("SomethingNew") == "SomethingNew"

    out = _project_asset(
        {"id": "a", "hardwareState": "Discontinued", "serial": "SN1",
         "discontinuedDate": "2024-01-01T00:00:00Z", "replacementProduct": "S7-1500"}
    )
    assert out["hardware_state"] == "Discontinued"
    assert (out["serial"], out["replacement_product"]) == ("SN1", "S7-1500")


_DETAILS = {
    "names": [{"source": "Wmi", "value": "VENG01"}],
    "hardware": {
        "csManufacturer": "VMware, Inc.",
        "csModel": "VMware7,1",
        "cpu": "Intel(R) Core(TM) i9",
        "cpuSpeed": 2400,
        "numOfProcessors": "2",
        "totalPhysicalMemory": 17178845184,
        "biosVersion": "VMW71",
        "devicesAndDrives": [
            {"name": "", "capacity": 428807831552, "driveLetter": "C:", "deviceType": "Local Disk"}
        ],
    },
    "usb": [{"name": "USB Input Device", "pnpDeviceId": "USB\\VID_0E0F"}],
    "snmp": {"Name": "VENG01", "Contact Name": "Some Person (p@example.com)"},
    "windows": {
        "osName": "Microsoft Windows 10 Pro",
        "version": "10.0.19045",
        "registeredUser": "someone@example.com",
        "hotFixes": [
            {"hotFixId": f"KB{i}", "installedOn": f"2024-0{i}-01T00:00:00Z", "description": "Update"}
            for i in range(1, 8)
        ],
        "installedSoftware": [
            {"name": "Wireshark", "version": "4.0.5", "installDate": "Jan 1 1970"},
            {"name": "TightVNC", "version": "2.8", "installDate": "Nov 25 2025"},
        ],
    },
    "networkPorts": [{"name": "ethernet_0", "mac": "00:0c:29:d3:05:aa", "operStatus": "Up"}],
}


def test_host_details_compact_by_default() -> None:
    from tenable_ot_mcp.tools.assets import _project_host_details

    out = _project_host_details(_DETAILS)

    assert out["wmi_reported"] is True
    assert out["hardware"]["memory_total_gb"] == 16.0
    assert out["hardware"]["drives"][0]["capacity_gb"] == 399.4
    assert out["hardware"]["drives"][0]["name"] is None
    w = out["windows"]
    assert (w["hotfix_count"], w["software_count"]) == (7, 2)
    assert [h["id"] for h in w["latest_hotfixes"]] == ["KB7", "KB6", "KB5", "KB4", "KB3"]
    assert "installed_software" not in w and "hotfixes" not in w
    assert "network_ports" not in out
    # personal data is never surfaced
    assert "Contact Name" not in out["snmp"]
    assert "registeredUser" not in str(out) and "registered" not in str(out).lower()


def test_host_details_include_lists() -> None:
    from tenable_ot_mcp.tools.assets import _project_host_details

    out = _project_host_details(_DETAILS, frozenset({"software", "hotfixes", "network_ports"}))

    assert [s["name"] for s in out["windows"]["installed_software"]] == ["Wireshark", "TightVNC"]
    assert len(out["windows"]["hotfixes"]) == 7
    assert out["network_ports"][0]["mac"] == "00:0c:29:d3:05:aa"


def test_host_details_none_for_non_hosts() -> None:
    from tenable_ot_mcp.tools.assets import _project_host_details

    assert _project_host_details({"cip": {"deviceType": "Communications Adapter"}}) is None
    assert _project_host_details(None) is None
    assert _project_host_details({}) is None


async def test_get_asset_returns_host_block_and_validates_include() -> None:
    client = FakeClient(
        [
            {"asset": {"id": "h-1", "name": "VENG01"}},
            {"customFields": []},
            {"asset": {"backplane": None}},
            {"asset": {"details": _DETAILS}},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](
        asset_id="h-1", site_uuid="site-uuid", include=["software"]
    )

    assert result["asset"]["host"]["windows"]["software_count"] == 2
    assert len(result["asset"]["host"]["windows"]["installed_software"]) == 2
    assert client.query_calls[3]["variables"] == {"id": "h-1"}

    with pytest.raises(ValueError, match="unknown include"):
        await mcp.tools["get_asset"](asset_id="h-1", site_uuid="s", include=["bogus"])


async def test_get_asset_survives_details_query_failure() -> None:
    from tenable_ot_mcp.tenable_client import TenableError

    client = FakeClient(
        [
            {"asset": {"id": "h-1"}},
            {"customFields": []},
            {"asset": {"backplane": None}},
            TenableError("boom"),
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](asset_id="h-1", site_uuid="site-uuid")

    assert result["asset"]["id"] == "h-1"
    assert result["asset"]["host"] is None
    assert result["asset"]["host_error"] == "boom"
