# SPDX-License-Identifier: Apache-2.0
"""Tests for asset-edit and custom-field-management write tools.

Uses a tiny FakeMcp / FakeClient / FakeAudit harness so tests run
hermetically — no network, no real Tenable OT.
"""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools import writes
from tenable_ot_mcp.tools._enums import REMOVE_USER_DEFINED
from tenable_ot_mcp.tools.assets import CustomFieldLabelCache

# ---- Test harness ---------------------------------------------------------


class FakeMcp:
    """Captures @mcp.tool-decorated functions into a name → fn dict."""

    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **_kwargs: Any):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


class FakeClient:
    """Records every query/mutation call. Returns canned responses by substring match."""

    def __init__(self, canned: dict[str, dict[str, Any]] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self.canned = canned or {}

    async def query(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((query, variables))
        for substr, response in self.canned.items():
            if substr in query:
                return response
        return {}


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


@pytest.fixture(autouse=True)
def _reset_label_cache():
    """Each test starts with an empty custom-field label cache to keep behavior deterministic."""
    CustomFieldLabelCache.invalidate()
    yield
    CustomFieldLabelCache.invalidate()


def _make_tools(canned: dict[str, dict[str, Any]] | None = None):
    mcp = FakeMcp()
    client = FakeClient(canned=canned)
    audit = FakeAudit()
    writes.register_write_tools(mcp, client, audit)
    return mcp, client, audit


# Canned `customFields` query response — one slot configured
_LIST_RESP_ONE_FIELD = {
    "customFields": [
        {"fieldId": "customField1", "userDefinedName": "CDA Type", "valueType": "PlainText"},
    ]
}

_LIST_RESP_TWO_FIELDS = {
    "customFields": [
        {"fieldId": "customField1", "userDefinedName": "CDA Type", "valueType": "PlainText"},
        {"fieldId": "customField3", "userDefinedName": "Plant ID", "valueType": "PlainText"},
    ]
}


# ---- update_asset ---------------------------------------------------------


async def test_update_asset_dry_run_returns_preview_without_client_call():
    mcp, client, audit = _make_tools()
    out = await mcp.tools["update_asset"](asset_id="A1", description="hello", dry_run=True)

    assert out["dry_run"] is True
    assert out["tool"] == "update_asset"
    assert out["preview_variables"]["id"] == "A1"
    assert out["preview_variables"]["description"] == "hello"
    # Dry-run must NOT have called the GraphQL client.
    assert client.calls == []
    # Audit log records the preview.
    assert audit.records[0]["outcome"] == "preview"


async def test_update_asset_with_name_sends_correct_variables():
    mcp, client, _audit = _make_tools()
    await mcp.tools["update_asset"](asset_id="A1", name="renamed-plc", dry_run=False)

    assert len(client.calls) == 1
    _query, variables = client.calls[0]
    assert variables["id"] == "A1"
    assert variables["name"] == "renamed-plc"


async def test_update_asset_clear_fields_uses_sentinels_and_empty_strings():
    mcp, _client, _audit = _make_tools()
    out = await mcp.tools["update_asset"](
        asset_id="A1",
        clear_fields=["criticality", "location", "type", "purdue_level"],
        dry_run=True,
    )
    vars_ = out["preview_variables"]
    assert vars_["criticality"] == REMOVE_USER_DEFINED
    assert vars_["type"] == REMOVE_USER_DEFINED
    assert vars_["purdueLevel"] == REMOVE_USER_DEFINED
    assert vars_["location"] == ""


async def test_update_asset_kind_translates_to_enum():
    mcp, _client, _audit = _make_tools()
    out = await mcp.tools["update_asset"](asset_id="A1", kind="plc", dry_run=True)
    assert out["preview_variables"]["type"] == "Plc"

    out = await mcp.tools["update_asset"](asset_id="A1", kind="ot_workstation", dry_run=True)
    assert out["preview_variables"]["type"] == "OtWorkstation"


async def test_update_asset_custom_fields_resolves_label_to_slot():
    mcp, _client, _audit = _make_tools(canned={"customFields": _LIST_RESP_TWO_FIELDS})
    out = await mcp.tools["update_asset"](
        asset_id="A1",
        custom_fields={"CDA Type": "Class 1", "Plant ID": "site-B"},
        dry_run=True,
    )
    cf = out["preview_variables"]["customFields"]
    assert cf == {"customField1": "Class 1", "customField3": "site-B"}


async def test_update_asset_custom_fields_unknown_label_raises():
    mcp, _client, _audit = _make_tools(canned={"customFields": _LIST_RESP_ONE_FIELD})
    with pytest.raises(ValueError, match="unknown custom-field label"):
        await mcp.tools["update_asset"](
            asset_id="A1",
            custom_fields={"NotARealLabel": "x"},
            dry_run=True,
        )


async def test_update_asset_requires_at_least_one_field():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="at least one editable field"):
        await mcp.tools["update_asset"](asset_id="A1", dry_run=True)


async def test_update_asset_invalid_clear_field_raises():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="unknown clear_fields"):
        await mcp.tools["update_asset"](
            asset_id="A1",
            clear_fields=["vendor"],
            dry_run=True,
        )


# ---- bulk_edit_assets -----------------------------------------------------


async def test_bulk_edit_assets_builds_natural_vocab_filter():
    mcp, _client, _audit = _make_tools()
    out = await mcp.tools["bulk_edit_assets"](
        kind="switch",
        criticality_at_least="medium",
        description="lab switch",
        dry_run=True,
    )
    vars_ = out["preview_variables"]
    assert vars_["description"] == "lab switch"
    filt = vars_["filter"]
    # AND of (type IN [Switch, IndustrialSwitch]) AND (criticality IN [Med, High])
    assert filt["op"] == "And"
    fields_in_filter = [e["field"] for e in filt["expressions"]]
    assert "type" in fields_in_filter
    assert "criticality" in fields_in_filter


async def test_bulk_edit_assets_refuses_bare_unfiltered_call():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="bare unfiltered bulk edits are rejected"):
        await mcp.tools["bulk_edit_assets"](description="anything", dry_run=True)


async def test_bulk_edit_assets_requires_edit_or_segment_or_clear():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="at least one edit arg"):
        await mcp.tools["bulk_edit_assets"](kind="plc", dry_run=True)


async def test_bulk_edit_assets_segment_only_is_allowed():
    mcp, _client, _audit = _make_tools()
    out = await mcp.tools["bulk_edit_assets"](kind="plc", segment_id="seg-42", dry_run=True)
    assert out["preview_variables"]["segment"] == "seg-42"


# ---- reset_asset_metadata -------------------------------------------------


async def test_reset_asset_metadata_clears_everything():
    mcp, _client, _audit = _make_tools()
    out = await mcp.tools["reset_asset_metadata"](asset_id="A1", dry_run=True)
    vars_ = out["preview_variables"]
    assert vars_["id"] == "A1"
    assert vars_["name"] == ""
    assert vars_["location"] == ""
    assert vars_["description"] == ""
    assert vars_["type"] == REMOVE_USER_DEFINED
    assert vars_["purdueLevel"] == REMOVE_USER_DEFINED
    assert vars_["criticality"] == REMOVE_USER_DEFINED
    cf = vars_["customFields"]
    assert all(cf[f"customField{i}"] == "" for i in range(1, 11))


# ---- create_custom_field --------------------------------------------------


async def test_create_custom_field_sends_correct_mutation():
    mcp, client, _audit = _make_tools()
    await mcp.tools["create_custom_field"](name="Plant ID", value_type="text", dry_run=False)

    query, variables = client.calls[0]
    assert "addCustomField" in query
    assert variables == {"userDefinedName": "Plant ID", "valueType": "PlainText"}


async def test_create_custom_field_hyperlink_translates_natural_synonyms():
    mcp, client, _audit = _make_tools()
    await mcp.tools["create_custom_field"](name="Docs", value_type="link", dry_run=False)
    _query, variables = client.calls[0]
    assert variables["valueType"] == "HyperLink"


async def test_create_custom_field_requires_name():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="name is required"):
        await mcp.tools["create_custom_field"](name="", dry_run=True)


# ---- rename_custom_field --------------------------------------------------


async def test_rename_custom_field_by_field_id():
    mcp, client, _audit = _make_tools()
    await mcp.tools["rename_custom_field"](
        field_id="customField1", new_name="Site Tag", dry_run=False
    )
    query, variables = client.calls[0]
    assert "updateCustomField" in query
    assert variables["fieldId"] == "customField1"
    assert variables["userDefinedName"] == "Site Tag"


async def test_rename_custom_field_by_current_name_resolves_to_slot():
    mcp, client, _audit = _make_tools(canned={"customFields": _LIST_RESP_ONE_FIELD})
    await mcp.tools["rename_custom_field"](
        current_name="CDA Type", new_name="CDA Class", dry_run=False
    )
    # First call: customFields query; second call: updateCustomField mutation.
    update_call = next(c for c in client.calls if "updateCustomField" in c[0])
    assert update_call[1]["fieldId"] == "customField1"
    assert update_call[1]["userDefinedName"] == "CDA Class"


async def test_rename_custom_field_requires_identifier():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="field_id or current_name"):
        await mcp.tools["rename_custom_field"](new_name="x", dry_run=True)


# ---- delete_custom_field --------------------------------------------------


async def test_delete_custom_field_dry_run_does_not_require_confirm():
    mcp, _client, _audit = _make_tools()
    out = await mcp.tools["delete_custom_field"](field_id="customField1", dry_run=True)
    assert out["dry_run"] is True


async def test_delete_custom_field_refuses_apply_without_confirm():
    mcp, _client, _audit = _make_tools()
    with pytest.raises(ValueError, match="confirm_wipes_values=True"):
        await mcp.tools["delete_custom_field"](
            field_id="customField1", dry_run=False, confirm_wipes_values=False
        )


async def test_delete_custom_field_applies_with_confirm_and_dry_run_off():
    mcp, client, _audit = _make_tools()
    await mcp.tools["delete_custom_field"](
        field_id="customField1", dry_run=False, confirm_wipes_values=True
    )
    query, variables = client.calls[0]
    assert "deleteCustomField" in query
    assert variables == {"fieldId": "customField1"}


# ---- Audit logging --------------------------------------------------------


async def test_audit_records_preview_outcome():
    mcp, _client, audit = _make_tools()
    await mcp.tools["update_asset"](asset_id="A1", description="x", dry_run=True)
    assert audit.records[-1]["tool_name"] == "update_asset"
    assert audit.records[-1]["dry_run"] is True
    assert audit.records[-1]["outcome"] == "preview"


async def test_audit_records_ok_outcome_on_apply():
    mcp, _client, audit = _make_tools()
    await mcp.tools["update_asset"](asset_id="A1", description="x", dry_run=False)
    rec = audit.records[-1]
    assert rec["tool_name"] == "update_asset"
    assert rec["dry_run"] is False
    assert rec["outcome"] == "ok"


async def test_audit_records_error_when_client_raises():
    class ErrorClient(FakeClient):
        async def query(self, query: str, variables=None):
            raise RuntimeError("boom")

    mcp = FakeMcp()
    client = ErrorClient()
    audit = FakeAudit()
    writes.register_write_tools(mcp, client, audit)

    with pytest.raises(RuntimeError):
        await mcp.tools["update_asset"](asset_id="A1", name="x", dry_run=False)
    err = audit.records[-1]
    assert err["outcome"] == "error"
    assert "boom" in err["error"]
