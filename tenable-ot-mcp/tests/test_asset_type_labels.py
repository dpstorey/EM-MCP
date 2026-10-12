"""Asset-type matching accepts Tenable enum names and UI display labels."""

import pytest

from tenable_ot_mcp.tools._enums import normalize_filter_types, resolve_asset_type_name


@pytest.mark.parametrize(
    "given,expected",
    [
        ("Controller", "Controller"),
        ("controller", "Controller"),
        ("Bms", "Bms"),
        ("BMS Controller", "Bms"),
        ("bms controller", "Bms"),
        ("Backplane Module", "BackplaneModule"),
        ("CNC", "Cnc"),
    ],
)
def test_resolve_enum_or_label(given, expected):
    assert resolve_asset_type_name(given) == expected


def test_resolve_unknown_raises_with_hint():
    with pytest.raises(ValueError) as exc:
        resolve_asset_type_name("Controler")
    assert "Controller" in str(exc.value)


def test_normalize_filter_nested_and_untouched_fields():
    node = {
        "op": "And",
        "expressions": [
            {"field": "type", "op": "In", "values": ["BMS Controller", "Controller"]},
            {"op": "Or", "expressions": [{"field": "type", "op": "Eq", "value": "Backplane Module"}]},
            {"field": "name", "op": "Eq", "value": "BMS Controller"},
        ],
    }
    out = normalize_filter_types(node)
    assert out["expressions"][0]["values"] == ["Bms", "Controller"]
    assert out["expressions"][1]["expressions"][0]["value"] == "BackplaneModule"
    assert out["expressions"][2]["value"] == "BMS Controller"
