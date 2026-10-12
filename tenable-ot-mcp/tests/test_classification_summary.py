# SPDX-License-Identifier: Apache-2.0
"""get_classification_summary: query building and result shaping."""

from __future__ import annotations

from tenable_ot_mcp.tools.summary import (
    _FILTER_ASSET_TYPES,
    _classification_query,
    classification_result,
)


def _counts(total: int, unknown: int, **by_type: int) -> dict:
    data = {
        "assetsTotal": {"totalCount": total},
        "assetsUnknown": {"totalCount": unknown},
    }
    for name, n in by_type.items():
        data[f"t_{name}"] = {"totalCount": n}
    return data


def test_query_has_total_and_unknown_only_by_default() -> None:
    q = _classification_query(False)
    assert "assetsTotal: assets" in q
    assert 'values: ["Unknown"]' in q
    assert "t_Plc" not in q


def test_query_by_type_adds_one_alias_per_filter_type() -> None:
    q = _classification_query(True)
    for t in _FILTER_ASSET_TYPES:
        if t != "Unknown":
            assert f"t_{t}:" in q
    assert q.count("totalCount") == len(_FILTER_ASSET_TYPES) + 1  # types + total


def test_filter_type_list_is_unique_and_has_unknown() -> None:
    assert len(set(_FILTER_ASSET_TYPES)) == len(_FILTER_ASSET_TYPES) == 36
    assert "Unknown" in _FILTER_ASSET_TYPES


def test_data_quality_against_default_target() -> None:
    ok = classification_result("s", _counts(1000, 100))  # 90.0 meets the default 90
    assert (ok["classified"], ok["data_quality_pct"], ok["quality"]) == (900, 90.0, "good")
    assert (ok["target_pct"], ok["meets_target"], ok["unclassified_pct"]) == (90.0, True, 10.0)
    assert "warning" not in ok
    low = classification_result("s", _counts(1480, 212))
    assert low["data_quality_pct"] == 85.7 and low["unclassified_pct"] == 14.3
    assert low["quality"] == "poor"
    assert low["meets_target"] is False and "warning" in low


def test_target_is_settable() -> None:
    data = _counts(1000, 60)  # 94.0% quality
    assert classification_result("s", data)["quality"] == "good"
    strict = classification_result("s", data, min_quality_pct=95.0)
    assert strict["quality"] == "poor" and strict["target_pct"] == 95.0
    assert strict["meets_target"] is False
    assert classification_result("s", data, min_quality_pct=94.0)["quality"] == "good"


def test_live_london_numbers() -> None:
    r = classification_result("s", _counts(3487, 1454))
    assert (r["data_quality_pct"], r["unclassified_pct"], r["quality"]) == (58.3, 41.7, "poor")


def test_empty_site_has_no_ratio() -> None:
    r = classification_result("s", _counts(0, 0))
    assert r["data_quality_pct"] is None and r["unclassified_pct"] is None
    assert r["quality"] == "no_assets" and r["meets_target"] is None


def test_missing_blocks_count_as_zero() -> None:
    r = classification_result("s", {})
    assert r["assets_total"] == 0 and r["unclassified"] == 0


def test_by_type_breakdown_sorted_with_remainder() -> None:
    data = _counts(100, 10, Plc=40, Switch=30)
    r = classification_result("s", data, by_type=True)
    assert list(r["by_type"]) == ["Plc", "Switch", "Unknown"]
    assert r["by_type"]["Unknown"] == 10
    assert r["by_type_other"] == 20  # 100 - (40 + 30 + 10)


def test_by_type_omitted_unless_requested() -> None:
    assert "by_type" not in classification_result("s", _counts(10, 1))
