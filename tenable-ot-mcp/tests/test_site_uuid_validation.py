# SPDX-License-Identifier: Apache-2.0
"""Regression tests for site/ICP machine-id validation.

Covers the failure mode where a malformed `site_uuid` (truncated,
hand-typed, or otherwise not a well-formed UUID) got silently relayed
to `<base>/<site_uuid>/graphql`, which Tenable OT/EM does not recognize
as a paired ICP. Rather than erroring, EM's web front end answers with
HTTP 200 and an HTML page, which previously surfaced downstream as an
opaque "Tenable OT/EM returned non-JSON response (HTTP 200)" error with
no indication of the actual mistake (a bad site_uuid). These tests
confirm the bad shape is now caught up front, before any network call,
with a message that tells the caller what to do differently.
"""

from __future__ import annotations

import pytest

from tenable_ot_mcp.tenable_client import TenableClient, validate_machine_id
from tenable_ot_mcp.tools._sites import _normalise_site_ids

VALID_UUID = "9b06f7ce-20ca-44d2-8927-4be792712345"
# The exact truncated id from the original bug report — 7 hex chars in
# the last group instead of 12.
TRUNCATED_UUID = "9b06f7ce-20ca-44d2-8927-4be7927"


def test_validate_machine_id_accepts_well_formed_uuid() -> None:
    assert validate_machine_id(VALID_UUID) == VALID_UUID


def test_validate_machine_id_accepts_mixed_case() -> None:
    mixed = VALID_UUID.upper()
    assert validate_machine_id(mixed) == mixed


def test_validate_machine_id_rejects_truncated_uuid() -> None:
    with pytest.raises(ValueError) as exc_info:
        validate_machine_id(TRUNCATED_UUID)
    message = str(exc_info.value)
    assert TRUNCATED_UUID in message
    assert "list_paired_icps" in message
    assert "not a valid Tenable site/ICP machine id" in message


def test_validate_machine_id_rejects_empty_and_garbage() -> None:
    with pytest.raises(ValueError, match="list_paired_icps"):
        validate_machine_id("")
    with pytest.raises(ValueError, match="list_paired_icps"):
        validate_machine_id("not-a-uuid-at-all")


def test_validate_machine_id_error_names_the_offending_field() -> None:
    with pytest.raises(ValueError, match=r"site_uuids=.*list_paired_icps"):
        validate_machine_id(TRUNCATED_UUID, field="site_uuids")


async def test_resolve_site_machine_id_rejects_malformed_site_uuid_before_any_request() -> None:
    # base_url intentionally bogus/unreachable — if validation didn't run
    # before the network call, this would raise a transport error instead
    # of the intended ValueError, and would hang/retry against a bad host.
    client = TenableClient(base_url="https://example.invalid", api_key="k")
    with pytest.raises(ValueError, match="list_paired_icps"):
        await client.resolve_site_machine_id(site_uuid=TRUNCATED_UUID, site_name=None)


async def test_resolve_site_machine_id_accepts_valid_site_uuid() -> None:
    client = TenableClient(base_url="https://example.invalid", api_key="k")
    resolved = await client.resolve_site_machine_id(site_uuid=VALID_UUID, site_name=None)
    assert resolved == VALID_UUID


def test_normalise_site_ids_rejects_malformed_entry_in_array() -> None:
    with pytest.raises(ValueError, match="site_uuids.*list_paired_icps"):
        _normalise_site_ids([VALID_UUID, TRUNCATED_UUID])


def test_normalise_site_ids_accepts_well_formed_array() -> None:
    other = "11111111-1111-1111-1111-111111111111"
    assert _normalise_site_ids([VALID_UUID, other]) == [VALID_UUID, other]
