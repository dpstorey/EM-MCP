# SPDX-License-Identifier: Apache-2.0
"""Resume bookkeeping for get_attackers_view (offset / next_offset)."""

from __future__ import annotations

from tenable_ot_mcp.tools.attack_vector import _paging_fields


def test_first_page_paused_after_three():
    # 3 processed, 22 left -> resume at offset 3
    assert _paging_fields(0, 3, 22) == {"offset": 0, "next_offset": 3}


def test_resume_from_offset_accumulates():
    # resumed at offset 3, processed 5 more, 10 left -> next is 8
    assert _paging_fields(3, 5, 10) == {"offset": 3, "next_offset": 8}


def test_finished_run_has_no_next_offset():
    assert _paging_fields(3, 22, 0) == {"offset": 3, "next_offset": None}
