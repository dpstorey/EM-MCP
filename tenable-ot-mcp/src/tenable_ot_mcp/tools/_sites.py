# SPDX-License-Identifier: Apache-2.0
"""Shared site-selection and bounded multi-site read helpers."""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from ..tenable_client import TenableClient

DEFAULT_SITE_CONCURRENCY = 4
_WRITE_SITE_MACHINE_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "write_site_machine_id", default=None
)


def _normalise_site_ids(site_uuids: list[str]) -> list[str]:
    """Strip, validate, and de-duplicate site ids while preserving order."""
    normalised: list[str] = []
    seen: set[str] = set()
    for raw_site_id in site_uuids:
        site_id = raw_site_id.strip("/").strip()
        if not site_id:
            raise ValueError("site_uuids cannot contain empty values")
        if site_id not in seen:
            seen.add(site_id)
            normalised.append(site_id)
    if not normalised:
        raise ValueError("site_uuids cannot be empty")
    return normalised


async def resolve_read_site_ids(
    client: TenableClient,
    *,
    site_uuid: str | None,
    site_name: str | None,
    site_uuids: list[str] | None,
) -> list[str]:
    """Resolve either one legacy selector or an explicit array of site ids."""
    if site_uuids is not None:
        if site_uuid or site_name:
            raise ValueError("site_uuids cannot be combined with site_uuid or site_name")
        return _normalise_site_ids(site_uuids)
    return [await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)]


async def run_multi_site_read(
    site_ids: list[str],
    worker: Callable[[str], Awaitable[dict[str, Any]]],
    *,
    concurrency: int = DEFAULT_SITE_CONCURRENCY,
) -> dict[str, Any]:
    """Run a read for each site with bounded concurrency and partial success."""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run_one(site_id: str) -> tuple[str, dict[str, Any] | None, str | None]:
        try:
            async with semaphore:
                return site_id, await worker(site_id), None
        except Exception as exc:  # Multi-site reads preserve successful siblings.
            return site_id, None, str(exc)

    outcomes = await asyncio.gather(*(run_one(site_id) for site_id in site_ids))
    results = [result for _, result, error in outcomes if error is None and result is not None]
    errors = [
        {"site_uuid": site_id, "error": error}
        for site_id, _, error in outcomes
        if error is not None
    ]
    return {
        "sites_requested": len(site_ids),
        "sites_succeeded": len(results),
        "sites_failed": len(errors),
        "results": results,
        "errors": errors,
    }


async def run_site_read(
    client: TenableClient,
    *,
    site_uuid: str | None,
    site_name: str | None,
    site_uuids: list[str] | None,
    worker: Callable[[str], Awaitable[dict[str, Any]]],
    concurrency: int = DEFAULT_SITE_CONCURRENCY,
) -> dict[str, Any]:
    """Resolve site selectors and preserve legacy shape for a single site."""
    site_ids = await resolve_read_site_ids(
        client,
        site_uuid=site_uuid,
        site_name=site_name,
        site_uuids=site_uuids,
    )
    if len(site_ids) == 1:
        return await worker(site_ids[0])
    return await run_multi_site_read(site_ids, worker, concurrency=concurrency)


def current_write_site_machine_id() -> str | None:
    """Return the site selected by a site-scoped write wrapper."""
    return _WRITE_SITE_MACHINE_ID.get()


class SiteScopedWriteMCP:
    """Expose and propagate one explicit site on legacy write tools."""

    def __init__(self, mcp: Any, client: TenableClient) -> None:
        self._mcp = mcp
        self._client = client

    def tool(self, **tool_kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        register = self._mcp.tool(**tool_kwargs)

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            signature = inspect.signature(fn)
            parameters = list(signature.parameters.values())
            insert_at = next(
                (
                    index
                    for index, parameter in enumerate(parameters)
                    if parameter.kind == inspect.Parameter.VAR_KEYWORD
                ),
                len(parameters),
            )
            site_parameters = [
                inspect.Parameter(
                    "site_uuid",
                    kind=inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=str | None,
                ),
                inspect.Parameter(
                    "site_name",
                    kind=inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=str | None,
                ),
            ]

            @functools.wraps(fn)
            async def routed(
                *args: Any,
                site_uuid: str | None = None,
                site_name: str | None = None,
                **kwargs: Any,
            ) -> Any:
                machine_id = await self._client.resolve_site_machine_id(
                    site_uuid=site_uuid, site_name=site_name
                )
                token = _WRITE_SITE_MACHINE_ID.set(machine_id)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _WRITE_SITE_MACHINE_ID.reset(token)

            routed.__signature__ = signature.replace(  # type: ignore[attr-defined]
                parameters=parameters[:insert_at] + site_parameters + parameters[insert_at:]
            )
            return register(routed)

        return decorator
