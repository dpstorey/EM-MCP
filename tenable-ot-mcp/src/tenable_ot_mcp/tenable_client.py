# SPDX-License-Identifier: Apache-2.0
"""Minimal async GraphQL client for Tenable OT Security.

This server is a translation layer — every MCP tool call issues a live
GraphQL query against the operator's Tenable OT Security deployment.
No data is cached or persisted in the container.

Authentication: Tenable OT uses a service-account API key sent as
`X-APIKeys` (the documented header used by appliance + EM GraphQL).
The key is loaded from the encrypted config and never logged.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_QUERY_EM_PAIRED_ICPS = """
query Q($pageSize: Int!) {
    emPairedIcps(first: $pageSize) {
        edges {
            node {
                site {
                    machineId
                    name
                }
            }
        }
    }
}
"""


class TenableError(Exception):
    """Raised on a Tenable OT GraphQL error or transport failure."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class TenableClient:
    """Issues authenticated GraphQL POSTs to appliance or EM-relayed ICP endpoints."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        icp_machine_id: str | None = None,
        tls_verify: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._icp_machine_id = icp_machine_id.strip("/") if icp_machine_id else None
        self._tls_verify = tls_verify
        self._timeout = timeout
        self._site_name_to_machine_id: dict[str, str] = {}
        self._debug_graphql = os.environ.get("MCP_DEBUG_GRAPHQL") == "1"

    def _endpoint_for(
        self,
        *,
        use_em_root: bool = False,
        icp_machine_id: str | None = None,
    ) -> str:
        """Build the target GraphQL endpoint.

        - Direct appliance mode:          <base>/graphql
        - EM default ICP relay mode:      <base>/<configured-icp>/graphql
        - EM explicit ICP relay override: <base>/<icp_machine_id>/graphql
        - EM root control-plane queries:  <base>/graphql
        """
        if use_em_root:
            return f"{self.base_url}/graphql"
        target_icp = icp_machine_id.strip("/") if icp_machine_id else self._icp_machine_id
        if target_icp:
            return f"{self.base_url}/{target_icp}/graphql"
        return f"{self.base_url}/graphql"

    def _headers(self) -> dict[str, str]:
        return {
            "X-APIKeys": f"key={self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        *,
        use_em_root: bool = False,
        icp_machine_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL operation and return the `data` payload.

        Raises TenableError on transport failure, non-2xx HTTP, or any
        `errors` array in the GraphQL response.
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        endpoint = self._endpoint_for(use_em_root=use_em_root, icp_machine_id=icp_machine_id)
        if self._debug_graphql:
            logger.info(
                "Tenable GraphQL request endpoint=%s use_em_root=%s icp_machine_id=%s op=%s vars_keys=%s",
                endpoint,
                use_em_root,
                icp_machine_id,
                operation_name or "Q",
                sorted((variables or {}).keys()),
            )

        try:
            async with httpx.AsyncClient(verify=self._tls_verify, timeout=self._timeout) as client:
                resp = await client.post(
                    endpoint,
                    headers=self._headers(),
                    json=payload,
                )
        except httpx.HTTPError as e:
            raise TenableError(f"Transport error talking to Tenable OT/EM: {e}") from e

        if resp.status_code >= 400:
            raise TenableError(
                (
                    f"Tenable OT/EM returned HTTP {resp.status_code} "
                    f"from {endpoint}: {resp.text[:500]}"
                ),
                status=resp.status_code,
            )

        try:
            body = resp.json()
        except json.JSONDecodeError as e:
            raise TenableError(
                f"Tenable OT/EM returned non-JSON response (HTTP {resp.status_code})",
                status=resp.status_code,
            ) from e

        if isinstance(body, dict) and body.get("errors"):
            messages = "; ".join(e.get("message", str(e)) for e in body["errors"])
            raise TenableError(f"Tenable OT/EM GraphQL errors: {messages}", status=resp.status_code)

        return body.get("data") or {}

    async def healthcheck(self) -> bool:
        """Issue a trivial query to verify connectivity + auth.

        Used by the setup wizard to validate the operator's input
        before saving configuration.
        """
        try:
            data = await self.query("{ __typename }")
            return bool(data)
        except TenableError:
            return False

    async def query_em(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        """Run a query against EM's root GraphQL endpoint.

        Useful for EM-only control-plane data (for example paired ICP inventory)
        even when the client is configured to relay regular queries through one ICP.
        """
        return await self.query(
            query=query,
            variables=variables,
            operation_name=operation_name,
            use_em_root=True,
        )

    async def _refresh_site_cache(self) -> None:
        """Refresh EM site-name -> machine-id mapping from paired ICP inventory."""
        data = await self.query_em(_QUERY_EM_PAIRED_ICPS, variables={"pageSize": 500})
        conn = (data or {}).get("emPairedIcps") or {}
        mapping: dict[str, str] = {}
        for edge in conn.get("edges") or []:
            node = (edge or {}).get("node") or {}
            site = node.get("site") or {}
            machine_id = site.get("machineId")
            site_name = site.get("name")
            if isinstance(machine_id, str) and isinstance(site_name, str):
                if machine_id.strip() and site_name.strip():
                    mapping[site_name.strip().lower()] = machine_id.strip("/")
        self._site_name_to_machine_id = mapping

    async def resolve_site_machine_id(
        self,
        *,
        site_uuid: str | None,
        site_name: str | None,
    ) -> str:
        """Resolve target site to machine id.

        `site_uuid` is treated as the machine id directly. When `site_name`
        is provided, resolve through EM paired-ICP inventory and cache the
        result on this client instance.
        """
        if site_uuid:
            return site_uuid.strip("/")
        if not site_name:
            raise ValueError("site_uuid or site_name is required")

        key = site_name.strip().lower()
        if not key:
            raise ValueError("site_uuid or site_name is required")

        machine_id = self._site_name_to_machine_id.get(key)
        if machine_id:
            return machine_id

        await self._refresh_site_cache()
        machine_id = self._site_name_to_machine_id.get(key)
        if not machine_id:
            raise ValueError("site not found")
        return machine_id
