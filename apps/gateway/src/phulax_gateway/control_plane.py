"""The gateway's client for the hosted control plane (ADR-0001).

Only metadata crosses this boundary: agent/tool lookups down, decision
events up. Raw arguments and results never leave the gateway process.
"""

import uuid
from typing import Any

import httpx


class ControlPlaneError(Exception):
    pass


class ExecutionConflict(ControlPlaneError):
    """The control plane refused an execution transition (409)."""

    def __init__(self, detail: Any) -> None:
        self.detail = detail
        super().__init__(str(detail))


class ControlPlaneClient:
    def __init__(self, base_url: str, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=5.0)

    async def get_agent(self, agent_id: uuid.UUID) -> dict[str, Any] | None:
        response = await self._client.get(f"/v1/agents/{agent_id}")
        if response.status_code == 404:
            return None
        self._raise_for_status(response)
        return response.json()

    async def get_tool(self, org_id: uuid.UUID, name: str) -> dict[str, Any] | None:
        response = await self._client.get("/v1/tools", params={"org_id": str(org_id), "name": name})
        self._raise_for_status(response)
        tools = response.json()
        return tools[0] if tools else None

    async def post_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post("/v1/events", json=payload)
        self._raise_for_status(response)
        return response.json()

    async def get_latest_bundle(self, org_id: uuid.UUID) -> dict[str, Any] | None:
        response = await self._client.get(
            "/v1/policy-bundles/latest", params={"org_id": str(org_id)}
        )
        if response.status_code == 404:
            return None
        self._raise_for_status(response)
        return response.json()

    async def resolve_approval(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post("/v1/approvals/resolve", json=payload)
        self._raise_for_status(response)
        return response.json()

    async def claim_execution(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post("/v1/executions/claim", json=payload)
        if response.status_code == 409:
            raise ExecutionConflict(response.json().get("detail"))
        self._raise_for_status(response)
        return response.json()

    async def complete_execution(
        self, execution_id: str, state: str, result_meta: dict[str, Any]
    ) -> dict[str, Any]:
        response = await self._client.post(
            f"/v1/executions/{execution_id}/complete",
            json={"state": state, "result_meta": result_meta},
        )
        if response.status_code == 409:
            raise ExecutionConflict(response.json().get("detail"))
        self._raise_for_status(response)
        return response.json()

    async def aclose(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code >= 400:
            raise ControlPlaneError(
                f"control plane returned {response.status_code}: {response.text[:200]}"
            )
