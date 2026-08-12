"""Days 11–12: the gateway enforces what the engine decides.

The deny test carries the phase's core promise: a denied request produces a
structured error, a recorded event, and **zero** calls to the destination —
proven by a mock, not by reading code.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from phulax_gateway import executor


def _envelope(seeded: dict, **overrides) -> dict:
    body = {
        "request_id": str(uuid.uuid4()),
        "agent_id": seeded["agent"]["id"],
        "agent_version": "1.0.0",
        "session_id": seeded["session"]["id"],
        "environment": "staging",
        "tool_name": "read_order",
        "arguments": {"order_id": "ORD-1001"},
        "requested_at": datetime.now(UTC).isoformat(),
    }
    return body | overrides


def _post(gateway_client, seeded, envelope):
    return gateway_client.post(
        "/v1/actions",
        json=envelope,
        headers={"Authorization": f"Bearer {seeded['token']}"},
    )


@pytest.fixture()
def destination(monkeypatch) -> MagicMock:
    """The mocked destination system — its call count is the whole point."""
    mock = MagicMock(wraps=executor.execute)
    monkeypatch.setattr(executor, "execute", mock)
    # main.py imported the module, not the function, so the patch is seen.
    return mock


def test_denied_request_never_calls_destination(gateway_client, api_client, seeded, destination):
    envelope = _envelope(
        seeded,
        tool_name="send_email",
        arguments={"to": "victim@external.example", "subject": "hi", "body": "…"},
    )
    response = _post(gateway_client, seeded, envelope)

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["effect"] == "deny"
    assert detail["rule"] == "block-external-sensitive-email"
    assert "RULE_DENY" in detail["reason_codes"]
    assert detail["policy_version"] == str(seeded["bundle"]["version"])
    destination.assert_not_called()  # zero destination calls — the exit criterion

    events = api_client.get("/v1/events", params={"request_id": envelope["request_id"]}).json()
    assert events[0]["verdict"] == "deny"
    assert events[0]["matched_rules"] == ["block-external-sensitive-email"]


def test_unregistered_sensitive_action_default_denied(
    gateway_client, api_client, seeded, destination
):
    # Scenario #18: a tool that exists in the registry but that no rule
    # mentions fails safe — DEFAULT_DENY, not silent allow.
    api_client.post(
        "/v1/tools",
        json={
            "org_id": seeded["org"]["id"],
            "name": "export_data",
            "description": "Bulk data export (no rule covers this)",
            "args_schema": {"type": "object"},
            "sensitivity": "high",
            "side_effect": "read",
        },
    )
    envelope = _envelope(seeded, tool_name="export_data", arguments={})
    response = _post(gateway_client, seeded, envelope)

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["effect"] == "deny"
    assert detail["rule"] == "DEFAULT_DENY"
    assert detail["matched_rules"] == []
    destination.assert_not_called()


def test_large_refund_requires_approval_and_does_not_execute(
    gateway_client, api_client, seeded, destination
):
    envelope = _envelope(
        seeded,
        tool_name="issue_refund",
        arguments={"order_id": "ORD-1001", "amount": 120.0},
    )
    response = _post(gateway_client, seeded, envelope)

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["effect"] == "require_approval"
    assert body["approver_role"] == "finance_approver"
    # Bound to the exact canonical hash: approving THIS request later can
    # never authorize a mutated one.
    assert body["approval_binding"] == body["canonical_hash"]
    destination.assert_not_called()

    events = api_client.get("/v1/events", params={"request_id": envelope["request_id"]}).json()
    # The request now carries two events: the decision and the approval
    # lifecycle entry it triggered (Phase 3).
    decision = next(event for event in events if event["type"] == "decision")
    assert decision["verdict"] == "require_approval"
    assert decision["matched_rules"] == ["approve-large-refund"]
    assert any(event["rule"] == "approval.requested" for event in events)


def test_small_refund_allowed_and_executes(gateway_client, seeded, destination):
    envelope = _envelope(
        seeded,
        tool_name="issue_refund",
        arguments={"order_id": "ORD-1001", "amount": 19.99},
    )
    response = _post(gateway_client, seeded, envelope)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["effect"] == "allow"
    assert body["rule"] == "allow-small-refund"
    assert body["result"]["status"] == "succeeded"
    destination.assert_called_once()


def test_decision_carries_risk_score_that_explains_not_decides(gateway_client, api_client, seeded):
    # A high-sensitivity write in the risk model is still ALLOWED when a
    # rule allows it: the score explains, it never overrides (plan §11.5).
    envelope = _envelope(
        seeded,
        tool_name="issue_refund",
        arguments={"order_id": "ORD-1001", "amount": 19.99},
    )
    response = _post(gateway_client, seeded, envelope)
    assert response.status_code == 200
    assert response.json()["risk_score"] > 0

    events = api_client.get("/v1/events", params={"request_id": envelope["request_id"]}).json()
    assert events[0]["risk_score"] == response.json()["risk_score"]
    assert events[0]["verdict"] == "allow"
