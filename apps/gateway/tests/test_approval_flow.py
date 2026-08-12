"""Days 15–19, end to end: high-risk actions pause for a human, the
approval authorizes one exact request once, and the whole story is one
trace query away. These are the failing tests the phase doc names."""

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from phulax_gateway import executor
from sqlalchemy import text


@pytest.fixture(autouse=True)
def clean_ledgers():
    executor.ISSUED_REFUNDS.clear()
    yield
    executor.ISSUED_REFUNDS.clear()


@pytest.fixture()
def destination(monkeypatch) -> MagicMock:
    mock = MagicMock(wraps=executor.execute)
    monkeypatch.setattr(executor, "execute", mock)
    return mock


def _refund_envelope(seeded, *, amount=748.0, trace_id=None, key=None, acting_user=None):
    body = {
        "request_id": str(uuid.uuid4()),
        "agent_id": seeded["agent"]["id"],
        "agent_version": "1.0.0",
        "session_id": seeded["session"]["id"],
        "environment": "staging",
        "tool_name": "issue_refund",
        "arguments": {
            "order_id": "ORD-1001",
            "amount": amount,
            "card_token": "tok_live_super_secret",
            "customer_note": "cardholder is furious",
        },
        "requested_at": datetime.now(UTC).isoformat(),
    }
    if trace_id:
        body["trace_id"] = str(trace_id)
    if key:
        body["idempotency_key"] = key
    if acting_user:
        body["acting_user_id"] = acting_user
    return body


def _post(gateway_client, seeded, envelope):
    return gateway_client.post(
        "/v1/actions", json=envelope, headers={"Authorization": f"Bearer {seeded['token']}"}
    )


def _approve(api_client, approval_id, user_id):
    return api_client.post(f"/v1/approvals/{approval_id}/approve", json={"user_id": user_id})


def test_no_destination_call_before_approval(gateway_client, api_client, seeded, destination):
    response = _post(gateway_client, seeded, _refund_envelope(seeded))
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["effect"] == "require_approval"
    assert body["approval"]["state"] == "PENDING"
    assert body["approval_binding"] == body["canonical_hash"]
    assert set(body["approval"]["redacted_fields"]) == {"card_token", "customer_note"}
    destination.assert_not_called()  # paused for judgment, not executed


def test_approval_executes_exactly_once_second_use_rejected(gateway_client, api_client, seeded):
    trace_id = uuid.uuid4()
    key = f"refund-{uuid.uuid4()}"
    first = _post(gateway_client, seeded, _refund_envelope(seeded, trace_id=trace_id, key=key))
    approval_id = first.json()["approval"]["id"]
    _approve(api_client, approval_id, seeded["finance"]["id"]).raise_for_status()

    executed = _post(gateway_client, seeded, _refund_envelope(seeded, trace_id=trace_id, key=key))
    assert executed.status_code == 200, executed.text
    body = executed.json()
    assert "APPROVAL_CONSUMED" in body["reason_codes"]
    assert body["result"]["status"] == "succeeded"
    assert len(executor.ISSUED_REFUNDS) == 1

    # Second use: the token is spent. The action pauses again — it can
    # never replay the consumed approval (scenario #9).
    replay = _post(gateway_client, seeded, _refund_envelope(seeded, trace_id=trace_id, key=key))
    assert replay.status_code == 202
    assert replay.json()["approval"]["id"] != approval_id
    assert len(executor.ISSUED_REFUNDS) == 1


def test_mutated_arguments_void_approval(gateway_client, api_client, seeded, destination):
    first = _post(gateway_client, seeded, _refund_envelope(seeded, amount=748.0))
    approval_id = first.json()["approval"]["id"]
    _approve(api_client, approval_id, seeded["finance"]["id"]).raise_for_status()

    # $748 was approved; $7480 arrives. Different canonical hash ⇒ the
    # approval simply does not apply (scenario #8).
    mutated = _post(gateway_client, seeded, _refund_envelope(seeded, amount=7480.0))
    assert mutated.status_code == 202
    assert mutated.json()["approval"]["id"] != approval_id
    destination.assert_not_called()


def test_expired_approval_rejected(gateway_client, api_client, seeded, clean_db, destination):
    first = _post(gateway_client, seeded, _refund_envelope(seeded))
    approval_id = first.json()["approval"]["id"]
    _approve(api_client, approval_id, seeded["finance"]["id"]).raise_for_status()
    with clean_db.begin() as conn:
        conn.execute(text("UPDATE approvals SET expires_at = now() - interval '1 minute'"))

    retry = _post(gateway_client, seeded, _refund_envelope(seeded))
    assert retry.status_code == 202  # paused again, not executed
    destination.assert_not_called()
    assert api_client.get(f"/v1/approvals/{approval_id}").json()["state"] == "EXPIRED"


def test_requester_cannot_approve_own_request(gateway_client, api_client, seeded):
    # A requester WITH the approver role is still refused: separation of
    # duties is about identity, not privilege.
    finance2 = api_client.post(
        "/v1/users",
        json={
            "org_id": seeded["org"]["id"],
            "email": "finance2@demo-org.dev",
            "name": "Second Approver",
            "role": "finance_approver",
        },
    ).json()
    response = _post(gateway_client, seeded, _refund_envelope(seeded, acting_user=finance2["id"]))
    approval_id = response.json()["approval"]["id"]

    refused = _approve(api_client, approval_id, finance2["id"])
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "approval.self-approval"

    allowed = _approve(api_client, approval_id, seeded["finance"]["id"])
    assert allowed.status_code == 200


def test_human_rejection_denies_the_request(gateway_client, api_client, seeded, destination):
    first = _post(gateway_client, seeded, _refund_envelope(seeded))
    approval_id = first.json()["approval"]["id"]
    api_client.post(
        f"/v1/approvals/{approval_id}/reject", json={"user_id": seeded["finance"]["id"]}
    ).raise_for_status()

    retry = _post(gateway_client, seeded, _refund_envelope(seeded))
    assert retry.status_code == 403
    assert "APPROVAL_REJECTED" in retry.json()["detail"]["reason_codes"]
    destination.assert_not_called()


def test_timeline_reconstructs_full_lifecycle_from_trace_id(gateway_client, api_client, seeded):
    trace_id = uuid.uuid4()
    key = f"refund-{uuid.uuid4()}"

    pending = _post(gateway_client, seeded, _refund_envelope(seeded, trace_id=trace_id, key=key))
    approval_id = pending.json()["approval"]["id"]
    _approve(api_client, approval_id, seeded["finance"]["id"]).raise_for_status()
    executed = _post(gateway_client, seeded, _refund_envelope(seeded, trace_id=trace_id, key=key))
    assert executed.status_code == 200

    timeline = api_client.get("/v1/timeline", params={"trace_id": str(trace_id)}).json()
    assert [event["rule"] for event in timeline] == [
        "approve-large-refund",  # received → decision: pause
        "approval.requested",  # a human is asked
        "approval.approved",  # the human says yes, once
        "approve-large-refund",  # the retry's own decision event
        "approval.consumed",  # the yes is spent, atomically
        "execution.succeeded",  # result — the story has an ending
    ]
    # The same three correlators ride every entry (plan §11.3).
    assert {event["trace_id"] for event in timeline} == {str(trace_id)}
    assert all(event["session_id"] == seeded["session"]["id"] for event in timeline)
