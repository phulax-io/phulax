"""Weekly Demo 3: judgment and memory (plan §7, Day 21).

The $25/$748/email demo, five minutes from `make seed`:

  1. issue_refund $25       → ALLOWED by rule, executed
  2. issue_refund $748      → PENDING human approval (fields redacted)
     · approved once by the finance approver (never the requester)
     · retry executes exactly once; a second retry cannot replay it
  3. send_email (external)  → DENIED, zero destination calls
  4. one trace_id query     → the full story, step by step

Review UI: http://127.0.0.1:<API_PORT>/ui/approvals
"""

import os
import sys
import uuid
from datetime import UTC, datetime

import httpx

API_URL = f"http://127.0.0.1:{os.environ.get('API_PORT', '8000')}"
GATEWAY_URL = f"http://127.0.0.1:{os.environ.get('GATEWAY_PORT', '8080')}"


def _decision_line(payload: dict) -> str:
    return (
        f"{payload['effect'].upper():18} rule={payload['rule']} "
        f"reasons={','.join(payload['reason_codes'])} "
        f"policy=v{payload['policy_version']}"
    )


def main() -> int:
    api = httpx.Client(base_url=API_URL, timeout=10.0)
    gateway = httpx.Client(base_url=GATEWAY_URL, timeout=10.0)
    try:
        api.get("/health").raise_for_status()
        gateway.get("/health").raise_for_status()

        agents = api.get("/v1/agents", params={"name": "refund-agent"}).json()
        finance = api.get("/v1/users", params={"email": "finance@demo-org.dev"}).json()
        if not agents or not finance:
            print("demo: missing seed data — run 'make seed' first")
            return 1
        agent, finance = agents[0], finance[0]
        version = agent["latest_version"]

        session = api.post(
            "/v1/sessions",
            json={"agent_version_id": version["id"], "environment": "staging"},
        ).json()
        token = api.post("/v1/tokens", json={"session_id": session["id"]}).json()
        headers = {"Authorization": f"Bearer {token['token']}"}
        trace_id = str(uuid.uuid4())

        def call(tool_name: str, arguments: dict, idempotency_key: str | None = None):
            envelope = {
                "request_id": str(uuid.uuid4()),
                "trace_id": trace_id,
                "agent_id": agent["id"],
                "agent_version": version["version"],
                "session_id": session["id"],
                "environment": "staging",
                "tool_name": tool_name,
                "arguments": arguments,
                "requested_at": datetime.now(UTC).isoformat(),
            }
            if idempotency_key is not None:
                envelope["idempotency_key"] = idempotency_key
            return gateway.post("/v1/actions", json=envelope, headers=headers)

        print(f"demo: agent      {agent['name']} v{version['version']} (staging session)")
        print(f"demo: trace      {trace_id}")
        print()

        # Act 1 — the small refund sails through.
        print("demo: [1] issue_refund $25")
        response = call("issue_refund", {"order_id": "ORD-1001", "amount": 25.0})
        if response.status_code != 200:
            print(f"demo: FAILED — expected allow, got {response.status_code} {response.text}")
            return 1
        print(f"demo:     {_decision_line(response.json())}")
        print(f"demo:     refund {response.json()['result']['refund_id']} issued")
        print()

        # Act 2 — the large refund pauses for a human.
        refund_args = {
            "order_id": "ORD-1001",
            "amount": 748.0,
            "card_token": "tok_live_extremely_sensitive",
            "customer_note": "cardholder threatened chargeback",
        }
        key = f"demo-refund-{uuid.uuid4()}"
        print("demo: [2] issue_refund $748 (card token + note attached)")
        response = call("issue_refund", refund_args, key)
        if response.status_code != 202:
            print(f"demo: FAILED — expected pending, got {response.status_code} {response.text}")
            return 1
        body = response.json()
        approval = body["approval"]
        print(f"demo:     {_decision_line(body)}")
        print(
            f"demo:     PENDING approval {approval['id'][:8]}… "
            f"({len(approval['redacted_fields'])} fields redacted: "
            f"{', '.join(approval['redacted_fields'])})"
        )
        print(f"demo:     review UI: {API_URL}/ui/approvals/{approval['id']}")

        decision = api.post(
            f"/v1/approvals/{approval['id']}/approve", json={"user_id": finance["id"]}
        )
        if decision.status_code != 200:
            print(f"demo: FAILED — approve refused: {decision.text}")
            return 1
        print(f"demo:     approved once by {finance['email']} (requester cannot self-approve)")

        retry = call("issue_refund", refund_args, key)
        if retry.status_code != 200:
            print(f"demo: FAILED — approved retry got {retry.status_code} {retry.text}")
            return 1
        retry_body = retry.json()
        print(
            f"demo:     retry → {retry_body['result']['refund_id']} issued "
            f"(reasons {','.join(retry_body['reason_codes'])})"
        )

        replay = call("issue_refund", refund_args, key)
        if replay.status_code != 202:
            print(f"demo: FAILED — replay got {replay.status_code} {replay.text}")
            return 1
        print(
            "demo:     replay → PENDING again "
            f"(new approval {replay.json()['approval']['id'][:8]}…) — "
            "the consumed approval cannot execute twice"
        )
        print()

        # Act 3 — the external email is denied, no human needed.
        print("demo: [3] send_email to victim@external.example")
        response = call(
            "send_email",
            {"to": "victim@external.example", "subject": "order data", "body": "…"},
        )
        if response.status_code != 403:
            print(f"demo: FAILED — expected deny, got {response.status_code} {response.text}")
            return 1
        print(f"demo:     {_decision_line(response.json()['detail'])}")
        print("demo:     destination called: NO")
        print()

        # Act 4 — one query, the whole story.
        print(f"demo: [4] timeline for trace {trace_id[:8]}…")
        timeline = api.get("/v1/timeline", params={"trace_id": trace_id}).json()
        for event in timeline:
            verdict = event["verdict"] or "—"
            print(
                f"demo:     {event['created_at'][11:19]}  {event['type']:9} "
                f"{verdict:17} {event['rule']}"
            )
        print()
        print(
            "demo: every step above is correlated evidence; the card token and "
            "customer note never left the gateway (redacted before transmission, "
            "and marked as such to the approver)."
        )
        return 0
    except httpx.HTTPError as exc:
        print(f"demo: FAILED — {exc}. Is 'make dev' running (and 'make migrate' applied)?")
        return 1
    finally:
        api.close()
        gateway.close()


if __name__ == "__main__":
    sys.exit(main())
