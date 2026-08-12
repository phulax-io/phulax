"""Seed the demo environment: org, owner, agent v1.0.0, three tools, and
the canonical policy bundle (plan §7.2).

Idempotent — safe to run repeatedly (the bundle is republished only when
its rules differ from the latest published version). Talks to the
control-plane API only (never the DB directly), so the seed exercises the
same surface agents use.
"""

import os
import sys

import httpx
import yaml
from phulax_policy.examples import CANONICAL_BUNDLE_YAML
from phulax_policy.signing import verify_bundle

API_URL = f"http://127.0.0.1:{os.environ.get('API_PORT', '8000')}"

TOOLS = [
    {
        "name": "read_order",
        "description": "Read one order by id (simulated)",
        "args_schema": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
            "additionalProperties": False,
        },
        "sensitivity": "low",
        "side_effect": "read",
    },
    {
        "name": "send_email",
        "description": "Send a customer email (simulated)",
        "args_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
        "sensitivity": "medium",
        "side_effect": "write",
    },
    {
        "name": "issue_refund",
        "description": "Refund a payment (simulated)",
        "args_schema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount": {"type": "number", "exclusiveMinimum": 0},
                "card_token": {"type": "string"},
                "customer_note": {"type": "string"},
            },
            "required": ["order_id", "amount"],
        },
        "sensitivity": "high",
        "side_effect": "write",
        # Redacted by the gateway before an approval preview leaves it.
        "sensitive_fields": ["card_token", "customer_note"],
    },
]


def publish_bundle_if_changed(client: httpx.Client, org_id: str) -> dict:
    """Publish the canonical bundle unless the latest version already
    carries exactly these rules AND still verifies under the current
    public key — after a key rotation the old signature is dead weight
    and the gateway would (correctly) reject it."""
    canonical_rules = yaml.safe_load(CANONICAL_BUNDLE_YAML)["rules"]
    public_key = os.environ.get("POLICY_PUBLIC_KEY", "")
    latest = client.get("/v1/policy-bundles/latest", params={"org_id": org_id})
    if latest.status_code == 200:
        bundle = latest.json()
        if bundle["rules"] == canonical_rules and verify_bundle(
            public_key,
            version=bundle["version"],
            rules_data=bundle["rules"],
            signature=bundle["signature"],
        ):
            return bundle
    response = client.post(
        "/v1/policy-bundles", json={"org_id": org_id, "document": CANONICAL_BUNDLE_YAML}
    )
    response.raise_for_status()
    return response.json()


def get_or_create(client: httpx.Client, path: str, body: dict, lookup: dict) -> dict:
    existing = client.get(path, params=lookup).json()
    if existing:
        return existing[0]
    response = client.post(path, json=body)
    response.raise_for_status()
    return response.json()


def main() -> int:
    try:
        with httpx.Client(base_url=API_URL, timeout=10.0) as client:
            client.get("/health").raise_for_status()

            org = get_or_create(
                client, "/v1/organizations", {"name": "demo-org"}, {"name": "demo-org"}
            )
            owner = get_or_create(
                client,
                "/v1/users",
                {"org_id": org["id"], "email": "founder@demo-org.dev", "name": "Demo Founder"},
                {"org_id": org["id"], "email": "founder@demo-org.dev"},
            )
            agent = get_or_create(
                client,
                "/v1/agents",
                {
                    "org_id": org["id"],
                    "name": "refund-agent",
                    "owner_user_id": owner["id"],
                    "version": "1.0.0",
                    "manifest": {
                        "model": "claude-sonnet-5",
                        "tools": [tool["name"] for tool in TOOLS],
                    },
                },
                {"org_id": org["id"], "name": "refund-agent"},
            )
            finance = get_or_create(
                client,
                "/v1/users",
                {
                    "org_id": org["id"],
                    "email": "finance@demo-org.dev",
                    "name": "Fin Approver",
                    "role": "finance_approver",
                },
                {"org_id": org["id"], "email": "finance@demo-org.dev"},
            )
            seeded_tools = []
            stale_tools = []
            for tool in TOOLS:
                created = get_or_create(
                    client,
                    "/v1/tools",
                    {"org_id": org["id"], **tool},
                    {"org_id": org["id"], "name": tool["name"]},
                )
                if created["args_schema"] != tool["args_schema"] or created[
                    "sensitive_fields"
                ] != tool.get("sensitive_fields", []):
                    stale_tools.append(created["name"])
                seeded_tools.append(
                    f"{created['name']} ({created['sensitivity']}/{created['side_effect']})"
                )

            bundle = publish_bundle_if_changed(client, org["id"])
            rule_ids = ", ".join(rule["id"] for rule in bundle["rules"])

            print(f"seed: org        {org['name']} ({org['id']})")
            print(f"seed: owner      {owner['email']}")
            print(f"seed: approver   {finance['email']} (role {finance['role']})")
            print(f"seed: agent      {agent['name']} v{agent['latest_version']['version']}")
            print(f"seed: tools      {', '.join(seeded_tools)}")
            print(f"seed: policy     bundle v{bundle['version']} (signed): {rule_ids}")
            if stale_tools:
                print(
                    f"seed: WARNING    tool(s) {', '.join(stale_tools)} already exist with an "
                    "older definition — reset dev data to pick up the new schema: "
                    "docker compose down -v && make dev migrate seed"
                )
            return 0
    except httpx.HTTPError as exc:
        print(f"seed: FAILED talking to {API_URL} — is 'make dev' running? ({exc})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
