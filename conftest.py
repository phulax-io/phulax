"""Shared test infrastructure: real Postgres, migrated schema, app clients.

Integration tests run against the compose Postgres (`make dev`); CI provides
a service container. Each test namespace gets its own throwaway database so
migration tests can't disturb data tests.
"""

import os
from collections.abc import Iterator

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from phulax_policy.examples import CANONICAL_BUNDLE_YAML
from phulax_policy.signing import generate_keypair

# There is no checked-in policy keypair (T08): tests run against an
# ephemeral one, injected before any Settings object is instantiated.
# setdefault so an explicit pair (e.g. from --env-file .env) wins.
_test_private_key, _test_public_key = generate_keypair()
os.environ.setdefault("POLICY_SIGNING_KEY", _test_private_key)
os.environ.setdefault("POLICY_PUBLIC_KEY", _test_public_key)

from phulax_api.settings import get_settings  # noqa: E402
from sqlalchemy import Engine, create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

ALEMBIC_INI = "apps/api/alembic.ini"
ALL_TABLES = (
    "events, action_requests, executions, policy_bundles, sessions, tools, "
    "agent_versions, agents, users, organizations"
)


def _swap_database(url: str, dbname: str) -> str:
    base, _, _ = url.rpartition("/")
    return f"{base}/{dbname}"


class DbAdmin:
    """Create/drop throwaway test databases on the dev Postgres server."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self._engine = create_engine(
            _swap_database(base_url, "postgres"), isolation_level="AUTOCOMMIT"
        )

    def fresh_database(self, name: str) -> str:
        with self._engine.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            conn.execute(text(f'CREATE DATABASE "{name}"'))
        return _swap_database(self.base_url, name)

    def drop(self, name: str) -> None:
        with self._engine.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))

    def dispose(self) -> None:
        self._engine.dispose()


def alembic_config(database_url: str) -> Config:
    cfg = Config(ALEMBIC_INI)
    cfg.attributes["database_url"] = database_url
    return cfg


@pytest.fixture(scope="session")
def db_admin() -> Iterator[DbAdmin]:
    admin = DbAdmin(get_settings().sqlalchemy_url)
    yield admin
    admin.dispose()


@pytest.fixture(scope="session")
def test_engine(db_admin: DbAdmin) -> Iterator[Engine]:
    url = db_admin.fresh_database("phulax_test")
    command.upgrade(alembic_config(url), "head")
    engine = create_engine(url)
    yield engine
    engine.dispose()
    db_admin.drop("phulax_test")


@pytest.fixture()
def clean_db(test_engine: Engine) -> Engine:
    with test_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {ALL_TABLES} CASCADE"))
    return test_engine


@pytest.fixture()
def api_app(clean_db: Engine):
    from phulax_api.db import get_db
    from phulax_api.main import create_app

    factory = sessionmaker(bind=clean_db, expire_on_commit=False)

    def override_get_db():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture()
def api_client(api_app) -> Iterator[TestClient]:
    with TestClient(api_app) as client:
        yield client


@pytest.fixture()
def gateway_client(api_app) -> Iterator[TestClient]:
    """Gateway wired to the in-process API app: the full skeleton in one loop."""
    from phulax_gateway.control_plane import ControlPlaneClient
    from phulax_gateway.main import create_app as create_gateway_app
    from phulax_gateway.settings import Settings as GatewaySettings

    transport = httpx.ASGITransport(app=api_app)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://api.test")
    control_plane = ControlPlaneClient("http://api.test", client=http_client)
    app = create_gateway_app(settings=GatewaySettings(), control_plane=control_plane)
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def seeded(api_client: TestClient) -> dict:
    """The standard walking-skeleton fixture set: org, owner, agent v1.0.0,
    demo tools, a staging session, and a fresh dev token."""
    org = api_client.post("/v1/organizations", json={"name": "demo-org"}).json()
    owner = api_client.post(
        "/v1/users",
        json={"org_id": org["id"], "email": "founder@demo-org.dev", "name": "Demo Founder"},
    ).json()
    agent = api_client.post(
        "/v1/agents",
        json={
            "org_id": org["id"],
            "name": "refund-agent",
            "owner_user_id": owner["id"],
            "version": "1.0.0",
            "manifest": {"model": "claude-sonnet-5", "tools": ["read_order"]},
        },
    ).json()
    api_client.post(
        "/v1/tools",
        json={
            "org_id": org["id"],
            "name": "read_order",
            "description": "Read one order by id",
            "args_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
                "additionalProperties": False,
            },
            "sensitivity": "low",
            "side_effect": "read",
        },
    )
    for name, sensitivity, side_effect, args_schema in (
        (
            "send_email",
            "medium",
            "write",
            {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        ),
        (
            "issue_refund",
            "high",
            "write",
            {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "amount": {"type": "number", "exclusiveMinimum": 0},
                },
                "required": ["order_id", "amount"],
            },
        ),
    ):
        api_client.post(
            "/v1/tools",
            json={
                "org_id": org["id"],
                "name": name,
                "description": f"{name} (simulated)",
                "args_schema": args_schema,
                "sensitivity": sensitivity,
                "side_effect": side_effect,
            },
        )
    bundle = api_client.post(
        "/v1/policy-bundles",
        json={"org_id": org["id"], "document": CANONICAL_BUNDLE_YAML},
    ).json()
    session = api_client.post(
        "/v1/sessions",
        json={
            "agent_version_id": agent["latest_version"]["id"],
            "environment": "staging",
        },
    ).json()
    token = api_client.post("/v1/tokens", json={"session_id": session["id"]}).json()
    return {
        "org": org,
        "owner": owner,
        "agent": agent,
        "bundle": bundle,
        "session": session,
        "token": token["token"],
    }
