import hashlib

import pytest
from fastapi.testclient import TestClient

from aegisvault.api import create_app


@pytest.fixture
def client(vault):
    credentials = [
        {
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "tenant": tenant,
            "actor": "test-host",
            "roles": roles,
            "purpose": "support",
        }
        for token, tenant, roles in [
            ("test-admin-a", "a", ["admin"]),
            ("test-reader-b", "b", ["reader"]),
        ]
    ]
    with TestClient(create_app(vault, credentials)) as c:
        yield c


def test_authenticated_http_journey_and_tenant_cannot_be_overridden(client, doc):
    admin = {"Authorization": "Bearer test-admin-a"}
    other = {"Authorization": "Bearer test-reader-b"}
    path = "/api/records/customers/a"
    assert client.put(path, json={"document": doc}).status_code == 403
    assert client.put(path, headers=admin, json={"document": doc}).json()["revision"] == 1
    assert client.get(path, headers=admin).json()["document"] == doc
    assert client.get(path, headers=other).status_code == 404
    assert client.put(path, headers=admin, json={"document": doc, "tenant": "b"}).status_code == 422
    assert client.post(
        "/api/search/customers", headers=admin, json={"field": "email", "values": [doc["email"]]}
    ).json()["records"]
    assert client.get("/api/audit/checkpoint", headers=admin).json()["seq"] == 3
    assert client.get("/api/audit/checkpoint", headers=other).status_code == 403
    assert client.request("DELETE", path, headers=admin, json={"expected_revision": 1}).json() == {
        "deleted": True
    }
    assert client.get(path, headers=admin).status_code == 404


def test_no_plaintext_in_validation_errors_or_cache(client):
    response = client.put(
        "/api/records/customers/a",
        headers={"Authorization": "Bearer test-admin-a"},
        json={"document": "highly-sensitive-plaintext"},
    )
    assert response.status_code == 422
    assert "highly-sensitive" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert (
        client.put("/api/records/customers/a", content=b"x" * (512 * 1024 + 1)).status_code == 413
    )


def test_console_and_health_require_no_secrets(client):
    assert client.get("/healthz").json()["production_qualified"] is False
    assert "AegisVault" in client.get("/").text
    assert client.get("/console.js").status_code == 200
    assert client.get("/console.css").status_code == 200
    assert "frame-ancestors 'none'" in client.get("/").headers["content-security-policy"]
