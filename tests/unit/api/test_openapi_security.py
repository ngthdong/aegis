from __future__ import annotations

from fastapi.testclient import TestClient

# Every path+method that must require the Bearer session token.
PROTECTED_OPERATIONS = {
    ("post", "/v1/vault/seal"),
    ("get", "/v1/auth/me"),
    ("post", "/v1/auth/logout"),
    ("put", "/v1/kv/{path}"),
    ("get", "/v1/kv/{path}"),
    ("delete", "/v1/kv/{path}"),
    ("post", "/v1/transit/keys/{name}"),
    ("delete", "/v1/transit/keys/{name}"),
    ("post", "/v1/transit/keys/{name}/encrypt"),
    ("post", "/v1/transit/keys/{name}/decrypt"),
    ("post", "/v1/transit/keys/{name}/sign"),
    ("post", "/v1/transit/keys/{name}/verify"),
    ("post", "/v1/transit/keys/{name}/rotate"),
    ("post", "/v1/transit/keys/{name}/disable"),
    ("get", "/v1/audit"),
}

# Bootstrap/lifecycle and unauthenticated endpoints that must NOT require it.
PUBLIC_OPERATIONS = {
    ("get", "/health"),
    ("get", "/ready"),
    ("post", "/v1/vault/init"),
    ("post", "/v1/vault/unseal"),
    ("get", "/v1/vault/status"),
    ("post", "/v1/auth/register"),
    ("post", "/v1/auth/login"),
}


def _openapi_schema(client: TestClient) -> dict:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    return resp.json()


def test_openapi_declares_http_bearer_security_scheme(client: TestClient):
    schema = _openapi_schema(client)

    scheme = schema["components"]["securitySchemes"]["HTTPBearer"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"


def test_protected_operations_require_bearer_security(client: TestClient):
    schema = _openapi_schema(client)

    for method, path in PROTECTED_OPERATIONS:
        operation = schema["paths"][path][method]
        assert operation.get("security") == [{"HTTPBearer": []}], (
            f"{method.upper()} {path} should require HTTPBearer security"
        )


def test_public_operations_do_not_require_bearer_security(client: TestClient):
    schema = _openapi_schema(client)

    for method, path in PUBLIC_OPERATIONS:
        operation = schema["paths"][path][method]
        assert not operation.get("security"), (
            f"{method.upper()} {path} should not require authentication"
        )


def test_docs_ui_is_served(client: TestClient):
    resp = client.get("/docs")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_swagger_authorize_flow_end_to_end(client: TestClient):
    """
    Simulates exactly what Swagger UI's "Authorize" button does: obtain a
    token from /v1/auth/login, then send it as `Authorization: Bearer
    <token>` on a protected call — the same header Swagger attaches
    automatically to every operation once authorized.
    """
    passphrase = "correct horse battery staple"
    admin_password = "correct-horse-battery-admin"

    resp = client.post(
        "/v1/vault/init",
        json={
            "passphrase": passphrase,
            "admin_username": "root",
            "admin_password": admin_password,
        },
    )
    assert resp.status_code == 200
    client.post("/v1/vault/unseal", json={"passphrase": passphrase})

    resp = client.post("/v1/auth/login", json={"username": "root", "password": admin_password})
    assert resp.status_code == 200
    token = resp.json()["token"]

    resp = client.post("/v1/vault/seal", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}
