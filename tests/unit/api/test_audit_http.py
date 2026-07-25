from __future__ import annotations

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"
PASSWORD = "correct-horse-battery"


def _setup_vault(client: TestClient) -> None:
    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})


def _register_and_login(client: TestClient, username: str) -> tuple[str, str]:
    resp = client.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    user_id = resp.json()["user_id"]
    resp = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    return resp.json()["token"], user_id


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_query_own_audit_trail_returns_own_events(client: TestClient):
    _setup_vault(client)
    token, user_id = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.put("/v1/kv/audit-test/path", json={"value": "x"}, headers=headers)

    resp = client.get("/v1/audit", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["events"]) >= 1
    assert all(e["principal_id"] == user_id for e in body["events"])


def test_cannot_query_another_principals_audit_trail(client: TestClient):
    _setup_vault(client)
    alice_token, alice_id = _register_and_login(client, "alice")
    bob_token, _bob_id = _register_and_login(client, "bob")

    client.put("/v1/kv/alices-secret", json={"value": "x"}, headers=_auth_header(alice_token))

    resp = client.get(f"/v1/audit?principal_id={alice_id}", headers=_auth_header(bob_token))
    assert resp.status_code == 403


def test_default_query_scopes_to_caller_even_without_principal_id_param(client: TestClient):
    _setup_vault(client)
    alice_token, _ = _register_and_login(client, "alice")
    bob_token, bob_id = _register_and_login(client, "bob")

    client.put("/v1/kv/alices-secret-2", json={"value": "x"}, headers=_auth_header(alice_token))
    client.put("/v1/kv/bobs-secret", json={"value": "x"}, headers=_auth_header(bob_token))

    resp = client.get("/v1/audit", headers=_auth_header(bob_token))
    body = resp.json()
    assert all(e["principal_id"] == bob_id for e in body["events"])
    assert not any(e["resource_id"] == "alices-secret-2" for e in body["events"])


def test_filter_by_action(client: TestClient):
    _setup_vault(client)
    token, _ = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.put("/v1/kv/filter-test", json={"value": "x"}, headers=headers)
    client.get("/v1/kv/filter-test", headers=headers)

    resp = client.get("/v1/audit?action=kv.write", headers=headers)
    body = resp.json()
    assert len(body["events"]) >= 1
    assert all(e["action"] == "kv.write" for e in body["events"])


def test_limit_is_enforced(client: TestClient):
    _setup_vault(client)
    token, _ = _register_and_login(client, "alice")
    headers = _auth_header(token)

    for i in range(5):
        client.put(f"/v1/kv/limit-test-{i}", json={"value": "x"}, headers=headers)

    resp = client.get("/v1/audit?limit=2", headers=headers)
    body = resp.json()
    assert len(body["events"]) == 2


def test_limit_over_max_is_rejected(client: TestClient):
    _setup_vault(client)
    token, _ = _register_and_login(client, "alice")

    resp = client.get("/v1/audit?limit=99999", headers=_auth_header(token))
    assert resp.status_code == 422


def test_query_without_token_returns_401(client: TestClient):
    resp = client.get("/v1/audit")
    assert resp.status_code == 401


def test_events_are_returned_newest_first(client: TestClient):
    _setup_vault(client)
    token, _ = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.put("/v1/kv/order-test-1", json={"value": "x"}, headers=headers)
    client.put("/v1/kv/order-test-2", json={"value": "x"}, headers=headers)

    resp = client.get("/v1/audit?action=kv.write&limit=2", headers=headers)
    events = resp.json()["events"]
    assert events[0]["resource_id"] == "order-test-2"
    assert events[1]["resource_id"] == "order-test-1"
