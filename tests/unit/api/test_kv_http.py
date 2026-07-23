from __future__ import annotations

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"
PASSWORD = "correct-horse-battery"


def _setup_vault(client: TestClient) -> None:
    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})


def _register_and_login(client: TestClient, username: str) -> str:
    resp = client.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 201, resp.text
    resp = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_write_then_read_round_trips_over_http(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    resp = client.put("/v1/kv/db/password", json={"value": "hunter2"}, headers=headers)
    assert resp.status_code == 204

    resp = client.get("/v1/kv/db/password", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"value": "hunter2"}


def test_read_nonexistent_path_returns_404(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    resp = client.get("/v1/kv/does/not/exist", headers=_auth_header(token))
    assert resp.status_code == 404


def test_write_without_token_returns_401(client: TestClient):
    _setup_vault(client)
    resp = client.put("/v1/kv/some/path", json={"value": "x"})
    assert resp.status_code == 401


def test_write_while_sealed_returns_503(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")

    client.post("/v1/vault/seal")

    resp = client.put("/v1/kv/some/path", json={"value": "x"}, headers=_auth_header(token))
    assert resp.status_code == 503


def test_non_owner_cannot_read_returns_403(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.put(
        "/v1/kv/alices/secret", json={"value": "only-alice"}, headers=_auth_header(alice_token)
    )

    resp = client.get("/v1/kv/alices/secret", headers=_auth_header(bob_token))
    assert resp.status_code == 403


def test_non_owner_cannot_overwrite_returns_403(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.put(
        "/v1/kv/alices/secret", json={"value": "original"}, headers=_auth_header(alice_token)
    )

    resp = client.put(
        "/v1/kv/alices/secret",
        json={"value": "overwritten"},
        headers=_auth_header(bob_token),
    )
    assert resp.status_code == 403

    resp = client.get("/v1/kv/alices/secret", headers=_auth_header(alice_token))
    assert resp.json() == {"value": "original"}


def test_non_owner_cannot_delete_returns_403(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.put("/v1/kv/alices/secret", json={"value": "x"}, headers=_auth_header(alice_token))

    resp = client.delete("/v1/kv/alices/secret", headers=_auth_header(bob_token))
    assert resp.status_code == 403

    resp = client.get("/v1/kv/alices/secret", headers=_auth_header(alice_token))
    assert resp.status_code == 200


def test_delete_then_read_returns_404(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.put("/v1/kv/temp/secret", json={"value": "x"}, headers=headers)
    resp = client.delete("/v1/kv/temp/secret", headers=headers)
    assert resp.status_code == 204

    resp = client.get("/v1/kv/temp/secret", headers=headers)
    assert resp.status_code == 404


def test_nested_path_with_multiple_slashes_works(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    resp = client.put("/v1/kv/prod/db/replica-1/password", json={"value": "x"}, headers=headers)
    assert resp.status_code == 204

    resp = client.get("/v1/kv/prod/db/replica-1/password", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"value": "x"}


def test_tampered_row_over_real_sqlite_returns_500(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.put("/v1/kv/tamper/target", json={"value": "hunter2"}, headers=headers)

    from sqlalchemy import select

    from aegis.storage.models import SecretRow

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        row = session.execute(
            select(SecretRow).where(SecretRow.path == "tamper/target")
        ).scalar_one()
        tampered = bytearray(row.ciphertext)
        tampered[0] ^= 0xFF
        row.ciphertext = bytes(tampered)
        session.commit()

    resp = client.get("/v1/kv/tamper/target", headers=headers)
    assert resp.status_code == 500
