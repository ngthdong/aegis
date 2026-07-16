from __future__ import annotations

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"


def _init_and_unseal(client: TestClient) -> None:
    resp = client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200, resp.text
    resp = client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200, resp.text


def test_vault_lifecycle_over_http(client: TestClient):
    assert client.get("/v1/vault/status").json() == {"status": "uninitialized"}

    resp = client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}

    resp = client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200
    assert resp.json() == {"status": "unsealed"}

    resp = client.post("/v1/vault/seal")
    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}


def test_wrong_passphrase_over_http_returns_401(client: TestClient):
    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    resp = client.post("/v1/vault/unseal", json={"passphrase": "wrong"})
    assert resp.status_code == 401


def test_double_init_returns_409(client: TestClient):
    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    resp = client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 409


def test_registration_rejected_while_vault_sealed(client: TestClient):
    resp = client.post(
        "/v1/auth/register", json={"username": "alice", "password": "correct-horse-battery"}
    )
    assert resp.status_code == 503


def test_registration_succeeds_once_unsealed(client: TestClient):
    _init_and_unseal(client)

    resp = client.post(
        "/v1/auth/register", json={"username": "alice", "password": "correct-horse-battery"}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "user_id" in body
    assert len(body["user_id"]) == 32  # uuid4().hex length


def test_duplicate_username_returns_409(client: TestClient):
    _init_and_unseal(client)
    client.post(
        "/v1/auth/register", json={"username": "alice", "password": "correct-horse-battery"}
    )
    resp = client.post(
        "/v1/auth/register", json={"username": "alice", "password": "another-good-password"}
    )
    assert resp.status_code == 409


def test_weak_password_returns_422(client: TestClient):
    _init_and_unseal(client)
    resp = client.post("/v1/auth/register", json={"username": "bob", "password": "short"})
    assert resp.status_code == 422


def test_password_is_never_stored_or_returned_in_plaintext(client: TestClient):
    _init_and_unseal(client)
    raw_password = "correct-horse-battery"

    resp = client.post("/v1/auth/register", json={"username": "carol", "password": raw_password})
    assert resp.status_code == 201
    assert raw_password not in resp.text

    # Reach into storage directly to check what actually landed on disk.
    # this is the only place in this test file allowed to do that, and
    # only to prove the security property, not to exercise behavior.
    from sqlalchemy import select

    from aegis.storage.models import UserRow

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        row = session.execute(select(UserRow).where(UserRow.username == "carol")).scalar_one()
        assert row.password_hash != raw_password
        assert row.password_hash.startswith("$argon2id$")
