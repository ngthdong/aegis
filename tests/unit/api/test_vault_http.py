from __future__ import annotations

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"
PASSWORD = "correct-horse-battery"
BOOTSTRAP_ADMIN_USERNAME = "bootstrap-admin"
BOOTSTRAP_ADMIN_PASSWORD = "correct-horse-battery-admin"


def _setup_vault(client: TestClient) -> None:
    resp = client.post(
        "/v1/vault/init",
        json={
            "passphrase": PASSPHRASE,
            "admin_username": BOOTSTRAP_ADMIN_USERNAME,
            "admin_password": BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    assert resp.status_code == 200, resp.text
    resp = client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200, resp.text


def _register_and_login(client: TestClient, username: str) -> str:
    resp = client.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 201, resp.text
    resp = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _make_admin_token(client: TestClient, username: str) -> str:
    from sqlalchemy import select

    from aegis.storage.models import UserRow

    _register_and_login(client, username)
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        row = session.execute(select(UserRow).where(UserRow.username == username)).scalar_one()
        row.role = "admin"
        session.commit()

    # Role is baked into the session at login time, so promoting the DB row
    # after the fact requires a fresh login to pick it up.
    resp = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_seal_the_vault(client: TestClient):
    _setup_vault(client)
    admin_token = _make_admin_token(client, "root")

    resp = client.post("/v1/vault/seal", headers=_auth_header(admin_token))

    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}
    assert client.get("/v1/vault/status").json() == {"status": "sealed"}


def test_seal_does_not_accept_a_passphrase_body(client: TestClient):
    _setup_vault(client)
    admin_token = _make_admin_token(client, "root")

    resp = client.post(
        "/v1/vault/seal",
        json={"passphrase": PASSPHRASE},
        headers=_auth_header(admin_token),
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}


def test_seal_without_token_returns_401(client: TestClient):
    _setup_vault(client)

    resp = client.post("/v1/vault/seal")

    assert resp.status_code == 401


def test_seal_with_invalid_token_returns_401(client: TestClient):
    _setup_vault(client)

    resp = client.post("/v1/vault/seal", headers=_auth_header("not-a-real-token"))

    assert resp.status_code == 401


def test_seal_by_non_admin_returns_403(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")

    resp = client.post("/v1/vault/seal", headers=_auth_header(token))

    assert resp.status_code == 403
    # Vault must remain unsealed after a denied attempt.
    assert client.get("/v1/vault/status").json() == {"status": "unsealed"}


def test_sealing_an_already_sealed_vault_returns_409(client: TestClient):
    _setup_vault(client)
    admin_token = _make_admin_token(client, "root")

    resp = client.post("/v1/vault/seal", headers=_auth_header(admin_token))
    assert resp.status_code == 200

    resp = client.post("/v1/vault/seal", headers=_auth_header(admin_token))
    assert resp.status_code == 409


def test_seal_preserves_encrypted_data_on_disk(client: TestClient):
    _setup_vault(client)
    admin_token = _make_admin_token(client, "root")
    token = _register_and_login(client, "alice")

    resp = client.put("/v1/kv/some/secret", json={"value": "hunter2"}, headers=_auth_header(token))
    assert resp.status_code == 204

    resp = client.post("/v1/vault/seal", headers=_auth_header(admin_token))
    assert resp.status_code == 200

    from sqlalchemy import select

    from aegis.storage.models import SecretRow, SecretVersionRow, VaultMetaRow

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        vault_meta = session.execute(select(VaultMetaRow)).scalar_one()
        assert vault_meta.dek_ciphertext  # encrypted DEK survives sealing

        secret = session.execute(select(SecretRow)).scalar_one()
        version = session.execute(
            select(SecretVersionRow).where(SecretVersionRow.secret_id == secret.id)
        ).scalar_one()
        assert version.ciphertext  # encrypted secret data survives sealing

    # And it's still readable once unsealed again.
    resp = client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200
    resp = client.get("/v1/kv/some/secret", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.json() == {"value": "hunter2"}


def test_dek_is_unavailable_after_admin_seal(client: TestClient):
    _setup_vault(client)
    admin_token = _make_admin_token(client, "root")

    vault_service = client.app.state.vault_service
    assert vault_service.get_dek()  # unsealed: DEK is available

    resp = client.post("/v1/vault/seal", headers=_auth_header(admin_token))
    assert resp.status_code == 200

    from aegis.core.service import VaultNotInitialized

    try:
        vault_service.get_dek()
        raise AssertionError("expected get_dek() to raise after sealing")
    except VaultNotInitialized:
        pass
