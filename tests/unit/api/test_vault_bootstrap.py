from __future__ import annotations

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"
ADMIN_USERNAME = "root"
ADMIN_PASSWORD = "correct-horse-battery-admin"


def _init_body(**overrides: str) -> dict[str, str]:
    body = {
        "passphrase": PASSPHRASE,
        "admin_username": ADMIN_USERNAME,
        "admin_password": ADMIN_PASSWORD,
    }
    body.update(overrides)
    return body


def test_bootstrap_creates_vault_and_admin(client: TestClient):
    resp = client.post("/v1/vault/init", json=_init_body())

    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}


def test_vault_remains_sealed_after_bootstrap(client: TestClient):
    client.post("/v1/vault/init", json=_init_body())

    assert client.get("/v1/vault/status").json() == {"status": "sealed"}


def test_bootstrap_does_not_create_a_session_or_return_secrets(client: TestClient):
    resp = client.post("/v1/vault/init", json=_init_body())

    body = resp.json()
    assert body == {"status": "sealed"}
    assert "token" not in resp.text
    assert PASSPHRASE not in resp.text
    assert ADMIN_PASSWORD not in resp.text


def test_admin_password_is_stored_only_as_argon2id_hash(client: TestClient):
    client.post("/v1/vault/init", json=_init_body())

    from sqlalchemy import select

    from aegis.storage.models import UserRow

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        row = session.execute(
            select(UserRow).where(UserRow.username == ADMIN_USERNAME)
        ).scalar_one()
        assert row.password_hash != ADMIN_PASSWORD
        assert row.password_hash.startswith("$argon2id$")
        assert row.role == "admin"


def test_passphrase_is_not_persisted_as_plaintext(client: TestClient):
    client.post("/v1/vault/init", json=_init_body())

    from sqlalchemy import select

    from aegis.storage.models import VaultMetaRow

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        row = session.execute(select(VaultMetaRow)).scalar_one()
        assert PASSPHRASE.encode() not in row.dek_ciphertext
        assert PASSPHRASE.encode() not in row.kdf_salt


def test_second_init_call_fails(client: TestClient):
    resp = client.post("/v1/vault/init", json=_init_body())
    assert resp.status_code == 200

    resp = client.post("/v1/vault/init", json=_init_body(admin_username="someone-else"))
    assert resp.status_code == 409


def test_second_init_call_does_not_create_a_second_admin(client: TestClient):
    client.post("/v1/vault/init", json=_init_body())
    client.post("/v1/vault/init", json=_init_body(admin_username="someone-else"))

    from sqlalchemy import func, select

    from aegis.storage.models import UserRow

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        count = session.execute(select(func.count()).select_from(UserRow)).scalar_one()
        assert count == 1


def test_admin_can_unseal_login_and_seal(client: TestClient):
    resp = client.post("/v1/vault/init", json=_init_body())
    assert resp.status_code == 200

    resp = client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    assert resp.status_code == 200
    assert resp.json() == {"status": "unsealed"}

    resp = client.post(
        "/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    assert resp.status_code == 200
    token = resp.json()["token"]

    resp = client.post("/v1/vault/seal", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}


def test_weak_admin_password_is_rejected(client: TestClient):
    resp = client.post("/v1/vault/init", json=_init_body(admin_password="short"))

    assert resp.status_code == 422
    assert client.get("/v1/vault/status").json() == {"status": "uninitialized"}


def test_bootstrap_failure_after_vault_init_rolls_back_vault(client: TestClient):
    from aegis.api.dependencies import get_user_repository

    class FailingUserRepository:
        def get_by_username(self, username: str) -> None:
            return None

        def save(self, user: object) -> None:
            raise RuntimeError("simulated user creation failure")

        def update_login_state(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("not expected to be called")

    client.app.dependency_overrides[get_user_repository] = lambda: FailingUserRepository()
    try:
        no_raise_client = TestClient(client.app, raise_server_exceptions=False)
        resp = no_raise_client.post("/v1/vault/init", json=_init_body())
        assert resp.status_code == 500
    finally:
        client.app.dependency_overrides.pop(get_user_repository, None)

    # The vault must not be left half-initialized: status reverts to
    # uninitialized, and a normal retry succeeds cleanly.
    assert client.get("/v1/vault/status").json() == {"status": "uninitialized"}

    resp = client.post("/v1/vault/init", json=_init_body())
    assert resp.status_code == 200
    assert resp.json() == {"status": "sealed"}
