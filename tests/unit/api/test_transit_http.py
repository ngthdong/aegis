from __future__ import annotations

import base64

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"
PASSWORD = "correct-horse-battery"
ADMIN_USERNAME = "bootstrap-admin"
ADMIN_PASSWORD = "correct-horse-battery-admin"


def _setup_vault(client: TestClient) -> None:
    client.post(
        "/v1/vault/init",
        json={
            "passphrase": PASSPHRASE,
            "admin_username": ADMIN_USERNAME,
            "admin_password": ADMIN_PASSWORD,
        },
    )
    client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})


def _register_and_login(client: TestClient, username: str) -> str:
    resp = client.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 201, resp.text
    resp = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def test_create_encrypt_decrypt_round_trips_over_http(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    resp = client.post("/v1/transit/keys/app-1", headers=headers)
    assert resp.status_code == 201

    resp = client.post(
        "/v1/transit/keys/app-1/encrypt",
        json={"plaintext": _b64(b"hello world")},
        headers=headers,
    )
    assert resp.status_code == 200
    ciphertext = resp.json()["ciphertext"]
    assert ciphertext != _b64(b"hello world")

    resp = client.post(
        "/v1/transit/keys/app-1/decrypt", json={"ciphertext": ciphertext}, headers=headers
    )
    assert resp.status_code == 200
    plaintext = base64.b64decode(resp.json()["plaintext"])
    assert plaintext == b"hello world"


def test_duplicate_key_name_returns_409(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.post("/v1/transit/keys/app-1", headers=headers)
    resp = client.post("/v1/transit/keys/app-1", headers=headers)
    assert resp.status_code == 409


def test_encrypt_under_nonexistent_key_returns_404(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    resp = client.post(
        "/v1/transit/keys/does-not-exist/encrypt",
        json={"plaintext": _b64(b"data")},
        headers=_auth_header(token),
    )
    assert resp.status_code == 404


def test_non_owner_cannot_encrypt_under_someone_elses_key(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.post("/v1/transit/keys/alices-key", headers=_auth_header(alice_token))

    resp = client.post(
        "/v1/transit/keys/alices-key/encrypt",
        json={"plaintext": _b64(b"data")},
        headers=_auth_header(bob_token),
    )
    assert resp.status_code == 403


def test_non_owner_cannot_decrypt_under_someone_elses_key(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.post("/v1/transit/keys/alices-key", headers=_auth_header(alice_token))
    resp = client.post(
        "/v1/transit/keys/alices-key/encrypt",
        json={"plaintext": _b64(b"data")},
        headers=_auth_header(alice_token),
    )
    ciphertext = resp.json()["ciphertext"]

    resp = client.post(
        "/v1/transit/keys/alices-key/decrypt",
        json={"ciphertext": ciphertext},
        headers=_auth_header(bob_token),
    )
    assert resp.status_code == 403


def test_tampered_ciphertext_returns_400_not_500(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.post("/v1/transit/keys/app-1", headers=headers)
    resp = client.post(
        "/v1/transit/keys/app-1/encrypt",
        json={"plaintext": _b64(b"hello world")},
        headers=headers,
    )
    ciphertext = resp.json()["ciphertext"]

    raw = bytearray(base64.b64decode(ciphertext))
    raw[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode("ascii")

    resp = client.post(
        "/v1/transit/keys/app-1/decrypt", json={"ciphertext": tampered}, headers=headers
    )
    assert resp.status_code == 400


def test_create_key_while_sealed_returns_503(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    admin_token = _make_admin_token(client, "admin-user")

    resp = client.post("/v1/vault/seal", headers=_auth_header(admin_token))
    assert resp.status_code == 200

    resp = client.post("/v1/transit/keys/app-1", headers=_auth_header(token))
    assert resp.status_code == 503


def test_binary_plaintext_round_trips_correctly(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    binary_data = bytes(range(256))  # includes every byte value, 0x00-0xFF

    client.post("/v1/transit/keys/binary-test", headers=headers)
    resp = client.post(
        "/v1/transit/keys/binary-test/encrypt",
        json={"plaintext": _b64(binary_data)},
        headers=headers,
    )
    ciphertext = resp.json()["ciphertext"]

    resp = client.post(
        "/v1/transit/keys/binary-test/decrypt",
        json={"ciphertext": ciphertext},
        headers=headers,
    )
    assert base64.b64decode(resp.json()["plaintext"]) == binary_data
