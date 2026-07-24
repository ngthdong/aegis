from __future__ import annotations

import base64

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


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def test_create_signing_key_sign_and_verify_over_http(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    resp = client.post(
        "/v1/transit/keys/doc-signer", json={"key_type": "asymmetric_sign"}, headers=headers
    )
    assert resp.status_code == 201
    assert resp.json()["key_type"] == "asymmetric_sign"

    resp = client.post(
        "/v1/transit/keys/doc-signer/sign",
        json={"message": _b64(b"approve invoice #42")},
        headers=headers,
    )
    assert resp.status_code == 200
    signature = resp.json()["signature"]

    resp = client.post(
        "/v1/transit/keys/doc-signer/verify",
        json={"message": _b64(b"approve invoice #42"), "signature": signature},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {"valid": True}


def test_verify_returns_false_not_an_error_for_tampered_message(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.post(
        "/v1/transit/keys/doc-signer", json={"key_type": "asymmetric_sign"}, headers=headers
    )
    resp = client.post(
        "/v1/transit/keys/doc-signer/sign",
        json={"message": _b64(b"original")},
        headers=headers,
    )
    signature = resp.json()["signature"]

    resp = client.post(
        "/v1/transit/keys/doc-signer/verify",
        json={"message": _b64(b"tampered"), "signature": signature},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {"valid": False}


def test_non_owner_can_verify_over_http_but_not_sign(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.post(
        "/v1/transit/keys/doc-signer",
        json={"key_type": "asymmetric_sign"},
        headers=_auth_header(alice_token),
    )
    resp = client.post(
        "/v1/transit/keys/doc-signer/sign",
        json={"message": _b64(b"message")},
        headers=_auth_header(alice_token),
    )
    signature = resp.json()["signature"]

    resp = client.post(
        "/v1/transit/keys/doc-signer/sign",
        json={"message": _b64(b"message")},
        headers=_auth_header(bob_token),
    )
    assert resp.status_code == 403

    resp = client.post(
        "/v1/transit/keys/doc-signer/verify",
        json={"message": _b64(b"message"), "signature": signature},
        headers=_auth_header(bob_token),
    )
    assert resp.status_code == 200
    assert resp.json() == {"valid": True}


def test_disable_then_encrypt_returns_409_but_decrypt_still_works(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.post("/v1/transit/keys/app-1", headers=headers)
    resp = client.post(
        "/v1/transit/keys/app-1/encrypt",
        json={"plaintext": _b64(b"before disable")},
        headers=headers,
    )
    ciphertext = resp.json()["ciphertext"]

    resp = client.post("/v1/transit/keys/app-1/disable", headers=headers)
    assert resp.status_code == 204

    resp = client.post(
        "/v1/transit/keys/app-1/encrypt",
        json={"plaintext": _b64(b"after disable")},
        headers=headers,
    )
    assert resp.status_code == 409

    resp = client.post(
        "/v1/transit/keys/app-1/decrypt", json={"ciphertext": ciphertext}, headers=headers
    )
    assert resp.status_code == 200
    assert base64.b64decode(resp.json()["plaintext"]) == b"before disable"


def test_destroy_then_every_operation_returns_409(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.post("/v1/transit/keys/app-1", headers=headers)
    resp = client.post(
        "/v1/transit/keys/app-1/encrypt", json={"plaintext": _b64(b"data")}, headers=headers
    )
    ciphertext = resp.json()["ciphertext"]

    resp = client.delete("/v1/transit/keys/app-1", headers=headers)
    assert resp.status_code == 204

    resp = client.post(
        "/v1/transit/keys/app-1/decrypt", json={"ciphertext": ciphertext}, headers=headers
    )
    assert resp.status_code == 409

    resp = client.post(
        "/v1/transit/keys/app-1/encrypt", json={"plaintext": _b64(b"data")}, headers=headers
    )
    assert resp.status_code == 409


def test_only_owner_can_disable_or_destroy_over_http(client: TestClient):
    _setup_vault(client)
    alice_token = _register_and_login(client, "alice")
    bob_token = _register_and_login(client, "bob")

    client.post("/v1/transit/keys/alices-key", headers=_auth_header(alice_token))

    resp = client.post("/v1/transit/keys/alices-key/disable", headers=_auth_header(bob_token))
    assert resp.status_code == 403

    resp = client.delete("/v1/transit/keys/alices-key", headers=_auth_header(bob_token))
    assert resp.status_code == 403


def test_wrong_key_type_for_operation_returns_400(client: TestClient):
    _setup_vault(client)
    token = _register_and_login(client, "alice")
    headers = _auth_header(token)

    client.post("/v1/transit/keys/sym-key", headers=headers)  # default: symmetric

    resp = client.post(
        "/v1/transit/keys/sym-key/sign", json={"message": _b64(b"x")}, headers=headers
    )
    assert resp.status_code == 400
