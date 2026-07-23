from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from aegis.auth.service import MAX_FAILED_LOGIN_ATTEMPTS
from aegis.common.clock import FakeClock

PASSPHRASE = "correct horse battery staple"
PASSWORD = "correct-horse-battery"


def _setup_user(client: TestClient, username: str = "alice") -> None:
    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    resp = client.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 201, resp.text


def test_login_returns_a_bearer_token(client: TestClient):
    _setup_user(client)
    resp = client.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert "token" in body
    assert "expires_at" in body


def test_token_grants_access_to_protected_endpoint(client: TestClient):
    _setup_user(client)
    login_resp = client.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    token = login_resp.json()["token"]

    resp = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"user_id": resp.json()["user_id"], "username": "alice"}


def test_me_without_token_returns_401(client: TestClient):
    resp = client.get("/v1/auth/me")
    assert resp.status_code == 401


def test_me_with_garbage_token_returns_401(client: TestClient):
    resp = client.get("/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_wrong_password_returns_401(client: TestClient):
    _setup_user(client)
    resp = client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_logout_invalidates_the_token(client: TestClient):
    _setup_user(client)
    login_resp = client.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/v1/auth/me", headers=headers).status_code == 200

    logout_resp = client.post("/v1/auth/logout", headers=headers)
    assert logout_resp.status_code == 204

    # The exact same token must now be rejected.
    assert client.get("/v1/auth/me", headers=headers).status_code == 401


def test_logout_with_already_invalid_token_returns_401_not_204(client: TestClient):
    resp = client.post("/v1/auth/logout", headers={"Authorization": "Bearer never-issued-token"})
    assert resp.status_code == 401


def test_token_rejected_after_ttl_expires(client: TestClient, clock: FakeClock):
    _setup_user(client)
    login_resp = client.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/v1/auth/me", headers=headers).status_code == 200

    clock.advance(timedelta(hours=12, seconds=1))  # DEFAULT_SESSION_TTL is 12h

    assert client.get("/v1/auth/me", headers=headers).status_code == 401


def test_lockout_over_http_returns_423(client: TestClient):
    _setup_user(client)

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
        resp = client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp.status_code == 401

    resp = client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 423
    assert "locked_until" in resp.json()


def test_correct_password_still_locked_out_over_http(client: TestClient):
    _setup_user(client)
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})

    resp = client.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 423


def test_lockout_clears_after_window_over_http(client: TestClient, clock: FakeClock):
    _setup_user(client)
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})

    clock.advance(timedelta(minutes=15, seconds=1))

    resp = client.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 200


def test_login_timing_is_similar_for_unknown_vs_known_username(client: TestClient):
    import time

    _setup_user(client)

    start = time.monotonic()
    client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})
    known_elapsed = time.monotonic() - start

    start = time.monotonic()
    client.post("/v1/auth/login", json={"username": "no-such-user-at-all", "password": "wrong"})
    unknown_elapsed = time.monotonic() - start

    assert unknown_elapsed > known_elapsed / 10
