from __future__ import annotations

from fastapi.testclient import TestClient

PASSPHRASE = "correct horse battery staple"
PASSWORD = "correct-horse-battery"


def _setup_vault_and_login(client: TestClient, username: str = "alice") -> str:
    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})
    client.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    resp = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    return resp.json()["token"]


def test_every_response_carries_a_request_id_header(client: TestClient):
    resp = client.get("/health")
    assert "X-Request-ID" in resp.headers


def test_two_requests_get_different_request_ids(client: TestClient):
    resp_a = client.get("/health")
    resp_b = client.get("/health")
    assert resp_a.headers["X-Request-ID"] != resp_b.headers["X-Request-ID"]


def test_metrics_endpoint_returns_prometheus_text_format(client: TestClient):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "aegis_http_requests_total" in resp.text
    assert "aegis_vault_sealed" in resp.text


def test_metrics_reflect_vault_seal_state(client: TestClient):
    resp = client.get("/metrics")
    assert "aegis_vault_sealed 1.0" in resp.text

    client.post("/v1/vault/init", json={"passphrase": PASSPHRASE})
    client.post("/v1/vault/unseal", json={"passphrase": PASSPHRASE})

    resp = client.get("/metrics")
    assert "aegis_vault_sealed 0.0" in resp.text


def test_metrics_use_route_template_not_raw_path(client: TestClient):
    token = _setup_vault_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    client.put("/v1/kv/db/password-one", json={"value": "x"}, headers=headers)
    client.put("/v1/kv/db/password-two", json={"value": "x"}, headers=headers)

    resp = client.get("/metrics")
    assert 'route="/v1/kv/{path:path}"' in resp.text
    assert "db/password-one" not in resp.text
    assert "db/password-two" not in resp.text


def test_metrics_do_not_create_new_labels_for_garbage_404_paths(client: TestClient):
    client.get("/this/path/does/not/exist/at/all")
    client.get("/another/completely/made/up/path")

    resp = client.get("/metrics")
    assert 'route="unmatched"' in resp.text
    assert "this/path/does/not/exist" not in resp.text


def test_kv_operations_increment_the_kv_metric(client: TestClient):
    token = _setup_vault_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    client.put("/v1/kv/metrics-test/path", json={"value": "x"}, headers=headers)

    resp = client.get("/metrics")
    assert 'aegis_kv_operations_total{action="write",outcome="success"}' in resp.text


def test_auth_failure_increments_the_auth_failure_metric(client: TestClient):
    _setup_vault_and_login(client)
    client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})

    resp = client.get("/metrics")
    assert "aegis_auth_failures_total 1.0" in resp.text
