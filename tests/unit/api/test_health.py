def test_liveness(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_not_ready_before_vault_is_unsealed(client):
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not ready"
    assert body["checks"]["database"] is True
    assert body["checks"]["vault_unsealed"] is False


def test_readiness_reports_ready_once_vault_is_unsealed(client):
    client.post(
        "/v1/vault/init",
        json={
            "passphrase": "correct horse battery staple",
            "admin_username": "bootstrap-admin",
            "admin_password": "correct-horse-battery-admin",
        },
    )
    client.post("/v1/vault/unseal", json={"passphrase": "correct horse battery staple"})

    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {"database": True, "vault_unsealed": True}


def test_app_is_isolated_per_settings_instance(settings):
    from aegis.api.main import create_app
    from aegis.config.settings import Settings
    from aegis.storage.db import create_memory_engine

    app_a = create_app(settings, engine=create_memory_engine())
    app_b = create_app(
        Settings(environment="test", log_json=False, app_name="other"),
        engine=create_memory_engine(),
    )

    assert app_a.state.settings.app_name != app_b.state.settings.app_name
    assert app_a.state.engine is not app_b.state.engine
