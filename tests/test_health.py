def test_liveness(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness(client):
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_app_is_isolated_per_settings_instance(settings):
    from aegis.api.main import create_app
    from aegis.config.settings import Settings

    app_a = create_app(settings)
    app_b = create_app(Settings(environment="test", log_json=False, app_name="other"))

    assert app_a.state.settings.app_name != app_b.state.settings.app_name
