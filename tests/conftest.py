from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test", log_json=False)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    app = create_app(settings)
    return TestClient(app)
