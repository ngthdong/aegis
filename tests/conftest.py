from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.common.clock import FakeClock
from aegis.config.settings import Settings
from aegis.storage.db import create_memory_engine


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test", log_json=False)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def client(settings: Settings, clock: FakeClock) -> TestClient:
    engine = create_memory_engine()
    app = create_app(settings, engine=engine, clock=clock)
    return TestClient(app)
