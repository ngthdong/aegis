from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)


@dataclass(frozen=True, slots=True)
class Metrics:
    registry: CollectorRegistry
    http_requests_total: Counter
    http_request_duration_seconds: Histogram
    vault_sealed: Gauge
    auth_failures_total: Counter
    kv_operations_total: Counter
    transit_operations_total: Counter


def create_metrics() -> Metrics:
    registry = CollectorRegistry()

    return Metrics(
        registry=registry,
        http_requests_total=Counter(
            "aegis_http_requests_total",
            "Total HTTP requests",
            labelnames=("method", "route", "status_code"),
            registry=registry,
        ),
        http_request_duration_seconds=Histogram(
            "aegis_http_request_duration_seconds",
            "HTTP request latency in seconds",
            labelnames=("method", "route"),
            registry=registry,
        ),
        vault_sealed=Gauge(
            "aegis_vault_sealed",
            "1 if the vault is currently sealed or uninitialized, 0 if unsealed",
            registry=registry,
        ),
        auth_failures_total=Counter(
            "aegis_auth_failures_total",
            "Total failed login attempts",
            registry=registry,
        ),
        kv_operations_total=Counter(
            "aegis_kv_operations_total",
            "Total KV engine operations",
            labelnames=("action", "outcome"),
            registry=registry,
        ),
        transit_operations_total=Counter(
            "aegis_transit_operations_total",
            "Total Transit engine operations",
            labelnames=("action", "outcome"),
            registry=registry,
        ),
    )


def render_metrics(metrics: Metrics) -> tuple[bytes, str]:
    return generate_latest(metrics.registry), CONTENT_TYPE_LATEST
