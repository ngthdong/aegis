from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute

REQUEST_ID_HEADER = "X-Request-ID"


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    if isinstance(route, APIRoute):
        return route.path
    return "unmatched"


def register_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = str(uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        start = time.monotonic()

        response = await call_next(request)

        duration = time.monotonic() - start
        route = _route_template(request)
        metrics = request.app.state.metrics

        metrics.http_request_duration_seconds.labels(method=request.method, route=route).observe(
            duration
        )
        metrics.http_requests_total.labels(
            method=request.method, route=route, status_code=str(response.status_code)
        ).inc()

        response.headers[REQUEST_ID_HEADER] = request_id
        return response
