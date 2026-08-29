from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import Settings
from app.database import Database
from app.schemas import ContainRequest, IncidentUpdate, IngestRequest, IngestResponse
from app.sensors.demo import scenario_events
from app.sensors.eve_tailer import EveTailer
from app.services.detection import DetectionEngine
from app.services.model_runtime import ModelRuntime
from app.services.pipeline import EventPipeline
from app.services.response import ResponseDenied, ResponseEngine

LOGGER = logging.getLogger("vajra")
WEB_ROOT = Path(__file__).parent / "web"
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class SlidingWindowLimiter:
    def __init__(self, limit: int = 180, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: dict[str, deque[float]] = defaultdict(deque)

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        values = self.requests[key]
        cutoff = now - self.window_seconds
        while values and values[0] < cutoff:
            values.popleft()
        if len(values) >= self.limit:
            return False
        values.append(now)
        return True


def _client_identity(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> str:
    supplied = x_api_key
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    expected = request.app.state.settings.api_key
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid API key is required for mutation endpoints",
        )
    return f"api:{hashlib.sha256(supplied.encode()).hexdigest()[:10]}"


def _health_score(metrics: dict[str, Any]) -> int:
    severity = metrics["severity"]
    penalty = (
        min(severity["critical"] * 18, 36)
        + min(severity["high"] * 10, 30)
        + min(severity["medium"] * 4, 16)
        + min(severity["low"], 5)
        + min(metrics["open_incidents"] * 2, 10)
    )
    return max(0, min(100, 100 - penalty))


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or Settings()
    configured.validate()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        database = Database(configured.database_path)
        database.initialize()
        model = ModelRuntime(configured.model_path, configured.model_metadata_path)
        model.load()
        detector = DetectionEngine(model)
        pipeline = EventPipeline(database, detector)
        response_engine = ResponseEngine(configured, database)
        tailer = EveTailer(configured.eve_path, pipeline)
        tail_task = asyncio.create_task(tailer.run(), name="eve-tailer")

        app.state.settings = configured
        app.state.database = database
        app.state.model = model
        app.state.pipeline = pipeline
        app.state.response_engine = response_engine
        app.state.tailer = tailer
        app.state.demo_lock = asyncio.Lock()

        if configured.demo_mode and database.is_empty():
            for raw in scenario_events("multi-stage"):
                pipeline.process(raw, "verified-demo-lab")
        try:
            yield
        finally:
            tailer.stop()
            tail_task.cancel()
            try:
                await tail_task
            except asyncio.CancelledError:
                pass

    app = FastAPI(
        title="Vajra Sentinel API",
        description="Evidence-first hybrid IDS/IPS and SOC investigation API",
        version=__version__,
        docs_url=None if configured.environment == "production" else "/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = configured
    limiter = SlidingWindowLimiter()

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        identity = _client_identity(request)
        if not limiter.allowed(identity):
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 2_000_000:
                    return JSONResponse(
                        status_code=413, content={"detail": "Request body exceeds 2 MB"}
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ResponseDenied)
    async def response_denied_handler(_: Request, exc: ResponseDenied):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        return FileResponse(WEB_ROOT / "index.html")

    @app.get("/api/v1/about")
    async def about(request: Request) -> dict[str, Any]:
        current = request.app.state.settings
        return {
            "name": "Vajra Sentinel",
            "version": __version__,
            "tagline": "Evidence before action.",
            "environment": current.environment,
            "demo_mode": current.demo_mode,
            "ips_mode": current.ips_mode,
            "telemetry": "Suricata EVE JSON",
            "capabilities": [
                "signature detection",
                "stateful behavior analytics",
                "optional supervised flow scoring",
                "incident correlation",
                "reversible nftables containment",
                "audit trail",
            ],
        }

    @app.get("/api/v1/health")
    async def health(request: Request) -> dict[str, Any]:
        database = request.app.state.database
        model = request.app.state.model
        return {
            "status": "healthy",
            "version": __version__,
            "components": {
                "database": "ready" if database.path.exists() else "initializing",
                "eve_sensor": "watching" if configured.eve_path.exists() else "awaiting-file",
                "ml_model": model.metadata.get("status", "unavailable"),
                "response": configured.ips_mode,
            },
        }

    @app.get("/api/v1/metrics")
    async def metrics(request: Request) -> dict[str, Any]:
        result = request.app.state.database.metrics()
        result["health_score"] = _health_score(result)
        result["score_method"] = (
            "100 minus capped severity and open-incident penalties; floor 0, ceiling 100"
        )
        return result

    @app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
    async def prometheus_metrics(request: Request) -> str:
        result = request.app.state.database.metrics()
        lines = [
            "# HELP vajra_events_total Normalized network events stored.",
            "# TYPE vajra_events_total gauge",
            f"vajra_events_total {result['events']}",
            "# HELP vajra_detections_total Security detections by severity.",
            "# TYPE vajra_detections_total gauge",
        ]
        for severity, count in result["severity"].items():
            lines.append(f'vajra_detections_total{{severity="{severity}"}} {count}')
        lines.extend(
            [
                "# HELP vajra_open_incidents Current non-closed incidents.",
                "# TYPE vajra_open_incidents gauge",
                f"vajra_open_incidents {result['open_incidents']}",
                "# HELP vajra_response_blocks Current simulated or active blocks.",
                "# TYPE vajra_response_blocks gauge",
                f"vajra_response_blocks {result['active_blocks']}",
            ]
        )
        return "\n".join(lines) + "\n"

    @app.get("/api/v1/events")
    async def list_events(request: Request, limit: int = Query(default=50, ge=1, le=500)):
        return {"items": request.app.state.database.list_events(limit)}

    @app.post("/api/v1/events/ingest", response_model=IngestResponse)
    async def ingest_event(
        payload: IngestRequest,
        request: Request,
        _: str = Depends(require_api_key),
    ):
        try:
            return request.app.state.pipeline.process(payload.event, payload.sensor_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/detections")
    async def list_detections(
        request: Request,
        limit: int = Query(default=50, ge=1, le=500),
        severity: str | None = Query(default=None),
    ):
        if severity and severity not in VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid severity")
        return {"items": request.app.state.database.list_detections(limit, severity)}

    @app.get("/api/v1/detections/{detection_id}")
    async def get_detection(detection_id: int, request: Request):
        detection = request.app.state.database.get_detection(detection_id)
        if detection is None:
            raise HTTPException(status_code=404, detail="Detection not found")
        return detection

    @app.get("/api/v1/incidents")
    async def list_incidents(request: Request, limit: int = Query(default=50, ge=1, le=500)):
        return {"items": request.app.state.database.list_incidents(limit)}

    @app.patch("/api/v1/incidents/{incident_id}")
    async def update_incident(
        incident_id: int,
        payload: IncidentUpdate,
        request: Request,
        actor: str = Depends(require_api_key),
    ):
        changed = request.app.state.database.update_incident(
            incident_id, payload.status, payload.note, actor
        )
        if not changed:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {"id": incident_id, "status": payload.status}

    @app.post("/api/v1/detections/{detection_id}/contain")
    async def contain_detection(
        detection_id: int,
        payload: ContainRequest,
        request: Request,
        actor: str = Depends(require_api_key),
    ):
        detection = request.app.state.database.get_detection(detection_id)
        if detection is None:
            raise HTTPException(status_code=404, detail="Detection not found")
        ttl = payload.ttl_seconds or configured.block_ttl_seconds
        reason = payload.reason or f"Containment requested for {detection['rule_id']}"
        return request.app.state.response_engine.contain(
            detection, ttl_seconds=ttl, reason=reason, actor=actor
        )

    @app.get("/api/v1/response/blocks")
    async def list_blocks(request: Request, limit: int = Query(default=50, ge=1, le=500)):
        return {"items": request.app.state.database.list_blocks(limit)}

    @app.delete("/api/v1/response/blocks/{block_id}")
    async def revert_block(
        block_id: int,
        request: Request,
        actor: str = Depends(require_api_key),
    ):
        try:
            return request.app.state.response_engine.revert(block_id, actor)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/audit")
    async def audit_log(request: Request, limit: int = Query(default=50, ge=1, le=500)):
        return {"items": request.app.state.database.audit_log(limit)}

    @app.get("/api/v1/model")
    async def model_status(request: Request):
        return request.app.state.model.metadata

    @app.post("/api/v1/demo/scenarios/{scenario}")
    async def run_demo(scenario: str, request: Request):
        if not configured.demo_mode:
            raise HTTPException(status_code=404, detail="Demo endpoint is disabled")
        try:
            events = scenario_events(scenario)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Unknown scenario") from exc
        async with request.app.state.demo_lock:
            replaced = request.app.state.database.reset_demo_data()
            request.app.state.pipeline.detector.reset_state()
            results = [
                request.app.state.pipeline.process(raw, f"demo-{scenario}") for raw in events
            ]
        return {
            "scenario": scenario,
            "events_ingested": len(results),
            "detections_created": sum(len(item["detection_ids"]) for item in results),
            "replaced": replaced,
        }

    app.mount("/assets", StaticFiles(directory=WEB_ROOT), name="assets")
    return app


app = create_app()


def run() -> None:
    import uvicorn

    settings = Settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
