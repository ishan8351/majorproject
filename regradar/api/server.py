from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from regradar.api.routes import api_router
from regradar.config import RegRadarConfig, get_config, load_config

STATIC_DIR = Path(__file__).parent.parent / "web"


def create_app(custom_config: Optional[RegRadarConfig] = None) -> FastAPI:
    cfg = custom_config or get_config()
    app = FastAPI(
        title="RegRadar Compliance & Governance Studio",
        description="Autonomous, Zero-Destruction Compliance Remediation for Infrastructure-as-Code",
        version="1.0.0",
    )

    # Enable CORS configured from global settings (defaults to ["*"])
    cors_origins = cfg.server.cors_origins if cfg.server.cors_origins else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return Response(status_code=204)

    # Mount API routes
    app.include_router(api_router)

    # Mount static frontend assets if present
    if STATIC_DIR.exists() and (STATIC_DIR / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="web")

    return app


def run_server(
    host: Optional[str] = None,
    port: Optional[int] = None,
    reload: Optional[bool] = None,
    config_path: Optional[str] = None,
) -> None:
    import uvicorn

    if config_path:
        load_config(config_path)

    cfg = get_config()
    target_host = host if host is not None else cfg.server.host
    target_port = port if port is not None else cfg.server.port
    target_reload = reload if reload is not None else cfg.server.reload

    uvicorn.run(
        "regradar.api.server:create_app",
        host=target_host,
        port=target_port,
        reload=target_reload,
        factory=True,
    )


if __name__ == "__main__":
    run_server()
