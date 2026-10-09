"""
Main FastAPI Application Entrypoint.
Initializes lifespan handlers (Redis pool lifecycle), routes, and health checks.
"""

from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware

from src.api.webhooks import router as webhook_router
from src.config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("codesentinel.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application startup and shutdown lifecycle.
    Initializes ARQ Redis connection pool for background task dispatch.
    """
    settings = get_settings()
    logger.info("Initializing %s in '%s' mode...", settings.APP_NAME, settings.APP_ENV)

    # Initialize ARQ Redis Pool
    arq_pool = None
    try:
        from arq import create_pool
        arq_pool = await create_pool(settings.get_arq_redis_settings())
        logger.info("Connected to Redis ARQ task queue at %s:%s", settings.REDIS_HOST, settings.REDIS_PORT)
    except Exception as exc:
        logger.warning(
            "Could not connect to Redis at %s:%s (%s). Webhook will operate in decoupled mock mode.",
            settings.REDIS_HOST,
            settings.REDIS_PORT,
            exc,
        )

    app.state.arq_pool = arq_pool

    yield

    # Shutdown
    if arq_pool is not None:
        logger.info("Closing Redis ARQ task pool...")
        await arq_pool.close()
    logger.info("%s shutdown complete.", settings.APP_NAME)


def create_app() -> FastAPI:
    """Factory function for FastAPI application instance."""
    settings = get_settings()

    app = FastAPI(
        title="CodeSentinel API Gateway",
        description="Autonomous Multi-Agent GitHub Pull Request & Security Review System",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routers
    app.include_router(webhook_router)

    @app.get(
        "/",
        tags=["System"],
        summary="Root Status",
        status_code=status.HTTP_200_OK,
    )
    async def root() -> Dict[str, Any]:
        return {
            "name": settings.APP_NAME,
            "version": "0.1.0",
            "environment": settings.APP_ENV,
            "docs": "/docs",
            "status": "operational",
        }

    @app.get(
        "/health",
        tags=["System"],
        summary="Service Health Check",
        status_code=status.HTTP_200_OK,
    )
    async def health_check() -> Dict[str, Any]:
        redis_connected = app.state.arq_pool is not None
        return {
            "status": "healthy",
            "app_name": settings.APP_NAME,
            "redis_connected": redis_connected,
            "environment": settings.APP_ENV,
        }

    return app


app = create_app()
