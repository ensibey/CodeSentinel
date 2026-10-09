"""
Tests for application configuration and environment settings.
"""

from __future__ import annotations
from src.config import Settings


def test_default_settings():
    settings = Settings(
        APP_NAME="CodeSentinelTest",
        REDIS_HOST="127.0.0.1",
        REDIS_PORT=6379,
        REDIS_DB=1,
    )
    assert settings.APP_NAME == "CodeSentinelTest"
    assert settings.REDIS_HOST == "127.0.0.1"
    assert settings.REDIS_PORT == 6379
    assert settings.REDIS_DB == 1
    assert settings.redis_url == "redis://127.0.0.1:6379/1"


def test_redis_url_with_password():
    settings = Settings(
        REDIS_HOST="redis.production.local",
        REDIS_PORT=6380,
        REDIS_PASSWORD="secret_password_xyz",
        REDIS_DB=2,
    )
    assert settings.redis_url == "redis://:secret_password_xyz@redis.production.local:6380/2"


def test_arq_redis_settings():
    settings = Settings(
        REDIS_HOST="10.0.0.5",
        REDIS_PORT=6379,
        REDIS_DB=3,
    )
    arq_settings = settings.get_arq_redis_settings()
    assert arq_settings.host == "10.0.0.5"
    assert arq_settings.port == 6379
    assert arq_settings.database == 3
