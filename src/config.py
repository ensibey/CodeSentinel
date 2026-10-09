"""
Application configuration management via Pydantic Settings.
Loads configuration from environment variables or .env file.
"""

from functools import lru_cache
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core Application Settings
    APP_NAME: str = Field(default="CodeSentinel", description="Application service name")
    APP_ENV: str = Field(default="development", description="Environment: development, test, production")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    HOST: str = Field(default="0.0.0.0", description="API server bind host")
    PORT: int = Field(default=8000, description="API server bind port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    # GitHub Integration
    GITHUB_TOKEN: str = Field(
        default="",
        description="GitHub Personal Access Token (PAT) or App Token for PR interactions",
    )
    GITHUB_WEBHOOK_SECRET: str = Field(
        default="",
        description="HMAC Secret configured in GitHub repository Webhook settings",
    )

    # Redis & ARQ Task Queue
    REDIS_HOST: str = Field(default="localhost", description="Redis host")
    REDIS_PORT: int = Field(default=6379, description="Redis port")
    REDIS_PASSWORD: Optional[str] = Field(default=None, description="Redis auth password")
    REDIS_DB: int = Field(default=0, description="Redis database index")

    # LLM & Observability (Prepared for Phase 2 LangGraph)
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI API key")
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, description="Anthropic API key")
    LANGCHAIN_TRACING_V2: bool = Field(default=False, description="Enable LangSmith tracing")
    LANGCHAIN_API_KEY: Optional[str] = Field(default=None, description="LangSmith API key")
    LANGCHAIN_PROJECT: str = Field(default="codesentinel", description="LangSmith project name")

    @property
    def redis_url(self) -> str:
        """Build redis connection URL."""
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    def get_arq_redis_settings(self):
        """Build ARQ RedisSettings object for worker and client pool."""
        from arq.connections import RedisSettings

        return RedisSettings(
            host=self.REDIS_HOST,
            port=self.REDIS_PORT,
            password=self.REDIS_PASSWORD,
            database=self.REDIS_DB,
        )


@lru_cache()
def get_settings() -> Settings:
    """Singleton getter for cached application settings."""
    return Settings()
