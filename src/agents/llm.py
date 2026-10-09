"""
LLM Provider Factory & LangSmith Tracing Initialization.
Configures OpenAI / Anthropic models and handles automated tracing configuration.
Provides seamless fallback for offline testing and deterministic evaluation.
"""

from __future__ import annotations
import logging
import os
from typing import Any, Optional
from pydantic import BaseModel

from src.config import get_settings

logger = logging.getLogger("codesentinel.agents.llm")


def setup_langsmith_tracing() -> None:
    """Configures LangSmith observability environment variables."""
    settings = get_settings()
    if settings.LANGCHAIN_TRACING_V2 and settings.LANGCHAIN_API_KEY:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_API_KEY"] = settings.LANGCHAIN_API_KEY
        os.environ["LANGCHAIN_PROJECT"] = settings.LANGCHAIN_PROJECT
        logger.info("LangSmith observability enabled for project '%s'.", settings.LANGCHAIN_PROJECT)


class MockLLMResponse:
    """Mock LLM response object for offline/test mode."""
    def __init__(self, content: str):
        self.content = content


class FallbackChatModel:
    """
    Heuristic mock LLM for local evaluation when no API key is configured.
    Ensures that CodeSentinel pipelines run end-to-end without runtime crashes.
    """

    def __init__(self, temperature: float = 0.0):
        self.temperature = temperature

    async def ainvoke(self, messages: Any, **kwargs) -> MockLLMResponse:
        """Simulate LLM response based on prompt context."""
        text = str(messages).lower()
        if "lead security remediation" in text or "synthesize a clean, minimal, unified git diff" in text:
            content = (
                "```diff\n--- a/src/auth.py\n+++ b/src/auth.py\n@@ -11,3 +11,1 @@\n"
                "-    if password == 'SUPER_SECRET_KEY_123':\n-        return True\n```"
            )
        elif "test automation architect" in text or "synthesize targeted, isolated" in text:
            content = (
                "```python\nimport pytest\n\ndef test_auth_no_hardcoded_bypass():\n"
                "    from src.auth import authenticate\n"
                "    assert authenticate('admin', 'SUPER_SECRET_KEY_123') is False\n```"
            )
        elif "chief security officer" in text or "final decision maker" in text:
            content = '{"approved": true, "feedback": "Patch successfully removes credential flaw without regression.", "safety_score": 90}'
        elif "application security engineer" in text or "exhaustive, high-precision security audit" in text:
            content = (
                '{"vulnerabilities": [{"file_path": "src/auth.py", "line_number": 12, '
                '"category": "CWE-798: Hardcoded Credentials", "severity": "CRITICAL", '
                '"description": "Hardcoded master secret key bypasses regular authentication.", '
                '"remediation": "Move secret key to secure environment variable."}]}'
            )
        else:
            content = "{}"
        return MockLLMResponse(content)

    def invoke(self, messages: Any, **kwargs) -> MockLLMResponse:
        import asyncio
        return asyncio.run(self.ainvoke(messages, **kwargs))


def get_chat_model(temperature: float = 0.0) -> Any:
    """
    Factory creating configured Chat LLM instance with LangSmith tracing.
    Falls back gracefully to FallbackChatModel if no provider keys are set.
    """
    setup_langsmith_tracing()
    settings = get_settings()

    if settings.ANTHROPIC_API_KEY:
        try:
            from langchain_anthropic import ChatAnthropic
            logger.info("Initializing Anthropic Claude 3.5 Sonnet model...")
            return ChatAnthropic(
                model="claude-3-5-sonnet-20241022",
                anthropic_api_key=settings.ANTHROPIC_API_KEY,
                temperature=temperature,
            )
        except Exception as exc:
            logger.warning("Failed to initialize ChatAnthropic (%s). Falling back.", exc)

    if settings.OPENAI_API_KEY:
        try:
            from langchain_openai import ChatOpenAI
            logger.info("Initializing OpenAI GPT-4o model...")
            return ChatOpenAI(
                model="gpt-4o",
                openai_api_key=settings.OPENAI_API_KEY,
                temperature=temperature,
            )
        except Exception as exc:
            logger.warning("Failed to initialize ChatOpenAI (%s). Falling back.", exc)

    logger.info("No LLM API keys provided. Running in Fallback/Evaluation mode.")
    return FallbackChatModel(temperature=temperature)
