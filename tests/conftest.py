"""
Pytest fixtures and test helpers for CodeSentinel.
"""

from __future__ import annotations
import hashlib
import hmac
import json
from typing import Any, AsyncGenerator, Dict
from unittest.mock import AsyncMock, MagicMock
import pytest
from httpx import ASGITransport, AsyncClient

from src.api.main import create_app
from src.config import Settings, get_settings


@pytest.fixture
def test_secret() -> str:
    return "test_super_secret_webhook_key_999"


@pytest.fixture
def mock_settings(test_secret: str, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", test_secret)
    monkeypatch.setenv("GITHUB_TOKEN", "mock_gh_token_xyz")
    monkeypatch.setenv("REDIS_HOST", "localhost")
    monkeypatch.setenv("REDIS_PORT", "6379")
    monkeypatch.setenv("APP_ENV", "test")
    # Reset lru_cache
    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()


@pytest.fixture
def make_signature(test_secret: str):
    """Helper factory to sign a payload bytes with HMAC-SHA256."""
    def _signer(payload_bytes: bytes, secret: str = test_secret) -> str:
        sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        return f"sha256={sig}"
    return _signer


@pytest.fixture
def sample_pr_payload() -> Dict[str, Any]:
    """Sample GitHub pull_request opened webhook payload."""
    return {
        "action": "opened",
        "number": 42,
        "pull_request": {
            "number": 42,
            "title": "feat: Add new user authentication flow",
            "body": "Implements login and session verification with JWT.",
            "head": {
                "sha": "a1b2c3d4e5f67890123456789abcdef012345678",
                "ref": "feature/auth",
            },
            "base": {
                "sha": "9876543210fedcba9876543210fedcba98765432",
                "ref": "main",
            },
            "user": {
                "login": "octocat",
            },
            "diff_url": "https://github.com/octocat/Hello-World/pull/42.diff",
        },
        "repository": {
            "full_name": "octocat/Hello-World",
            "name": "Hello-World",
            "owner": {"login": "octocat"},
        },
        "sender": {
            "login": "octocat",
        },
    }


@pytest.fixture
def sample_git_diff() -> str:
    """Sample unified git diff containing additions, deletions and modifications."""
    return """diff --git a/src/auth.py b/src/auth.py
index e69de29..4959473 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,6 +10,8 @@ def authenticate(username, password):
     user = db.query(f"SELECT * FROM users WHERE name = '{username}'")
-    return False
+    # Hardcoded master key risk
+    if password == "SUPER_SECRET_KEY_123":
+        return True
+    return user is not None
diff --git a/tests/test_auth.py b/tests/test_auth.py
new file mode 100644
index 0000000..f5b61e2
--- /dev/null
+++ b/tests/test_auth.py
@@ -0,0 +1,5 @@
+import pytest
+
+def test_dummy():
+    assert True
"""


@pytest.fixture
def mock_arq_pool() -> MagicMock:
    """Mock ARQ redis pool."""
    pool = MagicMock()
    mock_job = MagicMock()
    mock_job.job_id = "mock-arq-job-12345"
    pool.enqueue_job = AsyncMock(return_value=mock_job)
    pool.close = AsyncMock()
    return pool


@pytest.fixture
async def async_client(mock_settings: Settings, mock_arq_pool: MagicMock) -> AsyncGenerator[AsyncClient, None]:
    """Test HTTP client with mocked ARQ Redis pool."""
    app = create_app()
    app.state.arq_pool = mock_arq_pool

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
