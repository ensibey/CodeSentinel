"""
LangGraph Multi-Agent State and Pydantic Data Models.
Defines the shared state schema flowing through the cyclical multi-agent graph.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel, Field


class SecurityVulnerability(BaseModel):
    """Structured security vulnerability discovered by Security Scanner Agent."""
    file_path: str = Field(..., description="Target file path")
    line_number: Optional[int] = Field(default=None, description="Line number of vulnerable code")
    category: str = Field(..., description="Vulnerability category, e.g. SQL Injection, Secret Leak")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    description: str = Field(..., description="Technical explanation of the flaw")
    remediation: str = Field(..., description="Actionable fix recommendations")
    code_snippet: Optional[str] = Field(default=None, description="Vulnerable code snippet")


class ReviewComment(BaseModel):
    """Inline GitHub PR review comment."""
    path: str = Field(..., description="Relative file path")
    line: int = Field(..., description="Line number in the changed file")
    body: str = Field(..., description="Markdown review comment text")
    side: str = Field(default="RIGHT", description="Diff side: LEFT (base) or RIGHT (head)")


class GeneratedTest(BaseModel):
    """Automated pytest test suite synthesized by Test Generator Agent."""
    test_file_path: str = Field(..., description="Destination test file path, e.g. tests/test_auth.py")
    target_function: str = Field(..., description="Name of the function/module being tested")
    test_code: str = Field(..., description="Executable pytest code snippet")
    description: str = Field(..., description="Test purpose and edge cases covered")


class AgentState(TypedDict):
    """
    State shared across LangGraph agent nodes.
    Maintains diff context, security audit results, generated tests, and iterative judge feedback.
    """
    repo_name: str
    pr_number: int
    pr_title: str
    git_diff: str
    changed_files: List[Dict[str, Any]]
    security_vulnerabilities: List[Dict[str, Any]]
    generated_tests: List[str]
    suggested_patch: str
    judge_approval: bool
    judge_feedback: str
    review_comments: List[Dict[str, Any]]
    iteration_count: int
