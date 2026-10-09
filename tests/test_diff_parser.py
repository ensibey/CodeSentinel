"""
Tests for unified git diff parser and hunk line mapper.
"""

from __future__ import annotations
from src.github_client.parser import GitDiffParser, DiffFile


def test_parse_empty_diff():
    assert GitDiffParser.parse("") == []
    assert GitDiffParser.parse("   \n\n  ") == []


def test_parse_sample_diff(sample_git_diff: str):
    files = GitDiffParser.parse(sample_git_diff)
    assert len(files) == 2

    # File 1: Modified auth.py
    f1 = files[0]
    assert f1.file_path == "src/auth.py"
    assert f1.old_path == "src/auth.py"
    assert f1.new_path == "src/auth.py"
    assert f1.status == "modified"
    assert len(f1.hunks) == 1

    hunk1 = f1.hunks[0]
    assert hunk1.old_start == 10
    assert hunk1.new_start == 10
    assert len(hunk1.lines) > 0

    # Test added lines extraction
    added = f1.added_lines
    assert len(added) == 4
    assert any("SUPER_SECRET_KEY_123" in line.content for line in added)
    assert all(line.new_line_no is not None for line in added)

    # File 2: Added test_auth.py
    f2 = files[1]
    assert f2.file_path == "tests/test_auth.py"
    assert f2.status == "added"
    assert len(f2.hunks) == 1
    assert len(f2.added_lines) == 4


def test_get_summary_text(sample_git_diff: str):
    files = GitDiffParser.parse(sample_git_diff)
    summary = GitDiffParser.get_summary_text(files)

    assert "### File: src/auth.py" in summary
    assert "### File: tests/test_auth.py" in summary
    assert "SUPER_SECRET_KEY_123" in summary
