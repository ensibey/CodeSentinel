"""
Configuration loader for CodeSentinel rule policies and path exclusions.

Supports reading settings from `.codesentinel.toml` or `[tool.codesentinel]`
inside `pyproject.toml`. Uses stdlib `tomllib` on Python 3.11+ and falls back
to a lightweight TOML subset parser on Python 3.10 so zero extra runtime
dependencies are required.
"""

from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python 3.10 fallback
    tomllib = None


SEVERITY_ORDER: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DEFAULT_EXCLUDES: List[str] = [
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
]


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    """Minimal TOML parser for flat tables, strings, booleans, ints, and lists."""
    root: Dict[str, Any] = {}
    current: Dict[str, Any] = root

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            section_path = [part.strip() for part in line[1:-1].split(".") if part.strip()]
            target = root
            for part in section_path:
                target = target.setdefault(part, {})
            current = target
            continue

        if "=" in line:
            key, raw_val = line.split("=", 1)
            key = key.strip()
            raw_val = raw_val.strip()
            if raw_val.lower() == "true":
                value: Any = True
            elif raw_val.lower() == "false":
                value = False
            else:
                try:
                    value = ast.literal_eval(raw_val)
                except (ValueError, SyntaxError):
                    value = raw_val.strip('"').strip("'")
            current[key] = value

    return root


def _load_toml(path: Path) -> Dict[str, Any]:
    raw_bytes = path.read_bytes()
    if tomllib is not None:
        return tomllib.loads(raw_bytes.decode("utf-8"))
    return _parse_simple_toml(raw_bytes.decode("utf-8"))


@dataclass
class ScanConfig:
    """Policy configuration governing static AST and CLI scans."""

    exclude: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    disabled_rules: List[str] = field(default_factory=list)
    min_severity: str = "LOW"

    def normalized_min_severity(self) -> str:
        sev = self.min_severity.upper().strip()
        return sev if sev in SEVERITY_ORDER else "LOW"

    def meets_severity(self, severity: str) -> bool:
        sev_rank = SEVERITY_ORDER.get(severity.upper().strip(), 1)
        min_rank = SEVERITY_ORDER.get(self.normalized_min_severity(), 1)
        return sev_rank >= min_rank

    def is_rule_enabled(self, rule_id: Optional[str] = None, category: str = "") -> bool:
        if not self.disabled_rules:
            return True
        disabled_upper = {r.upper().strip() for r in self.disabled_rules}
        if rule_id and rule_id.upper().strip() in disabled_upper:
            return False
        cat_upper = category.upper()
        for entry in disabled_upper:
            if entry and entry in cat_upper:
                return False
        return True

    def is_path_excluded(self, path: Path) -> bool:
        parts = set(path.parts)
        posix = path.as_posix()
        for pattern in self.exclude:
            if pattern in parts:
                return True
            if fnmatch.fnmatch(posix, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        raw_excludes = data.get("exclude")
        excludes = list(DEFAULT_EXCLUDES)
        if isinstance(raw_excludes, Sequence) and not isinstance(raw_excludes, str):
            for item in raw_excludes:
                if str(item) not in excludes:
                    excludes.append(str(item))

        raw_disabled = data.get("disabled_rules", [])
        disabled = (
            [str(r).strip() for r in raw_disabled]
            if isinstance(raw_disabled, Sequence) and not isinstance(raw_disabled, str)
            else []
        )

        min_sev = str(data.get("min_severity", "LOW")).upper().strip()
        if min_sev not in SEVERITY_ORDER:
            min_sev = "LOW"

        return cls(exclude=excludes, disabled_rules=disabled, min_severity=min_sev)

    @classmethod
    def discover(cls, start_dir: Optional[Path] = None) -> "ScanConfig":
        """Search for `.codesentinel.toml` or `pyproject.toml` in `start_dir`."""
        base = (start_dir or Path.cwd()).resolve()
        if base.is_file():
            base = base.parent

        dedicated = base / ".codesentinel.toml"
        if dedicated.is_file():
            parsed = _load_toml(dedicated)
            section = parsed.get("codesentinel", parsed)
            if isinstance(section, dict):
                return cls.from_dict(section)

        pyproject = base / "pyproject.toml"
        if pyproject.is_file():
            parsed = _load_toml(pyproject)
            tool_section = parsed.get("tool", {})
            if isinstance(tool_section, dict) and isinstance(tool_section.get("codesentinel"), dict):
                return cls.from_dict(tool_section["codesentinel"])

        return cls()
