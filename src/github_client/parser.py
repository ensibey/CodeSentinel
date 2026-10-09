"""
Git unified diff parser and chunker.
Extracts structured file-level and line-level changes from unified diffs.
Provides precise line number mapping for GitHub inline review comments.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DiffLine:
    """Represents a single line within a diff hunk."""
    type: str  # '+', '-', ' '
    content: str
    old_line_no: Optional[int] = None
    new_line_no: Optional[int] = None
    position: int = 0  # Position relative to hunk start for GitHub diff comments


@dataclass
class DiffHunk:
    """Represents a unified diff hunk header and its lines."""
    header: str
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    lines: List[DiffLine] = field(default_factory=list)

    @property
    def added_lines(self) -> List[DiffLine]:
        """Filter only lines added in this hunk."""
        return [line for line in self.lines if line.type == "+"]


@dataclass
class DiffFile:
    """Represents a changed file within a unified diff."""
    old_path: str
    new_path: str
    status: str  # 'modified', 'added', 'deleted', 'renamed'
    hunks: List[DiffHunk] = field(default_factory=list)
    raw_diff: str = ""

    @property
    def file_path(self) -> str:
        """Normalized path of the changed file."""
        if self.status == "deleted":
            return self.old_path
        return self.new_path

    @property
    def added_lines(self) -> List[DiffLine]:
        """All lines added in this file across all hunks."""
        result: List[DiffLine] = []
        for hunk in self.hunks:
            result.extend(hunk.added_lines)
        return result


class GitDiffParser:
    """
    Parses unified git diff output into structured dataclass hierarchy.
    """

    HUNK_HEADER_REGEX = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)")
    DIFF_FILE_HEADER_REGEX = re.compile(r"^diff --git a/(.*) b/(.*)")

    @classmethod
    def parse(cls, diff_text: str) -> List[DiffFile]:
        """
        Parse unified diff text into a list of DiffFile objects.
        """
        if not diff_text or not diff_text.strip():
            return []

        files: List[DiffFile] = []
        current_file: Optional[DiffFile] = None
        current_hunk: Optional[DiffHunk] = None
        file_diff_lines: List[str] = []

        old_line_counter = 0
        new_line_counter = 0
        diff_position = 0

        lines = diff_text.splitlines()

        for line in lines:
            # Check for new file header: 'diff --git a/... b/...'
            diff_match = cls.DIFF_FILE_HEADER_REGEX.match(line)
            if diff_match:
                if current_file is not None:
                    if current_hunk is not None:
                        current_file.hunks.append(current_hunk)
                        current_hunk = None
                    current_file.raw_diff = "\n".join(file_diff_lines)
                    files.append(current_file)

                old_path = diff_match.group(1)
                new_path = diff_match.group(2)
                current_file = DiffFile(
                    old_path=old_path,
                    new_path=new_path,
                    status="modified",
                    hunks=[],
                )
                file_diff_lines = [line]
                current_hunk = None
                continue

            if current_file is not None:
                file_diff_lines.append(line)

            # Check status hints
            if current_file is not None:
                if line.startswith("new file mode"):
                    current_file.status = "added"
                elif line.startswith("deleted file mode"):
                    current_file.status = "deleted"
                elif line.startswith("similarity index") or line.startswith("rename from"):
                    current_file.status = "renamed"

            # Check for hunk header: '@@ -old,len +new,len @@'
            hunk_match = cls.HUNK_HEADER_REGEX.match(line)
            if hunk_match:
                if current_file is not None and current_hunk is not None:
                    current_file.hunks.append(current_hunk)

                old_start = int(hunk_match.group(1))
                old_lines = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                new_start = int(hunk_match.group(3))
                new_lines = int(hunk_match.group(4)) if hunk_match.group(4) else 1

                old_line_counter = old_start
                new_line_counter = new_start
                diff_position = 1

                current_hunk = DiffHunk(
                    header=line,
                    old_start=old_start,
                    old_lines=old_lines,
                    new_start=new_start,
                    new_lines=new_lines,
                    lines=[],
                )
                continue

            # Process lines inside a hunk
            if current_hunk is not None and current_file is not None:
                if line.startswith("+") and not line.startswith("+++"):
                    current_hunk.lines.append(
                        DiffLine(
                            type="+",
                            content=line[1:],
                            old_line_no=None,
                            new_line_no=new_line_counter,
                            position=diff_position,
                        )
                    )
                    new_line_counter += 1
                    diff_position += 1
                elif line.startswith("-") and not line.startswith("---"):
                    current_hunk.lines.append(
                        DiffLine(
                            type="-",
                            content=line[1:],
                            old_line_no=old_line_counter,
                            new_line_no=None,
                            position=diff_position,
                        )
                    )
                    old_line_counter += 1
                    diff_position += 1
                elif line.startswith(" ") or line == "":
                    content = line[1:] if line.startswith(" ") else line
                    current_hunk.lines.append(
                        DiffLine(
                            type=" ",
                            content=content,
                            old_line_no=old_line_counter,
                            new_line_no=new_line_counter,
                            position=diff_position,
                        )
                    )
                    old_line_counter += 1
                    new_line_counter += 1
                    diff_position += 1

        # Finalize last file and hunk
        if current_file is not None:
            if current_hunk is not None:
                current_file.hunks.append(current_hunk)
            current_file.raw_diff = "\n".join(file_diff_lines)
            files.append(current_file)

        return files

    @classmethod
    def get_summary_text(cls, files: List[DiffFile]) -> str:
        """Generate a concise textual representation of the diff for LLM input."""
        output_chunks: List[str] = []
        for file in files:
            output_chunks.append(f"### File: {file.file_path} (Status: {file.status})")
            for hunk in file.hunks:
                output_chunks.append(f"```diff\n{hunk.header}")
                for line in hunk.lines:
                    prefix = line.type
                    line_no = f"{line.new_line_no or line.old_line_no or ''}: "
                    output_chunks.append(f"{prefix} {line_no}{line.content}")
                output_chunks.append("```\n")
        return "\n".join(output_chunks)
