"""Unified-diff parser.

Turns a raw `git diff` / PR patch into structured files and hunks so analyzers
can reason about *added* lines specifically (shift-left: we care about what the
change introduces, not the whole world). Also supports whole-file ingestion for
`defender scan <path>`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FILE_HEADER = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_PLUSPLUS = re.compile(r"^\+\+\+ b/(?P<path>.+)$")
_MINUSMINUS = re.compile(r"^--- a/(?P<path>.+)$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")


@dataclass
class DiffLine:
    """One line in a change set with its resolved line number in the new file."""

    new_lineno: int | None
    content: str
    added: bool


@dataclass
class DiffFile:
    """A single file's worth of changes."""

    path: str
    lines: list[DiffLine] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False

    @property
    def added_lines(self) -> list[DiffLine]:
        return [ln for ln in self.lines if ln.added]

    def added_text(self) -> str:
        """Just the added lines, joined — the surface Defender scrutinizes most."""
        return "\n".join(ln.content for ln in self.added_lines)

    def full_text(self) -> str:
        """All context+added lines, for whole-file scans."""
        return "\n".join(ln.content for ln in self.lines)


def parse_diff(diff_text: str) -> list[DiffFile]:
    """Parse a unified diff into DiffFile objects."""
    files: list[DiffFile] = []
    current: DiffFile | None = None
    new_lineno = 0

    for raw in diff_text.splitlines():
        header = _FILE_HEADER.match(raw)
        if header:
            current = DiffFile(path=header.group("b"))
            files.append(current)
            new_lineno = 0
            continue
        if current is None:
            continue

        if raw.startswith("new file mode"):
            current.is_new = True
            continue
        if raw.startswith("deleted file mode"):
            current.is_deleted = True
            continue

        pp = _PLUSPLUS.match(raw)
        if pp:
            if pp.group("path") != "/dev/null":
                current.path = pp.group("path")
            continue
        if _MINUSMINUS.match(raw):
            continue

        hunk = _HUNK.match(raw)
        if hunk:
            new_lineno = int(hunk.group("start"))
            continue

        if raw.startswith("+") and not raw.startswith("+++"):
            current.lines.append(
                DiffLine(new_lineno=new_lineno, content=raw[1:], added=True)
            )
            new_lineno += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            current.lines.append(DiffLine(new_lineno=None, content=raw[1:], added=False))
        elif raw.startswith(" "):
            current.lines.append(
                DiffLine(new_lineno=new_lineno, content=raw[1:], added=False)
            )
            new_lineno += 1

    return files


def file_to_difffile(path: str, content: str) -> DiffFile:
    """Wrap a whole file as a DiffFile where every line counts as 'added'.

    Lets `defender scan` reuse the exact same analyzer pipeline as PR review.
    """
    df = DiffFile(path=path, is_new=True)
    for i, line in enumerate(content.splitlines(), start=1):
        df.lines.append(DiffLine(new_lineno=i, content=line, added=True))
    return df
