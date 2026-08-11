"""Shared code-batching for LLM analysis.

Both the native per-agent path and the genuine ADK pipeline need to turn a set
of change-set files into char-bounded batches (so large repos degrade
predictably instead of silently truncating). One implementation, used by both.
"""

from __future__ import annotations

from defender.core.diff import DiffFile

MAX_CODE_CHARS = 6000


def collect_batches(
    files: list[DiffFile],
    max_files: int = 40,
    max_batches: int = 8,
    max_chars: int = MAX_CODE_CHARS,
) -> list[str]:
    """Group added code into char-bounded batches for one-or-more LLM calls."""
    usable = [
        df for df in files if not df.is_deleted and df.added_text().strip()
    ][:max_files]
    batches: list[str] = []
    current: list[str] = []
    size = 0
    for df in usable:
        block = f"### FILE: {df.path}\n{df.added_text()[:max_chars]}\n"
        if size + len(block) > max_chars and current:
            batches.append("\n".join(current))
            current, size = [], 0
            if len(batches) >= max_batches:
                return batches
        current.append(block)
        size += len(block)
    if current and len(batches) < max_batches:
        batches.append("\n".join(current))
    return batches
