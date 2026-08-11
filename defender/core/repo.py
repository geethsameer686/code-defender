"""Repository walker — turns a directory (or git repo) into an analyzable file set.

The naive "scan these exact files" approach silently analyzes *nothing* when you
point it at a directory, which for a compliance gate is a dangerous false-green.
This module expands a directory into real source files while:

  * Respecting ``.gitignore`` (via ``git ls-files`` when inside a repo).
  * Skipping vendor/build/cache junk (node_modules, .venv, dist, ...).
  * Filtering to known source extensions.
  * Bounding per-file size and total file count with explicit stats so a huge
    monorepo degrades predictably instead of hanging or OOMing.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

# Directories we never want to walk into.
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "out", "target", ".next", ".nuxt", "coverage",
    ".tox", ".idea", ".vscode", "vendor", "site-packages", ".terraform",
    "bin", "obj", ".gradle", ".cache",
}

# Source extensions worth analyzing. Deliberately excludes binaries/lockfiles.
# "Any language" is a real product claim, so this list is intentionally broad
# rather than curated to whatever the maintainers personally write in.
DEFAULT_CODE_EXTS = {
    # Mainstream
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".kt", ".kts",
    ".scala", ".swift", ".m", ".mm", ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".bat", ".cmd", ".sql", ".pl", ".pm",
    # Config/infra-as-code (findings live here too: TLS flags, secrets, etc.)
    ".yaml", ".yml", ".tf", ".hcl", ".gradle", ".groovy", ".vue", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".proto", ".graphql",
    # Legacy / mainframe — real presence in banking codebases
    ".cob", ".cbl", ".cpy", ".pli", ".rpg", ".pas", ".f", ".f90", ".asm", ".s",
    # Web front-end
    ".html", ".htm", ".css", ".scss", ".less",
    # Functional / other ecosystems
    ".dart", ".lua", ".r", ".jl", ".ex", ".exs", ".erl", ".hrl",
    ".clj", ".cljs", ".cljc", ".zig", ".nim", ".v", ".vb",
    # Smart contracts (relevant for banking/fintech blockchain work)
    ".sol",
    # Game engines (GDScript — Godot)
    ".gd",
}

# Extensionless files that are unambiguously source/config, matched by exact
# basename (case-insensitive) rather than extension.
DEFAULT_CODE_FILENAMES = {
    "dockerfile", "makefile", "jenkinsfile", "rakefile", "gemfile",
    "procfile", "vagrantfile", "cmakelists.txt",
}


@dataclass
class RepoScan:
    files: list[str] = field(default_factory=list)
    skipped_large: int = 0
    skipped_binary: int = 0
    truncated_at_max: bool = False
    total_seen: int = 0
    root: str = ""

    def summary(self) -> str:
        parts = [f"{len(self.files)} source file(s)"]
        if self.skipped_large:
            parts.append(f"{self.skipped_large} skipped (too large)")
        if self.skipped_binary:
            parts.append(f"{self.skipped_binary} skipped (binary)")
        if self.truncated_at_max:
            parts.append("hit max-files cap")
        return ", ".join(parts)


def _is_git_repo(root: str) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", root, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, check=False,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, FileNotFoundError):
        return False


def _git_tracked_files(root: str) -> list[str] | None:
    """List tracked + untracked-but-not-ignored files (respects .gitignore)."""
    try:
        r = subprocess.run(
            ["git", "-C", root, "ls-files", "--cached", "--others",
             "--exclude-standard"],
            capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            return None
        return [os.path.join(root, line) for line in r.stdout.splitlines() if line]
    except (OSError, FileNotFoundError):
        return None


def _walk_files(root: str, exclude_dirs: set[str]) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".")]
        for fn in filenames:
            out.append(os.path.join(dirpath, fn))
    return out


def _looks_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


def collect_files(
    root: str,
    exts: set[str] | None = None,
    extra_excludes: set[str] | None = None,
    max_files: int = 2000,
    max_bytes: int = 400_000,
    use_gitignore: bool = True,
) -> RepoScan:
    """Expand a directory into a bounded list of analyzable source files."""
    exts = exts or DEFAULT_CODE_EXTS
    exclude_dirs = DEFAULT_EXCLUDE_DIRS | (extra_excludes or set())
    scan = RepoScan(root=os.path.abspath(root))

    candidates: list[str] | None = None
    if use_gitignore and _is_git_repo(root):
        candidates = _git_tracked_files(root)
    if candidates is None:
        candidates = _walk_files(root, exclude_dirs)

    for path in sorted(candidates):
        # Filter out excluded path segments (git list can include them via -o).
        parts = set(os.path.normpath(path).split(os.sep))
        if parts & exclude_dirs:
            continue
        ext = os.path.splitext(path)[1].lower()
        basename_ok = os.path.basename(path).lower() in DEFAULT_CODE_FILENAMES
        if exts and ext not in exts and not basename_ok:
            continue
        if not os.path.isfile(path):
            continue
        scan.total_seen += 1
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > max_bytes:
            scan.skipped_large += 1
            continue
        if _looks_binary(path):
            scan.skipped_binary += 1
            continue
        scan.files.append(path)
        if len(scan.files) >= max_files:
            scan.truncated_at_max = True
            break

    return scan


def expand_paths(paths: list[str], **kwargs) -> RepoScan:
    """Accept a mix of files and directories; expand dirs, keep files."""
    combined = RepoScan()
    for p in paths:
        if os.path.isdir(p):
            sub = collect_files(p, **kwargs)
            combined.files.extend(sub.files)
            combined.skipped_large += sub.skipped_large
            combined.skipped_binary += sub.skipped_binary
            combined.truncated_at_max = combined.truncated_at_max or sub.truncated_at_max
            combined.total_seen += sub.total_seen
        elif os.path.isfile(p):
            combined.files.append(p)
            combined.total_seen += 1
    # De-dup while preserving order.
    seen: set[str] = set()
    combined.files = [f for f in combined.files if not (f in seen or seen.add(f))]
    return combined
