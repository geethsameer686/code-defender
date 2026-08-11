"""Safe shallow git-clone helper for scanning remote repositories.

Used by ``defender audit <git-url>`` and the website's "scan a repo" demo.
Deliberately conservative: only http(s) git URLs, no local/file/ssh schemes (no
SSRF-via-file:// or arbitrary local-path traversal), a hard clone timeout, and
guaranteed cleanup of the temp checkout via a context manager.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import shutil
import socket
import subprocess
import tempfile
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}
# Loose but sane: host/org/repo(.git), optionally with a path prefix.
_URL_RE = re.compile(r"^https?://[\w.\-]+(?::\d+)?/[\w.\-/]+?(?:\.git)?/?$", re.IGNORECASE)


class CloneError(Exception):
    """Raised when a URL is rejected or the clone fails/times out."""


def looks_like_git_url(value: str) -> bool:
    """Cheap heuristic so callers can route a CLI arg to clone vs. local path."""
    return bool(_URL_RE.match(value.strip()))


def _reject_private_targets(url: str) -> None:
    """Block obviously internal/loopback targets to avoid SSRF-style abuse."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise CloneError(f"Unsupported scheme '{parsed.scheme}'. Only http/https allowed.")
    host = parsed.hostname or ""
    if host in {"localhost"}:
        raise CloneError("Refusing to clone from localhost.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return  # can't resolve here; let git itself fail with a clear error
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise CloneError(f"Refusing to clone from a private/internal address ({ip}).")


def _inject_token(url: str, token: str | None) -> str:
    """Embed a PAT into an https clone URL for private-repo access.

    Works for both GitHub (`https://<token>@github.com/...`) and GitLab
    (`https://oauth2:<token>@gitlab.com/...` also accepts a bare token form).
    Never logged/returned to callers — used only for the local `git clone`.
    """
    if not token:
        return url
    parsed = urlparse(url)
    netloc = f"{token}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


@contextlib.contextmanager
def cloned_repo(
    url: str,
    timeout: int = 45,
    branch: str | None = None,
    auth_token: str | None = None,
):
    """Shallow-clone `url` into a temp dir; yields the path; always cleans up.

    `auth_token`, if given, is injected into the clone URL only (for private
    repos) and is never stored, logged, or returned in any report.
    """
    url = url.strip()
    if not looks_like_git_url(url):
        raise CloneError(f"'{url}' does not look like a supported git URL.")
    _reject_private_targets(url)

    clone_url = _inject_token(url, auth_token)
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]

    tmpdir = tempfile.mkdtemp(prefix="defone_")
    try:
        result = subprocess.run(
            [*cmd, clone_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            # Scrub any token that might have leaked into git's stderr.
            err = (result.stderr or "unknown error")[-400:]
            if auth_token:
                err = err.replace(auth_token, "***")
            raise CloneError(f"git clone failed: {err}")
        yield tmpdir
    except subprocess.TimeoutExpired as exc:
        raise CloneError(f"Clone timed out after {timeout}s.") from exc
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
