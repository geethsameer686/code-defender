"""VCS integrations — GitHub & GitLab webhook plumbing.

Responsibilities:
  * Verify webhook signatures (HMAC) so we don't act on spoofed events.
  * Fetch the PR/MR diff.
  * Post the Defender verdict back as a review comment and (optionally) a
    commit status / merge-request note — the 'runs on every pull request' story.

All network calls are best-effort and require a token; without one, the handler
still returns the computed report so the dashboard/logs stay useful.
"""

from __future__ import annotations

import hashlib
import hmac

import httpx

from defender.core.models import ComplianceReport, Verdict
from defender.reporting import to_markdown

_GH_API = "https://api.github.com"

# Comment trigger for on-demand full-repo audits (vs. the automatic diff-only
# review that runs on every PR/MR event).
AUDIT_TRIGGER = "/defender audit"


def has_audit_trigger(comment_body: str) -> bool:
    return AUDIT_TRIGGER in (comment_body or "").lower()


def verify_github_signature(secret: str, body: bytes, signature: str | None) -> bool:
    if not secret:
        return True  # no secret configured -> skip verification (dev mode)
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_gitlab_token(secret: str, token: str | None) -> bool:
    if not secret:
        return True
    return hmac.compare_digest(secret, token or "")


async def fetch_github_pr_head(repo: str, pr_number: int, token: str) -> tuple[str, str]:
    """Return (clone_url, branch_ref) for a PR's head, for a full-repo audit.

    `issue_comment` webhook payloads don't include head branch info, so this
    hits the PR API directly.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{_GH_API}/repos/{repo}/pulls/{pr_number}", headers=headers
        )
        resp.raise_for_status()
        data = resp.json()
    head = data["head"]
    return head["repo"]["clone_url"], head["ref"]


async def fetch_gitlab_mr_head(
    base_url: str, project_id: str, mr_iid: int, token: str
) -> tuple[str, str]:
    """Return (clone_url, source_branch) for an MR's head."""
    headers = {"PRIVATE-TOKEN": token}
    async with httpx.AsyncClient(timeout=30) as client:
        mr_resp = await client.get(
            f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            headers=headers,
        )
        mr_resp.raise_for_status()
        mr = mr_resp.json()
        proj_resp = await client.get(
            f"{base_url}/api/v4/projects/{mr['source_project_id']}", headers=headers
        )
        proj_resp.raise_for_status()
        project = proj_resp.json()
    return project["http_url_to_repo"], mr["source_branch"]


async def fetch_github_pr_diff(repo: str, pr_number: int, token: str) -> str:
    """Fetch a PR's unified diff via the GitHub 'diff' media type."""
    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{_GH_API}/repos/{repo}/pulls/{pr_number}", headers=headers
        )
        resp.raise_for_status()
        return resp.text


async def post_github_comment(
    repo: str, pr_number: int, token: str, report: ComplianceReport
) -> bool:
    """Post the Defender report as an issue comment on the PR."""
    body = _comment_header(report) + "\n\n" + to_markdown(report)
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{_GH_API}/repos/{repo}/issues/{pr_number}/comments",
            headers=headers,
            json={"body": body},
        )
        return resp.status_code < 300


async def post_github_comment_raw(repo: str, pr_number: int, token: str, body: str) -> bool:
    """Post a plain-text comment (used for error/status messages, not a full report)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{_GH_API}/repos/{repo}/issues/{pr_number}/comments",
            headers=headers,
            json={"body": body},
        )
        return resp.status_code < 300


async def set_github_status(
    repo: str, sha: str, token: str, report: ComplianceReport
) -> bool:
    """Set a commit status so Defender can be a required check."""
    state = {
        Verdict.PASS: "success",
        Verdict.WARN: "success",
        Verdict.FAIL: "failure",
    }[report.verdict]
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{_GH_API}/repos/{repo}/statuses/{sha}",
            headers=headers,
            json={
                "state": state,
                "context": "defender/compliance",
                "description": f"score {report.overall_score}/100 · {report.verdict.value}",
            },
        )
        return resp.status_code < 300


async def fetch_gitlab_mr_diff(
    base_url: str, project_id: str, mr_iid: int, token: str
) -> str:
    """Fetch and reconstruct a GitLab MR diff."""
    headers = {"PRIVATE-TOKEN": token}
    url = f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/changes"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    chunks = []
    for ch in data.get("changes", []):
        path = ch.get("new_path", ch.get("old_path", "unknown"))
        chunks.append(f"diff --git a/{path} b/{path}")
        if ch.get("new_file"):
            chunks.append("new file mode 100644")
        chunks.append(f"--- a/{path}")
        chunks.append(f"+++ b/{path}")
        chunks.append(ch.get("diff", ""))
    return "\n".join(chunks)


async def post_gitlab_note(
    base_url: str, project_id: str, mr_iid: int, token: str, report: ComplianceReport
) -> bool:
    body = _comment_header(report) + "\n\n" + to_markdown(report)
    headers = {"PRIVATE-TOKEN": token}
    url = f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=headers, json={"body": body})
        return resp.status_code < 300


async def post_gitlab_note_raw(
    base_url: str, project_id: str, mr_iid: int, token: str, body: str
) -> bool:
    """Post a plain-text note (used for error/status messages, not a full report)."""
    headers = {"PRIVATE-TOKEN": token}
    url = f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=headers, json={"body": body})
        return resp.status_code < 300


def _comment_header(report: ComplianceReport) -> str:
    return (
        f"<!-- defender:{report.change_id} -->\n"
        f"**Defender** validated this change: **{report.verdict.value.upper()}** "
        f"(score {report.overall_score}/100)."
    )
