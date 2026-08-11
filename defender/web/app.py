"""Defender FastAPI application.

Three surfaces in one process:
  * A dashboard (HTMX) to paste a diff or code and get an instant verdict,
    with a job-based stage-wise progress UI (connect -> clone -> scan ->
    dispatch to ADK agents -> score).
  * A JSON API (`POST /api/analyze`) for programmatic / IDE integration.
  * Webhook receivers for GitHub & GitLab that run on every PR/MR and post the
    verdict back to the review thread.

Reports are cached in memory so the dashboard can deep-link to a full HTML view.
For production you'd back this with a database; the interface is deliberately
small so swapping the store is trivial.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from defender.core.config import get_settings
from defender.core.models import ComplianceReport
from defender.engine import Defender
from defender.integrations import vcs
from defender.reporting import to_html, to_markdown

app = FastAPI(title="Defender", version="0.1.0")
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Tiny in-memory report cache (change_id -> report).
_REPORTS: dict[str, ComplianceReport] = {}
_MAX_CACHE = 200

# In-memory job store backing the stage-wise progress UI (job_id -> state).
# Best-effort / demo-grade: swap for Redis or a DB if this needs to survive a
# restart or run across multiple worker processes.
_JOBS: dict[str, dict] = {}
_MAX_JOBS = 100
_BACKGROUND_TASKS: set[asyncio.Task] = set()


def _store(report: ComplianceReport) -> None:
    if len(_REPORTS) >= _MAX_CACHE:
        _REPORTS.pop(next(iter(_REPORTS)))
    _REPORTS[report.change_id] = report


def _resolve_live_backend(settings) -> tuple[str, str]:
    """Return the (provider, model) actually active right now.

    Mirrors exactly how Defender.__init__ resolves this (ADK is handled
    separately from the get_provider() factory, with its own availability
    check) so the website's footer/architecture badges always show the
    real, currently-active backend -- never a stale hardcoded string.
    """
    provider_name = settings.effective_model_provider
    if provider_name == "adk":
        from defender.adk import adk_available

        if adk_available():
            return "adk", settings.defender_model_name
        # google-adk not installed -> engine.py falls back to get_provider(),
        # which itself falls back to mock for an unrecognized "adk" name.
    from defender.models.factory import get_provider

    provider = get_provider(settings)
    return provider.name, provider.model


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    settings = get_settings()
    live_provider, live_model = _resolve_live_backend(settings)
    return _TEMPLATES.TemplateResponse(
        request,
        "landing.html",
        {
            "recent": list(_REPORTS.values())[-8:][::-1],
            "live_provider": live_provider,
            "live_model": live_model,
            "byom_override_active": bool(settings.openai_api_key.strip()),
        },
    )


async def _run_analysis(
    payload: str, mode: str, llm_enabled: bool, on_progress=None
) -> ComplianceReport:
    """Shared by the legacy synchronous /analyze and the job-based flow.

    Raises defender.core.clone.CloneError for bad repo mode input.
    """
    defender = Defender(use_llm=llm_enabled, llm_max_files=15, on_progress=on_progress)
    if mode == "repo":
        return await defender.analyze_git_url(payload, clone_timeout=30)
    if mode == "diff":
        return await defender.analyze_diff(payload, title="Dashboard review")
    from defender.core.diff import file_to_difffile

    files = [file_to_difffile("pasted_snippet", payload)]
    return await defender.analyze(files, title="Dashboard scan")


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    payload: str = Form(...),
    mode: str = Form("diff"),
    use_llm: str = Form("on"),
) -> HTMLResponse:
    """HTMX endpoint: returns an inline report fragment (no progress UI).

    Kept for simple programmatic use; the website's live demo uses the
    job-based /analyze/start + /analyze/status flow below for stage-wise
    progress instead.
    """
    llm_enabled = use_llm.strip().lower() in {"on", "true", "1", "yes"}
    from defender.core.clone import CloneError

    try:
        report = await _run_analysis(payload, mode, llm_enabled)
    except CloneError as exc:
        return _TEMPLATES.TemplateResponse(
            request, "demo_error.html", {"message": str(exc)}
        )
    _store(report)
    return _TEMPLATES.TemplateResponse(
        request, "report_fragment.html", {"report": report}
    )


def _new_job() -> str:
    if len(_JOBS) >= _MAX_JOBS:
        _JOBS.pop(next(iter(_JOBS)))
    job_id = uuid.uuid4().hex[:12]
    _JOBS[job_id] = {"stages": [], "done": False, "error": None, "report": None}
    return job_id


async def _run_job(job_id: str, payload: str, mode: str, llm_enabled: bool) -> None:
    from defender.core.clone import CloneError

    job = _JOBS[job_id]

    def on_progress(message: str) -> None:
        job["stages"].append(message)

    try:
        report = await _run_analysis(payload, mode, llm_enabled, on_progress)
        _store(report)
        job["report"] = report
    except CloneError as exc:
        job["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        job["error"] = f"Unexpected error: {exc}"
    finally:
        job["done"] = True


@app.post("/analyze/start", response_class=HTMLResponse)
async def analyze_start(
    request: Request,
    payload: str = Form(...),
    mode: str = Form("diff"),
    use_llm: str = Form("on"),
) -> HTMLResponse:
    """Kick off analysis in the background; returns a self-polling progress
    fragment immediately so the UI can show real stage-wise updates."""
    llm_enabled = use_llm.strip().lower() in {"on", "true", "1", "yes"}
    job_id = _new_job()
    task = asyncio.create_task(_run_job(job_id, payload, mode, llm_enabled))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return _TEMPLATES.TemplateResponse(
        request, "progress_fragment.html", {"job_id": job_id, "stages": []}
    )


@app.get("/analyze/status/{job_id}", response_class=HTMLResponse)
async def analyze_status(request: Request, job_id: str) -> HTMLResponse:
    job = _JOBS.get(job_id)
    if job is None:
        return _TEMPLATES.TemplateResponse(
            request, "demo_error.html", {"message": "Job not found or expired."}
        )
    if job["error"]:
        return _TEMPLATES.TemplateResponse(
            request, "demo_error.html", {"message": job["error"]}
        )
    if job["done"] and job["report"] is not None:
        return _TEMPLATES.TemplateResponse(
            request, "report_fragment.html", {"report": job["report"]}
        )
    return _TEMPLATES.TemplateResponse(
        request,
        "progress_fragment.html",
        {"job_id": job_id, "stages": job["stages"]},
    )


@app.get("/report/{change_id}", response_class=HTMLResponse)
async def report_view(change_id: str) -> Response:
    report = _REPORTS.get(change_id)
    if not report:
        return HTMLResponse("<h1>Report not found</h1>", status_code=404)
    return HTMLResponse(to_html(report))


@app.post("/api/analyze")
async def api_analyze(request: Request) -> JSONResponse:
    body = await request.json()
    diff_text = body.get("diff")
    code = body.get("code")
    use_llm = body.get("use_llm", True)
    defender = Defender(use_llm=use_llm)
    if diff_text:
        report = await defender.analyze_diff(diff_text, title="API review")
    elif code:
        from defender.core.diff import file_to_difffile

        report = await defender.analyze(
            [file_to_difffile(body.get("path", "snippet"), code)], title="API scan"
        )
    else:
        return JSONResponse({"error": "provide 'diff' or 'code'"}, status_code=400)
    _store(report)
    status = 200 if report.verdict.value != "fail" else 422
    return JSONResponse(report.model_dump(mode="json"), status_code=status)


@app.post("/webhook/github")
async def webhook_github(request: Request) -> JSONResponse:
    settings = get_settings()
    raw = await request.body()
    sig = request.headers.get("X-Hub-Signature-256")
    if not vcs.verify_github_signature(settings.github_webhook_secret, raw, sig):
        return JSONResponse({"error": "bad signature"}, status_code=401)

    event = request.headers.get("X-GitHub-Event", "")
    payload = await request.json()

    # On-demand full-repo audit: a maintainer comments "/defender audit" on a PR.
    if event == "issue_comment":
        return await _handle_github_comment(payload, settings)

    if event != "pull_request" or payload.get("action") not in {
        "opened",
        "synchronize",
        "reopened",
    }:
        return JSONResponse({"status": "ignored", "event": event})

    repo = payload["repository"]["full_name"]
    pr = payload["pull_request"]["number"]
    sha = payload["pull_request"]["head"]["sha"]
    token = settings.github_token

    report = await _review_remote_github(repo, pr, token)
    posted = False
    if token:
        posted = await vcs.post_github_comment(repo, pr, token, report)
        await vcs.set_github_status(repo, sha, token, report)
    return JSONResponse(
        {
            "status": "reviewed",
            "verdict": report.verdict.value,
            "score": report.overall_score,
            "comment_posted": posted,
            "change_id": report.change_id,
        }
    )


async def _handle_github_comment(payload: dict, settings) -> JSONResponse:
    if payload.get("action") != "created":
        return JSONResponse({"status": "ignored", "reason": "not a new comment"})
    issue = payload.get("issue", {})
    if "pull_request" not in issue:
        return JSONResponse({"status": "ignored", "reason": "comment not on a PR"})
    body = payload.get("comment", {}).get("body", "")
    if not vcs.has_audit_trigger(body):
        return JSONResponse({"status": "ignored", "reason": "no trigger phrase"})

    repo = payload["repository"]["full_name"]
    pr = issue["number"]
    token = settings.github_token
    if not token:
        return JSONResponse({"status": "error", "reason": "no github_token configured"})

    from defender.core.clone import CloneError

    try:
        clone_url, branch = await vcs.fetch_github_pr_head(repo, pr, token)
        defender = Defender(llm_max_files=25)
        report = await defender.analyze_git_url(
            clone_url, branch=branch, auth_token=token
        )
        report.title = f"{repo}#{pr} (full-repo audit @ {branch})"
    except CloneError as exc:
        posted = await vcs.post_github_comment_raw(
            repo, pr, token, f"**Defender audit failed:** {exc}"
        )
        return JSONResponse({"status": "error", "reason": str(exc), "comment_posted": posted})

    _store(report)
    posted = await vcs.post_github_comment(repo, pr, token, report)
    return JSONResponse(
        {
            "status": "audited",
            "verdict": report.verdict.value,
            "score": report.overall_score,
            "comment_posted": posted,
            "change_id": report.change_id,
        }
    )


@app.post("/webhook/gitlab")
async def webhook_gitlab(request: Request) -> JSONResponse:
    settings = get_settings()
    token_hdr = request.headers.get("X-Gitlab-Token")
    if not vcs.verify_gitlab_token(settings.gitlab_webhook_secret, token_hdr):
        return JSONResponse({"error": "bad token"}, status_code=401)

    payload = await request.json()

    # On-demand full-repo audit: someone comments "/defender audit" on an MR.
    if payload.get("object_kind") == "note":
        return await _handle_gitlab_note(payload, settings)

    if payload.get("object_kind") != "merge_request":
        return JSONResponse({"status": "ignored"})

    attrs = payload["object_attributes"]
    if attrs.get("action") not in {"open", "update", "reopen"}:
        return JSONResponse({"status": "ignored", "action": attrs.get("action")})

    base_url = payload["project"]["web_url"].rsplit("/", 2)[0]
    project_id = str(payload["project"]["id"])
    mr_iid = attrs["iid"]
    token = settings.gitlab_token

    report = await _review_remote_gitlab(base_url, project_id, mr_iid, token)
    posted = False
    if token:
        posted = await vcs.post_gitlab_note(base_url, project_id, mr_iid, token, report)
    return JSONResponse(
        {
            "status": "reviewed",
            "verdict": report.verdict.value,
            "score": report.overall_score,
            "note_posted": posted,
        }
    )


async def _handle_gitlab_note(payload: dict, settings) -> JSONResponse:
    mr = payload.get("merge_request")
    if not mr:
        return JSONResponse({"status": "ignored", "reason": "note not on an MR"})
    body = payload.get("object_attributes", {}).get("note", "")
    if not vcs.has_audit_trigger(body):
        return JSONResponse({"status": "ignored", "reason": "no trigger phrase"})

    base_url = payload["project"]["web_url"].rsplit("/", 2)[0]
    project_id = str(payload["project"]["id"])
    mr_iid = mr["iid"]
    token = settings.gitlab_token
    if not token:
        return JSONResponse({"status": "error", "reason": "no gitlab_token configured"})

    from defender.core.clone import CloneError

    try:
        clone_url, branch = await vcs.fetch_gitlab_mr_head(
            base_url, project_id, mr_iid, token
        )
        defender = Defender(llm_max_files=25)
        report = await defender.analyze_git_url(
            clone_url, branch=branch, auth_token=token
        )
        report.title = f"MR!{mr_iid} (full-repo audit @ {branch})"
    except CloneError as exc:
        posted = await vcs.post_gitlab_note_raw(
            base_url, project_id, mr_iid, token, f"**Defender audit failed:** {exc}"
        )
        return JSONResponse({"status": "error", "reason": str(exc), "note_posted": posted})

    _store(report)
    posted = await vcs.post_gitlab_note(base_url, project_id, mr_iid, token, report)
    return JSONResponse(
        {
            "status": "audited",
            "verdict": report.verdict.value,
            "score": report.overall_score,
            "note_posted": posted,
            "change_id": report.change_id,
        }
    )


@app.get("/healthz")
async def healthz() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "provider": settings.effective_model_provider,
        "configured_provider": settings.defender_model_provider,
    }


async def _review_remote_github(repo: str, pr: int, token: str) -> ComplianceReport:
    defender = Defender()
    diff = ""
    if token:
        try:
            diff = await vcs.fetch_github_pr_diff(repo, pr, token)
        except Exception:
            diff = ""
    report = await defender.analyze_diff(diff, title=f"{repo}#{pr}")
    _store(report)
    return report


async def _review_remote_gitlab(
    base_url: str, project_id: str, mr_iid: int, token: str
) -> ComplianceReport:
    defender = Defender()
    diff = ""
    if token:
        try:
            diff = await vcs.fetch_gitlab_mr_diff(base_url, project_id, mr_iid, token)
        except Exception:
            diff = ""
    report = await defender.analyze_diff(diff, title=f"MR!{mr_iid}")
    _store(report)
    return report
