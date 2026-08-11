"""Web app + VCS integration tests (FastAPI TestClient)."""

import hashlib
import hmac

from fastapi.testclient import TestClient

from defender.integrations import vcs
from defender.web.app import app

client = TestClient(app)


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_dashboard_renders():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Defender" in resp.text
    assert "Run Defender" in resp.text


def test_dashboard_shows_live_backend_not_hardcoded():
    """Regression: the footer used to hardcode 'Google ADK + Gemini' /
    'Walmart PROD LLM Gateway' regardless of actual config. It must now
    reflect the real, currently-resolved provider.
    """
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Backend:" in resp.text
    assert "Model:" in resp.text


def test_api_analyze_flags_vulnerable_code():
    resp = client.post(
        "/api/analyze",
        json={"code": 'password = "hunter2secret"\neval(x)', "path": "s.py"},
    )
    # eval() is HIGH -> gate FAILs -> 422
    assert resp.status_code == 422
    body = resp.json()
    assert body["verdict"] == "fail"
    assert any(f["id"] == "SEC-HARDCODED-SECRET" for f in _findings(body))


def test_api_analyze_requires_payload():
    resp = client.post("/api/analyze", json={})
    assert resp.status_code == 400


def test_htmx_analyze_returns_fragment():
    resp = client.post(
        "/analyze",
        data={"mode": "code", "use_llm": "on", "payload": "num = 4111111111111111"},
    )
    assert resp.status_code == 200
    assert "Findings" in resp.text


def test_htmx_analyze_respects_unchecked_llm_checkbox():
    """Regression: an unchecked checkbox must disable the LLM, not silently
    fall back to the Form("on") default. Browsers omit unchecked checkboxes
    entirely, and the hidden-fallback-field must send an explicit 'off' that
    isn't clobbered by FastAPI's empty-string-falls-back-to-default quirk.
    """
    resp = client.post(
        "/analyze",
        data={"mode": "code", "use_llm": "off", "payload": "x = 1"},
    )
    assert resp.status_code == 200
    assert "backend <code" in resp.text
    assert ">mock<" in resp.text  # static-only path -> mock provider label


def test_analyze_start_returns_polling_progress_fragment():
    """The job-based stage-wise progress endpoint kicks off a background
    task and immediately returns a self-polling fragment (not the report).
    """
    resp = client.post(
        "/analyze/start",
        data={"mode": "code", "use_llm": "off", "payload": "eval(x)"},
    )
    assert resp.status_code == 200
    assert "Defender is working" in resp.text
    assert "hx-get" in resp.text and "/analyze/status/" in resp.text


def test_analyze_status_eventually_returns_final_report():
    """Polling /analyze/status until done must yield the same report shape
    as the synchronous /analyze endpoint -- the job wrapper must not change
    the underlying analysis result.
    """
    import re
    import time

    start = client.post(
        "/analyze/start",
        data={"mode": "code", "use_llm": "off", "payload": "eval(x)"},
    )
    job_id = re.search(r"/analyze/status/([a-f0-9]+)", start.text).group(1)

    body = ""
    for _ in range(50):
        resp = client.get(f"/analyze/status/{job_id}")
        body = resp.text
        if "Findings" in body:
            break
        time.sleep(0.05)
    assert "Findings" in body


def test_analyze_status_unknown_job_returns_error_fragment():
    resp = client.get("/analyze/status/doesnotexist")
    assert resp.status_code == 200
    assert "not found" in resp.text.lower()


def test_github_signature_verification():
    secret = "topsecret"
    body = b'{"hello":"world"}'
    good = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert vcs.verify_github_signature(secret, body, good) is True
    assert vcs.verify_github_signature(secret, body, "sha256=nope") is False
    # No secret configured => dev mode, accept.
    assert vcs.verify_github_signature("", body, None) is True


def test_gitlab_diff_reconstruction_shape():
    # Smoke: the note header includes the verdict marker.
    from defender.core.models import ComplianceReport, Verdict

    report = ComplianceReport(change_id="abc123", verdict=Verdict.FAIL, overall_score=10)
    header = vcs._comment_header(report)
    assert "defender:abc123" in header
    assert "FAIL" in header


def _findings(body: dict) -> list:
    out = []
    for d in body["dimensions"]:
        out.extend(d["findings"])
    return out


class _FakeSettings:
    """Minimal settings stub so comment-trigger tests don't need real secrets."""

    github_webhook_secret = ""
    gitlab_webhook_secret = ""
    github_token = "tok"
    gitlab_token = "tok"


def test_has_audit_trigger():
    assert vcs.has_audit_trigger("please /defender audit this branch")
    assert vcs.has_audit_trigger("/DEFENDER AUDIT")
    assert not vcs.has_audit_trigger("looks good to me, LGTM")


def test_github_comment_ignored_when_not_a_pr(monkeypatch):
    import defender.web.app as web_app

    monkeypatch.setattr(web_app, "get_settings", lambda: _FakeSettings())
    resp = client.post(
        "/webhook/github",
        headers={"X-GitHub-Event": "issue_comment"},
        json={
            "action": "created",
            "issue": {"number": 1},  # no 'pull_request' key => plain issue
            "comment": {"body": "/defender audit"},
            "repository": {"full_name": "acme/bank"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_github_comment_ignored_without_trigger(monkeypatch):
    import defender.web.app as web_app

    monkeypatch.setattr(web_app, "get_settings", lambda: _FakeSettings())
    resp = client.post(
        "/webhook/github",
        headers={"X-GitHub-Event": "issue_comment"},
        json={
            "action": "created",
            "issue": {"number": 1, "pull_request": {}},
            "comment": {"body": "nice work!"},
            "repository": {"full_name": "acme/bank"},
    },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_github_comment_triggers_full_repo_audit(monkeypatch):
    import defender.web.app as web_app
    from defender.core.models import ComplianceReport, Verdict

    async def fake_head(repo, pr, token):
        return "https://github.com/acme/bank.git", "feature/x"

    async def fake_analyze_git_url(self, url, clone_timeout=45, branch=None, auth_token=None):
        assert branch == "feature/x"
        assert auth_token == "tok"
        return ComplianceReport(change_id="c1", verdict=Verdict.FAIL, overall_score=10)

    async def fake_post(repo, pr, token, report):
        return True

    monkeypatch.setattr(web_app, "get_settings", lambda: _FakeSettings())
    monkeypatch.setattr(vcs, "fetch_github_pr_head", fake_head)
    monkeypatch.setattr("defender.engine.Defender.analyze_git_url", fake_analyze_git_url)
    monkeypatch.setattr(vcs, "post_github_comment", fake_post)

    resp = client.post(
        "/webhook/github",
        headers={"X-GitHub-Event": "issue_comment"},
        json={
            "action": "created",
            "issue": {"number": 7, "pull_request": {}},
            "comment": {"body": "/defender audit please"},
            "repository": {"full_name": "acme/bank"},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "audited"
    assert body["verdict"] == "fail"
    assert body["comment_posted"] is True


def test_gitlab_note_ignored_without_mr(monkeypatch):
    import defender.web.app as web_app

    monkeypatch.setattr(web_app, "get_settings", lambda: _FakeSettings())
    resp = client.post(
        "/webhook/gitlab",
        json={"object_kind": "note", "object_attributes": {"note": "/defender audit"}},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_gitlab_note_triggers_full_repo_audit(monkeypatch):
    import defender.web.app as web_app
    from defender.core.models import ComplianceReport, Verdict

    async def fake_head(base_url, project_id, mr_iid, token):
        return "https://gitlab.com/acme/bank.git", "feature/y"

    async def fake_analyze_git_url(self, url, clone_timeout=45, branch=None, auth_token=None):
        assert branch == "feature/y"
        return ComplianceReport(change_id="c2", verdict=Verdict.WARN, overall_score=65)

    async def fake_note(base_url, project_id, mr_iid, token, report):
        return True

    monkeypatch.setattr(web_app, "get_settings", lambda: _FakeSettings())
    monkeypatch.setattr(vcs, "fetch_gitlab_mr_head", fake_head)
    monkeypatch.setattr("defender.engine.Defender.analyze_git_url", fake_analyze_git_url)
    monkeypatch.setattr(vcs, "post_gitlab_note", fake_note)

    resp = client.post(
        "/webhook/gitlab",
        json={
            "object_kind": "note",
            "object_attributes": {"note": "/defender audit"},
            "merge_request": {"iid": 3},
            "project": {"id": 55, "web_url": "https://gitlab.com/acme/bank"},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "audited"
    assert body["verdict"] == "warn"
    assert body["note_posted"] is True
