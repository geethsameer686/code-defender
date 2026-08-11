"""Tests for the git-clone safety guards (no network calls)."""

import pytest

from defender.core.clone import CloneError, looks_like_git_url, _reject_private_targets


def test_looks_like_git_url_accepts_https():
    assert looks_like_git_url("https://github.com/pallets/flask.git")
    assert looks_like_git_url("https://gitlab.com/group/project")


def test_looks_like_git_url_rejects_junk():
    assert not looks_like_git_url("/local/path")
    assert not looks_like_git_url("not a url at all")
    assert not looks_like_git_url("ssh://git@github.com/x/y.git")
    assert not looks_like_git_url("file:///etc/passwd")


def test_rejects_localhost():
    with pytest.raises(CloneError):
        _reject_private_targets("http://localhost:8080/x.git")


def test_rejects_non_http_scheme():
    with pytest.raises(CloneError):
        _reject_private_targets("ftp://example.com/x.git")
