"""Tests for the repository walker."""

import os

from defender.core.repo import collect_files, expand_paths


def _make_repo(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n")
    (tmp_path / "app" / "util.js").write_text("const y = 2;\n")
    # Junk that must be skipped.
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("bad\n")
    (tmp_path / "README.md").write_text("# docs\n")  # not a code ext
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00\x00binary")
    return tmp_path


def test_collect_files_finds_source_skips_junk(tmp_path):
    _make_repo(tmp_path)
    scan = collect_files(str(tmp_path), use_gitignore=False)
    names = {os.path.basename(f) for f in scan.files}
    assert "main.py" in names
    assert "util.js" in names
    assert "dep.js" not in names  # node_modules excluded
    assert "README.md" not in names  # non-code extension


def test_collect_files_skips_large(tmp_path):
    (tmp_path / "big.py").write_text("# " + "a" * 1000)
    scan = collect_files(str(tmp_path), max_bytes=100, use_gitignore=False)
    assert scan.skipped_large == 1
    assert not scan.files


def test_collect_files_respects_max_files(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    scan = collect_files(str(tmp_path), max_files=3, use_gitignore=False)
    assert len(scan.files) == 3
    assert scan.truncated_at_max is True


def test_expand_paths_mixes_files_and_dirs(tmp_path):
    _make_repo(tmp_path)
    single = str(tmp_path / "app" / "main.py")
    scan = expand_paths([single, str(tmp_path / "app")], use_gitignore=False)
    # main.py appears once despite being passed twice (dir + explicit).
    assert sum("main.py" in f for f in scan.files) == 1


def test_collect_files_binary_detection(tmp_path):
    (tmp_path / "code.py").write_text("print('ok')\n")
    (tmp_path / "fake.py").write_bytes(b"\x00\x01\x02binary masquerading as py")
    scan = collect_files(str(tmp_path), use_gitignore=False)
    names = {os.path.basename(f) for f in scan.files}
    assert "code.py" in names
    assert "fake.py" not in names
    assert scan.skipped_binary == 1


def test_collect_files_covers_broad_language_set(tmp_path):
    """Regression: real repos (Godot/GDScript, Dockerfiles, COBOL, etc.) must
    not silently scan to zero files just because they don't use mainstream
    web-stack extensions. This was a real bug found scanning a public repo.
    """
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "Player.gd").write_text("func _ready():\n\tpass\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    (tmp_path / "legacy.cbl").write_text("IDENTIFICATION DIVISION.\n")
    scan = collect_files(str(tmp_path), use_gitignore=False)
    names = {os.path.basename(f) for f in scan.files}
    assert "Player.gd" in names
    assert "Dockerfile" in names
    assert "legacy.cbl" in names
