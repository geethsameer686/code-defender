"""Tests for the diff parser and static rule engine."""

from defender.core.diff import file_to_difffile, parse_diff
from defender.core.models import Dimension, Severity
from defender.rules import default_engine


def test_parse_diff_extracts_added_lines():
    diff = (
        "diff --git a/a.py b/a.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/a.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+x = 1\n"
        "+y = 2\n"
    )
    files = parse_diff(diff)
    assert len(files) == 1
    assert files[0].path == "a.py"
    added = files[0].added_lines
    assert [ln.content for ln in added] == ["x = 1", "y = 2"]
    assert added[0].new_lineno == 1
    assert added[1].new_lineno == 2


def test_file_to_difffile_marks_all_added():
    df = file_to_difffile("f.py", "line1\nline2")
    assert len(df.added_lines) == 2
    assert df.is_new


def test_rule_engine_flags_hardcoded_secret():
    df = file_to_difffile("s.py", 'password = "hunter2secret"')
    findings = default_engine().scan([df])
    ids = {f.id for f in findings}
    assert "SEC-HARDCODED-SECRET" in ids


def test_rule_engine_flags_pan_and_cvv():
    df = file_to_difffile(
        "pay.py", "num = 4111111111111111\nx = cvv2_value"
    )
    findings = default_engine().scan([df])
    ids = {f.id for f in findings}
    assert "PCI-PAN-LITERAL" in ids
    assert "PCI-CVV-HANDLING" in ids


def test_rule_engine_dimension_filter():
    engine = default_engine().for_dimension(Dimension.SECURITY)
    assert all(r.dimension == Dimension.SECURITY for r in engine.rules)


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.HIGH >= Severity.HIGH
