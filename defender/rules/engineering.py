"""Engineering rules — quality, performance, architecture, and vulnerability.

The non-security dimensions that still gate delivery: maintainability smells,
performance anti-patterns, architectural erosion, and known-vulnerable
dependency usage.
"""

from __future__ import annotations

from defender.core.models import Dimension, Severity
from defender.rules.base import StaticRule

Q = Dimension.QUALITY
P = Dimension.PERFORMANCE
A = Dimension.ARCHITECTURE
V = Dimension.VULNERABILITY

ENGINEERING_RULES: list[StaticRule] = [
    # --- Quality ---
    StaticRule(
        id="QUAL-BARE-EXCEPT",
        dimension=Q,
        severity=Severity.MEDIUM,
        title="Bare except swallows errors",
        message="A bare `except:` hides failures and complicates incident response.",
        pattern=r"^\s*except\s*:",
        remediation="Catch specific exceptions and log/handle them explicitly.",
        file_suffixes=(".py",),
    ),
    StaticRule(
        id="QUAL-TODO-FIXME",
        dimension=Q,
        severity=Severity.LOW,
        title="Unresolved TODO/FIXME",
        message="A TODO/FIXME/HACK marker was introduced in the change set.",
        pattern=r"\b(?:TODO|FIXME|HACK|XXX)\b",
        remediation="Resolve or file a tracked ticket before merging.",
    ),
    StaticRule(
        id="QUAL-PRINT-DEBUG",
        dimension=Q,
        severity=Severity.LOW,
        title="Leftover debug print",
        message="A raw print/console.log looks like leftover debugging.",
        pattern=r"^\s*(?:print\s*\(|console\.log\s*\()",
        remediation="Use a structured logger with appropriate levels.",
    ),
    StaticRule(
        id="QUAL-MAGIC-SLEEP",
        dimension=Q,
        severity=Severity.LOW,
        title="Magic sleep as synchronization",
        message="Fixed sleeps as synchronization are flaky and fragile.",
        pattern=r"(?:time\.sleep\(\s*\d|Thread\.sleep\(\s*\d)",
        remediation="Use proper waits/events instead of arbitrary sleeps.",
    ),
    # --- Performance ---
    StaticRule(
        id="PERF-SELECT-STAR",
        dimension=P,
        severity=Severity.MEDIUM,
        title="SELECT * query",
        message="SELECT * fetches unnecessary columns and defeats indexing.",
        pattern=r"select\s+\*\s+from",
        remediation="Select only the columns you need.",
    ),
    StaticRule(
        id="PERF-BLOCKING-IO",
        dimension=P,
        severity=Severity.MEDIUM,
        title="Blocking sleep in request path",
        message="Blocking sleep in a request/async path harms throughput.",
        pattern=r"time\.sleep\s*\(",
        remediation="Use async sleep or move work off the hot path.",
        file_suffixes=(".py",),
    ),
    StaticRule(
        id="PERF-QUERY-IN-LOOP",
        dimension=P,
        severity=Severity.HIGH,
        title="Possible N+1 query in loop",
        message="A DB query inside a loop suggests an N+1 access pattern.",
        pattern=r"for\s+\w+\s+in\s+.*:\s*.*(?:\.execute\(|\.query\(|\.get\()",
        remediation="Batch/join queries or prefetch related data.",
    ),
    # --- Architecture ---
    StaticRule(
        id="ARCH-GLOBAL-STATE",
        dimension=A,
        severity=Severity.MEDIUM,
        title="Global mutable state",
        message="Global mutable state hurts testability and thread-safety.",
        pattern=r"^\s*global\s+\w+",
        remediation="Pass dependencies explicitly; prefer injection.",
        file_suffixes=(".py",),
    ),
    StaticRule(
        id="ARCH-LAYER-VIOLATION",
        dimension=A,
        severity=Severity.MEDIUM,
        title="Layering violation (SQL in controller/UI)",
        message="Raw SQL appears in a controller/handler/view layer.",
        pattern=r"(?:controller|handler|view|route).*(?:SELECT|INSERT|UPDATE|DELETE)\s",
        remediation="Move data access into a repository/service layer.",
    ),
    StaticRule(
        id="ARCH-WILDCARD-IMPORT",
        dimension=A,
        severity=Severity.LOW,
        title="Wildcard import",
        message="`from x import *` pollutes namespace and obscures dependencies.",
        pattern=r"^\s*from\s+[\w.]+\s+import\s+\*",
        remediation="Import names explicitly.",
        file_suffixes=(".py",),
    ),
    # --- Vulnerability (dependency / known-bad usage) ---
    StaticRule(
        id="VULN-REQUESTS-NO-TIMEOUT",
        dimension=V,
        severity=Severity.MEDIUM,
        title="Outbound HTTP call without timeout",
        message="requests call without a timeout can hang worker threads (DoS).",
        pattern=r"requests\.(?:get|post|put|delete|patch)\((?![^)]*timeout)",
        remediation="Always set a timeout on outbound calls.",
        frameworks=["CWE-400"],
        file_suffixes=(".py",),
    ),
    StaticRule(
        id="VULN-INSECURE-RANDOM",
        dimension=V,
        severity=Severity.MEDIUM,
        title="Insecure randomness for security value",
        message="random module is not cryptographically secure.",
        pattern=r"\brandom\.(?:random|randint|choice|randrange)\s*\(",
        remediation="Use secrets/os.urandom for tokens, keys, and nonces.",
        frameworks=["CWE-330"],
        file_suffixes=(".py",),
    ),
    StaticRule(
        id="VULN-HTTP-URL",
        dimension=V,
        severity=Severity.MEDIUM,
        title="Cleartext HTTP endpoint",
        message="An http:// URL transmits data without encryption.",
        pattern=r"http://(?!localhost|127\.0\.0\.1)",
        remediation="Use https:// for all external communication.",
        frameworks=["CWE-319", "PCI-DSS 4.1"],
    ),
]
