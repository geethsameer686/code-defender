"""Security / SAST rules — OWASP-flavored patterns that matter for banking.

Covers hardcoded secrets, injection, weak crypto, TLS misconfig, dangerous
deserialization, and command execution. Every rule maps to an OWASP / CWE
reference so findings are audit-defensible.
"""

from __future__ import annotations

from defender.core.models import Dimension, Severity
from defender.rules.base import StaticRule

SEC = Dimension.SECURITY

SECURITY_RULES: list[StaticRule] = [
    StaticRule(
        id="SEC-HARDCODED-SECRET",
        dimension=SEC,
        severity=Severity.CRITICAL,
        title="Hardcoded secret / credential",
        message="A secret, API key, or password appears to be hardcoded in source.",
        pattern=r"(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        remediation="Load secrets from a vault or environment, never source control.",
        frameworks=["OWASP A07", "CWE-798", "PCI-DSS 8.2.1"],
    ),
    StaticRule(
        id="SEC-PRIVATE-KEY",
        dimension=SEC,
        severity=Severity.CRITICAL,
        title="Private key material committed",
        message="A PEM/private key block was found in the change set.",
        pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        remediation="Rotate the key immediately and store it in a secrets manager.",
        frameworks=["CWE-321", "PCI-DSS 3.6"],
    ),
    StaticRule(
        id="SEC-SQL-INJECTION",
        dimension=SEC,
        severity=Severity.HIGH,
        title="Possible SQL injection via string building",
        message="SQL appears to be built with string concatenation/formatting.",
        pattern=r"(?:execute|executemany|cursor\.execute|query)\s*\(\s*[f\"'].*(?:\+|%s?|\{).*(?:select|insert|update|delete|from|where)",
        remediation="Use parameterized queries / prepared statements.",
        frameworks=["OWASP A03", "CWE-89", "PCI-DSS 6.5.1"],
    ),
    StaticRule(
        id="SEC-EVAL-EXEC",
        dimension=SEC,
        severity=Severity.HIGH,
        title="Dynamic code execution",
        message="Use of eval()/exec() enables arbitrary code execution.",
        pattern=r"\b(?:eval|exec)\s*\(",
        remediation="Avoid eval/exec; use explicit parsing or safe dispatch tables.",
        frameworks=["OWASP A03", "CWE-95"],
        file_suffixes=(".py",),
    ),
    StaticRule(
        id="SEC-INSECURE-DESERIALIZE",
        dimension=SEC,
        severity=Severity.HIGH,
        title="Insecure deserialization",
        message="pickle/yaml.load on untrusted data can execute code.",
        pattern=r"(?:pickle\.loads?|yaml\.load\s*\((?!.*Loader))",
        remediation="Use yaml.safe_load / JSON; never unpickle untrusted input.",
        frameworks=["OWASP A08", "CWE-502"],
    ),
    StaticRule(
        id="SEC-TLS-DISABLED",
        dimension=SEC,
        severity=Severity.HIGH,
        title="TLS certificate verification disabled",
        message="verify=False / rejectUnauthorized:false disables TLS validation.",
        pattern=r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*0)",
        remediation="Never disable certificate verification for banking traffic.",
        frameworks=["OWASP A02", "CWE-295", "PCI-DSS 4.1"],
    ),
    StaticRule(
        id="SEC-WEAK-HASH",
        dimension=SEC,
        severity=Severity.MEDIUM,
        title="Weak cryptographic hash",
        message="MD5/SHA1 are broken for security-sensitive use.",
        pattern=r"(?:hashlib\.(?:md5|sha1)|MessageDigest\.getInstance\(\s*['\"](?:MD5|SHA-1)['\"])",
        remediation="Use SHA-256+ or bcrypt/argon2 for passwords.",
        frameworks=["OWASP A02", "CWE-327", "PCI-DSS 6.5.3"],
    ),
    StaticRule(
        id="SEC-COMMAND-INJECTION",
        dimension=SEC,
        severity=Severity.HIGH,
        title="Possible OS command injection",
        message="Shell execution with shell=True or string-built commands.",
        pattern=r"(?:os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True)",
        remediation="Pass args as a list and avoid shell=True.",
        frameworks=["OWASP A03", "CWE-78"],
    ),
    StaticRule(
        id="SEC-DEBUG-ENABLED",
        dimension=SEC,
        severity=Severity.MEDIUM,
        title="Debug mode enabled",
        message="Debug flags leak stack traces and internals in production.",
        pattern=r"(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)",
        remediation="Disable debug in any non-local environment.",
        frameworks=["OWASP A05", "CWE-489"],
    ),
]
