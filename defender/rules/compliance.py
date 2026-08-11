"""Compliance rules — PCI-DSS, SOC 2, GDPR/PII, and HIPAA.

These are the banking-critical frameworks. They detect handling of cardholder
data (PAN), PII, insecure logging of sensitive data, and audit-trail gaps.
"""

from __future__ import annotations

from defender.core.models import Dimension, Severity
from defender.rules.base import StaticRule

CMP = Dimension.COMPLIANCE

COMPLIANCE_RULES: list[StaticRule] = [
    # --- PCI-DSS: cardholder data ---
    StaticRule(
        id="PCI-PAN-LITERAL",
        dimension=CMP,
        severity=Severity.CRITICAL,
        title="Primary Account Number (PAN) literal in code",
        message="A 13-19 digit sequence resembling a payment card number found.",
        pattern=r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b",
        remediation="Never store PAN in code/tests. Tokenize per PCI-DSS.",
        frameworks=["PCI-DSS 3.2", "PCI-DSS 3.4"],
    ),
    StaticRule(
        id="PCI-CVV-HANDLING",
        dimension=CMP,
        severity=Severity.CRITICAL,
        title="CVV / sensitive authentication data handling",
        message="Code references CVV/CVC/track data, which must never be stored.",
        pattern=r"\b(?:cvv2?|cvc2?|card_verification|track2?_data|magstripe)",
        remediation="Sensitive auth data must never be persisted (PCI-DSS 3.2).",
        frameworks=["PCI-DSS 3.2.1"],
    ),
    StaticRule(
        id="PCI-PAN-VARIABLE",
        dimension=CMP,
        severity=Severity.HIGH,
        title="Cardholder data variable in scope",
        message="Variable names suggest cardholder data flows through this code.",
        pattern=r"\b(?:card_number|cardnumber|pan|primary_account_number|full_card)\b",
        remediation="Ensure PAN is encrypted at rest/in transit and access-logged.",
        frameworks=["PCI-DSS 3.4", "PCI-DSS 4.1"],
    ),
    # --- GDPR / PII ---
    StaticRule(
        id="GDPR-PII-LOGGING",
        dimension=CMP,
        severity=Severity.HIGH,
        title="Potential PII written to logs",
        message="Logging call appears to include PII (email, ssn, dob, name).",
        pattern=r"(?:log(?:ger)?\.\w+|print|console\.log)\s*\([^)]*\b(?:ssn|social_security|email|dob|date_of_birth|passport|national_id|phone_number)\b",
        remediation="Redact or hash PII before logging (GDPR data minimization).",
        frameworks=["GDPR Art.5", "GDPR Art.32", "SOC 2 CC6.1"],
    ),
    StaticRule(
        id="GDPR-SSN-LITERAL",
        dimension=CMP,
        severity=Severity.HIGH,
        title="Social Security Number pattern",
        message="A value matching an SSN pattern was found in the change set.",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        remediation="Never embed real PII; use synthetic test data.",
        frameworks=["GDPR Art.9", "HIPAA 164.514"],
    ),
    # --- SOC 2 / audit trail ---
    StaticRule(
        id="SOC2-AUTH-BYPASS",
        dimension=CMP,
        severity=Severity.HIGH,
        title="Authorization check appears disabled",
        message="A commented-out or force-true auth/permission check was found.",
        pattern=r"(?:#\s*(?:auth|permission|authorize)|is_admin\s*=\s*True|authorized\s*=\s*True\s*#)",
        remediation="Keep access controls active; log all privileged actions.",
        frameworks=["SOC 2 CC6.1", "SOC 2 CC6.3"],
    ),
    # --- HIPAA (scaffolded evenly) ---
    StaticRule(
        id="HIPAA-PHI-REFERENCE",
        dimension=CMP,
        severity=Severity.MEDIUM,
        title="Protected Health Information reference",
        message="Code references PHI fields; ensure encryption and audit controls.",
        pattern=r"\b(?:diagnosis|medical_record|patient_id|health_plan|icd10)\b",
        remediation="Encrypt PHI and maintain access audit logs (HIPAA Security Rule).",
        frameworks=["HIPAA 164.312"],
    ),
]
