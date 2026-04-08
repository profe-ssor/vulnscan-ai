"""
Person A — Guardrails.

Two jobs:
  1. INPUT guardrails  — check the request BEFORE we do any scanning
  2. OUTPUT guardrails — check the results AFTER scanning is done
"""

import re
from urllib.parse import urlparse
from shared.schemas import Finding
from typing import List, Tuple


# ─────────────────────────────────────────────
# INPUT GUARDRAILS
# ─────────────────────────────────────────────

def validate_github_url(url: str) -> Tuple[bool, str]:
    """
    Check that the URL is a real GitHub repo link.
    Returns (is_valid, error_message)

    Example valid:   https://github.com/torvalds/linux
    Example invalid: https://evil.com/hack
    """
    try:
        parsed = urlparse(url)

        # Must be github.com
        if parsed.netloc != "github.com":
            return False, "URL must be a GitHub repository (github.com)"

        # Must have at least /owner/repo in the path
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            return False, "URL must point to a repo e.g. github.com/owner/repo"

        return True, ""

    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


def check_prompt_injection(url: str) -> Tuple[bool, str]:
    """
    Prompt injection = someone hides instructions inside the URL
    to try to trick the AI agents.

    Example attack: https://github.com/x/y?ignore+previous+instructions

    We block anything that looks like it's trying to hijack the AI.
    """
    injection_patterns = [
        r"ignore.{0,20}previous.{0,20}instructions",
        r"you are now",
        r"forget.{0,20}everything",
        r"act as",
        r"jailbreak",
        r"<\s*script",       # HTML/JS injection
        r"system\s*prompt",
    ]

    url_lower = url.lower()
    for pattern in injection_patterns:
        if re.search(pattern, url_lower):
            return True, f"Potential prompt injection detected in URL"

    return False, ""


def input_guardrails(repo_url: str) -> Tuple[bool, str]:
    """
    Master input check — call this before scanning starts.
    Returns (is_safe, error_message)

    If is_safe is False, stop everything and return the error to the user.
    """

    # 1. Validate URL format
    valid, error = validate_github_url(repo_url)
    if not valid:
        return False, error

    # 2. Check for prompt injection
    injected, error = check_prompt_injection(repo_url)
    if injected:
        return False, error

    # 3. Block obviously bad patterns in the URL
    blocked_keywords = ["malware", "exploit", "ransomware", "rootkit"]
    for keyword in blocked_keywords:
        if keyword in repo_url.lower():
            return False, f"Blocked: URL contains flagged keyword '{keyword}'"

    return True, ""  # All good!


# ─────────────────────────────────────────────
# OUTPUT GUARDRAILS
# ─────────────────────────────────────────────

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

_CWE_PATTERN = re.compile(r"^CWE-\d{1,5}$", re.IGNORECASE)

_SEVERITY_ALIASES = {
    "critical": "Critical",
    "crit": "Critical",
    "high": "High",
    "medium": "Medium",
    "med": "Medium",
    "low": "Low",
    "info": "Low",
    "informational": "Low",
}


def normalize_severity(raw: str) -> str:
    """Map LLM output (e.g. HIGH, high) to guardrail canonical values."""
    if raw is None:
        return "Low"
    if not isinstance(raw, str):
        raw = str(raw)
    s = raw.strip()
    if not s:
        return "Low"
    upper = s.upper()
    upper_map = {
        "CRITICAL": "Critical",
        "CRIT": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "MED": "Medium",
        "LOW": "Low",
        "INFO": "Low",
        "INFORMATIONAL": "Low",
        "NONE": "Low",
    }
    if upper in upper_map:
        return upper_map[upper]
    key = s.lower()
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key]
    t = s.title()
    if t in VALID_SEVERITIES:
        return t
    return "Low"


def normalize_cwe_id(raw: str) -> str:
    """Normalize to CWE-123 form; accept any standard CWE number from the model."""
    if not raw or not str(raw).strip():
        return "CWE-200"
    s = str(raw).strip().upper()
    if s.startswith("CWE-"):
        m = re.match(r"^CWE-(\d{1,5})$", s)
        if m:
            return f"CWE-{int(m.group(1))}"  # CWE-020 -> CWE-20
    m = re.search(r"CWE-(\d{1,5})", s, re.I)
    if m:
        return f"CWE-{int(m.group(1))}"
    return "CWE-200"

# Regex to detect secrets that might have leaked into the report
SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{32,}",          # OpenAI API key
    r"ghp_[a-zA-Z0-9]{36}",           # GitHub token
    r"AKIA[A-Z0-9]{16}",              # AWS access key
    r"-----BEGIN RSA PRIVATE KEY-----", # Private key
]


def redact_secrets(text: str) -> str:
    """
    Scan any text field for leaked secrets and replace with [REDACTED].
    We never want real API keys showing up in our vulnerability report!
    """
    for pattern in SECRET_PATTERNS:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def validate_finding(finding: Finding) -> Tuple[bool, str]:
    """
    Check one Finding object is valid before it goes into the report.
    """
    finding.cwe_id = normalize_cwe_id(finding.cwe_id)
    if not _CWE_PATTERN.match(finding.cwe_id):
        return False, f"Malformed CWE ID: {finding.cwe_id}"

    finding.severity = normalize_severity(finding.severity)
    if finding.severity not in VALID_SEVERITIES:
        return False, f"Invalid severity: {finding.severity}"

    # Confidence must be between 0 and 1
    if not (0.0 <= finding.confidence <= 1.0):
        return False, f"Confidence must be 0.0-1.0, got: {finding.confidence}"

    # Must have explanation and fix
    if not finding.explanation.strip():
        return False, "Finding has no explanation"

    if not finding.suggested_fix.strip():
        return False, "Finding has no suggested fix"

    return True, ""


def output_guardrails(findings: List[Finding]) -> List[Finding]:
    """
    Master output check — call this after all agents finish.
    Validates each finding and redacts any leaked secrets.
    Returns only the clean, valid findings.
    """
    clean_findings = []

    for finding in findings:
        # Redact secrets from text fields
        finding.explanation = redact_secrets(finding.explanation)
        finding.suggested_fix = redact_secrets(finding.suggested_fix)

        # Validate the finding
        valid, error = validate_finding(finding)
        if valid:
            clean_findings.append(finding)
        else:
            print(f"[GUARDRAIL] Dropped invalid finding: {error}")

    return clean_findings