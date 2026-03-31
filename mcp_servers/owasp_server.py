"""
OWASP Patterns MCP Server — regex and heuristic-based pattern matching
for common vulnerabilities from the OWASP Top 10.

This is a fast, deterministic first pass. No LLM, no API calls — just
pattern matching against known-bad code patterns. The scanner agents
use these results as a starting point for deeper LLM-based analysis.

Each pattern maps to a CWE ID and OWASP Top 10 category so findings
slot directly into the shared Finding schema.

Transport: stdio
"""

import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("owasp-patterns")


# ---------------------------------------------------------------------------
# Pattern definitions
#
# Each pattern has:
#   - id: short identifier
#   - cwe_id: the CWE it maps to
#   - title: human-readable name
#   - owasp: which OWASP Top 10 (2021) category
#   - severity: default severity if matched
#   - languages: which file extensions to check (None = all)
#   - pattern: compiled regex
#   - description: why this is dangerous
# ---------------------------------------------------------------------------

PATTERNS = [
    # --- A03:2021 Injection ---
    {
        "id": "sql-injection-format",
        "cwe_id": "CWE-89",
        "title": "Potential SQL Injection (string formatting)",
        "owasp": "A03:2021 Injection",
        "severity": "Critical",
        "languages": {".py", ".rb", ".php", ".java", ".js", ".ts"},
        "pattern": re.compile(
            r"""(?:execute|query|cursor\.execute|\.raw|rawQuery)\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\+|['\"].*\.format)""",
            re.IGNORECASE,
        ),
        "description": "SQL query built with string formatting or concatenation. User input can alter the query structure.",
    },
    {
        "id": "sql-injection-concat",
        "cwe_id": "CWE-89",
        "title": "Potential SQL Injection (concatenation)",
        "owasp": "A03:2021 Injection",
        "severity": "Critical",
        "languages": {".py", ".rb", ".php", ".java", ".js", ".ts"},
        "pattern": re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?\+\s*(?:req\.|request\.|params\.|input|user)""",
            re.IGNORECASE,
        ),
        "description": "SQL statement concatenated with user-supplied input.",
    },
    {
        "id": "command-injection",
        "cwe_id": "CWE-78",
        "title": "Potential OS Command Injection",
        "owasp": "A03:2021 Injection",
        "severity": "Critical",
        "languages": {".py", ".rb", ".php", ".js", ".ts"},
        "pattern": re.compile(
            r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen|exec\(|child_process\.exec)\s*\(\s*(?:f['\"]|['\"].*\+|['\"].*%|['\"].*\.format|.*\+\s*(?:req|request|input|user|params))""",
            re.IGNORECASE,
        ),
        "description": "OS command built with user-supplied input. Attacker can inject arbitrary commands.",
    },
    {
        "id": "xss-innerhtml",
        "cwe_id": "CWE-79",
        "title": "Potential Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 Injection",
        "severity": "High",
        "languages": {".js", ".ts", ".jsx", ".tsx", ".html", ".php"},
        "pattern": re.compile(
            r"""(?:innerHTML|outerHTML|document\.write|\.html\()\s*[=\(]\s*.*(?:req\.|request\.|params\.|input|user|\$\{)""",
            re.IGNORECASE,
        ),
        "description": "User input inserted into DOM without sanitization. Enables script injection.",
    },
    # --- A02:2021 Cryptographic Failures ---
    {
        "id": "hardcoded-secret",
        "cwe_id": "CWE-798",
        "title": "Hardcoded Credentials or Secret",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "High",
        "languages": None,  # check all files
        "pattern": re.compile(
            r"""(?:password|passwd|secret|api_key|apikey|api_secret|access_token|private_key|auth_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]""",
            re.IGNORECASE,
        ),
        "description": "Secret or credential appears to be hardcoded. Should use environment variables or a secrets manager.",
    },
    {
        "id": "weak-hash",
        "cwe_id": "CWE-328",
        "title": "Weak Hashing Algorithm",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "Medium",
        "languages": {".py", ".rb", ".php", ".java", ".js", ".ts", ".go"},
        "pattern": re.compile(
            r"""(?:md5|sha1|MD5|SHA1)\s*[\(.]""",
        ),
        "description": "MD5 or SHA1 used for hashing. These are cryptographically broken — use SHA-256+ or bcrypt for passwords.",
    },
    # --- A01:2021 Broken Access Control ---
    {
        "id": "cors-wildcard",
        "cwe_id": "CWE-942",
        "title": "Permissive CORS Policy",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "Medium",
        "languages": None,
        "pattern": re.compile(
            r"""(?:Access-Control-Allow-Origin|allow_origins|cors_origins|allowedOrigins)\s*[=:]\s*['\"\[]\s*\*""",
            re.IGNORECASE,
        ),
        "description": "CORS set to allow all origins (*). Any website can make authenticated requests to this API.",
    },
    {
        "id": "debug-enabled",
        "cwe_id": "CWE-489",
        "title": "Debug Mode Enabled",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "Medium",
        "languages": {".py", ".js", ".ts", ".rb", ".yml", ".yaml", ".json"},
        "pattern": re.compile(
            r"""(?:DEBUG\s*=\s*True|debug\s*[=:]\s*true|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)""",
        ),
        "description": "Debug mode left on. Exposes stack traces, internal state, and often enables code execution.",
    },
    # --- A07:2021 Identification and Authentication Failures ---
    {
        "id": "no-verify-ssl",
        "cwe_id": "CWE-295",
        "title": "SSL/TLS Verification Disabled",
        "owasp": "A07:2021 Auth Failures",
        "severity": "High",
        "languages": {".py", ".rb", ".js", ".ts", ".java", ".go"},
        "pattern": re.compile(
            r"""(?:verify\s*=\s*False|rejectUnauthorized\s*[=:]\s*false|InsecureSkipVerify\s*[=:]\s*true|VERIFY_SSL\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"])""",
            re.IGNORECASE,
        ),
        "description": "TLS certificate verification is disabled. Connections are vulnerable to man-in-the-middle attacks.",
    },
    # --- A08:2021 Software and Data Integrity Failures ---
    {
        "id": "unsafe-deserialization",
        "cwe_id": "CWE-502",
        "title": "Unsafe Deserialization",
        "owasp": "A08:2021 Integrity Failures",
        "severity": "Critical",
        "languages": {".py", ".rb", ".java", ".php"},
        "pattern": re.compile(
            r"""(?:pickle\.loads|yaml\.load\s*\((?!.*Loader=SafeLoader)|Marshal\.load|unserialize\s*\(|ObjectInputStream)""",
        ),
        "description": "Deserializing untrusted data can lead to remote code execution.",
    },
    {
        "id": "eval-usage",
        "cwe_id": "CWE-95",
        "title": "Use of eval() or Similar",
        "owasp": "A03:2021 Injection",
        "severity": "High",
        "languages": {".py", ".js", ".ts", ".rb", ".php"},
        "pattern": re.compile(
            r"""(?:^|\s)(?:eval|exec)\s*\(""",
        ),
        "description": "eval/exec executes arbitrary code. If input is user-controlled, this is remote code execution.",
    },
    # --- A09:2021 Security Logging and Monitoring Failures ---
    {
        "id": "sensitive-logging",
        "cwe_id": "CWE-532",
        "title": "Sensitive Data in Log Output",
        "owasp": "A09:2021 Logging Failures",
        "severity": "Medium",
        "languages": None,
        "pattern": re.compile(
            r"""(?:log|logger|console\.log|print)\s*\(.*(?:password|token|secret|api_key|credit_card|ssn)""",
            re.IGNORECASE,
        ),
        "description": "Sensitive data (passwords, tokens, etc.) written to logs. Logs are often stored insecurely.",
    },
    # --- A06:2021 Vulnerable and Outdated Components ---
    {
        "id": "pinned-http",
        "cwe_id": "CWE-319",
        "title": "Cleartext HTTP URL",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "Low",
        "languages": None,
        "pattern": re.compile(
            r"""['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[\w.-]+""",
        ),
        "description": "Non-localhost HTTP URL found. Data transmitted in cleartext is vulnerable to interception.",
    },
]


def _get_extension(file_path: str) -> str:
    """Extract the file extension from a path."""
    dot = file_path.rfind(".")
    return file_path[dot:].lower() if dot != -1 else ""


@mcp.tool()
def scan_code(file_path: str, content: str) -> list[dict]:
    """
    Scan source code for OWASP Top 10 vulnerability patterns.

    Args:
        file_path: The file path (used to determine language and filter patterns).
        content: The full source code to scan.

    Returns:
        List of matches, each containing:
        - pattern_id: which pattern matched
        - cwe_id: e.g. "CWE-89"
        - title: human-readable vulnerability name
        - owasp_category: which OWASP Top 10 category
        - severity: Critical | High | Medium | Low
        - line_number: where the match was found
        - matched_line: the actual line of code
        - description: why this is dangerous
    """
    ext = _get_extension(file_path)
    lines = content.splitlines()
    matches = []

    for pattern_def in PATTERNS:
        # Skip patterns that don't apply to this file type
        if pattern_def["languages"] is not None and ext not in pattern_def["languages"]:
            continue

        for line_num, line in enumerate(lines, start=1):
            if pattern_def["pattern"].search(line):
                matches.append({
                    "pattern_id": pattern_def["id"],
                    "cwe_id": pattern_def["cwe_id"],
                    "title": pattern_def["title"],
                    "owasp_category": pattern_def["owasp"],
                    "severity": pattern_def["severity"],
                    "line_number": line_num,
                    "matched_line": line.strip(),
                    "description": pattern_def["description"],
                })

    return matches


@mcp.tool()
def list_patterns() -> list[dict]:
    """
    List all available OWASP vulnerability patterns this server can detect.

    Returns:
        List of pattern definitions with id, CWE, title, severity, and
        which languages they apply to.
    """
    return [
        {
            "pattern_id": p["id"],
            "cwe_id": p["cwe_id"],
            "title": p["title"],
            "owasp_category": p["owasp"],
            "severity": p["severity"],
            "languages": sorted(p["languages"]) if p["languages"] else ["all"],
        }
        for p in PATTERNS
    ]


if __name__ == "__main__":
    mcp.run()
