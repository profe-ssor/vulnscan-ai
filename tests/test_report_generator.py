"""
Test script for the Report Generator Agent.
Feeds it sample findings and generates a full vulnerability report.
"""

import asyncio
import json

from shared.schemas import Finding
from report.report_generator import generate_report, deduplicate_findings, rank_findings


# Simulated findings from the three scanner agents — including duplicates
SAMPLE_FINDINGS = [
    # From Static Analysis Agent
    Finding(
        file_path="app/routes/users.py",
        line_number=42,
        cwe_id="CWE-89",
        severity="Critical",
        title="SQL Injection in user lookup",
        explanation="User ID from request is interpolated directly into SQL query using f-string",
        suggested_fix="Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        confidence=0.95,
    ),
    # From OWASP Patterns Server (same vuln, lower confidence — should be deduped)
    Finding(
        file_path="app/routes/users.py",
        line_number=42,
        cwe_id="CWE-89",
        severity="Critical",
        title="Potential SQL Injection (string formatting)",
        explanation="SQL query built with string formatting",
        suggested_fix="Use parameterized queries",
        confidence=0.80,
    ),
    # From Config/Secrets Agent
    Finding(
        file_path="config/settings.py",
        line_number=15,
        cwe_id="CWE-798",
        severity="High",
        title="Hardcoded database password",
        explanation="Database password is hardcoded as a string literal instead of loaded from environment",
        suggested_fix="Use os.environ.get('DATABASE_PASSWORD') or a secrets manager",
        confidence=0.99,
    ),
    # From Dependency Audit Agent
    Finding(
        file_path="requirements.txt",
        line_number=3,
        cwe_id="CWE-502",
        severity="High",
        title="Vulnerable dependency: requests 2.25.0",
        explanation="requests 2.25.0 has CVE-2023-32681 — CRLF injection in redirect handling",
        suggested_fix="Upgrade to requests >= 2.31.0",
        confidence=0.90,
    ),
    # From Static Analysis Agent
    Finding(
        file_path="app/utils/crypto.py",
        line_number=8,
        cwe_id="CWE-328",
        severity="Medium",
        title="MD5 used for password hashing",
        explanation="MD5 is cryptographically broken and unsuitable for password hashing",
        suggested_fix="Use bcrypt: import bcrypt; bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        confidence=0.92,
    ),
    # From OWASP Patterns Server
    Finding(
        file_path="app/server.py",
        line_number=1,
        cwe_id="CWE-489",
        severity="Medium",
        title="Debug mode enabled in production config",
        explanation="DEBUG = True is set in what appears to be a production configuration file",
        suggested_fix="Set DEBUG = False and use environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
        confidence=0.85,
    ),
]


async def main():
    # 1. Show deduplication
    print("=" * 60)
    print(f"RAW FINDINGS: {len(SAMPLE_FINDINGS)}")
    deduped = deduplicate_findings(SAMPLE_FINDINGS)
    print(f"AFTER DEDUP:  {len(deduped)}")
    ranked = rank_findings(deduped)
    print(f"SEVERITY ORDER: {[f'{f.severity} ({f.cwe_id})' for f in ranked]}")
    print()

    # 2. Generate full report via the LLM agent
    print("=" * 60)
    print("GENERATING REPORT (calling OpenAI)...")
    print("=" * 60)
    report = await generate_report(
        findings=SAMPLE_FINDINGS,
        repo_url="https://github.com/example/vulnerable-app",
    )

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
