"""
Report Generator Agent — aggregates, deduplicates, and formats vulnerability
findings into a structured security report.

This is an OpenAI Agents SDK agent, NOT an MCP server. It sits at the end
of the pipeline:

    Scanner Agents → raw findings → Report Generator → structured report

What it does:
  1. Receives all findings from the three scanner agents
  2. Deduplicates (e.g. OWASP regex + LLM both flagged the same line)
  3. Merges related findings (same file, same vuln type, adjacent lines)
  4. Ranks by severity and confidence
  5. Produces a structured JSON report the output guardrails can validate
"""

import json
from dotenv import load_dotenv

load_dotenv()

from agents import Agent, Runner

from shared.schemas import Finding


# ---------------------------------------------------------------------------
# Deduplication and ranking logic (runs BEFORE the LLM)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings. Two findings are duplicates if they point
    to the same file + line + CWE. We keep the one with higher confidence.
    """
    seen: dict[str, Finding] = {}

    for f in findings:
        key = f"{f.file_path}:{f.line_number}:{f.cwe_id}"
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f

    return list(seen.values())


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (Critical first), then by confidence."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence),
    )


def findings_to_text(findings: list[Finding]) -> str:
    """Convert findings list to a readable text block for the LLM."""
    if not findings:
        return "No findings to report."

    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(
            f"Finding #{i}:\n"
            f"  File: {f.file_path} (line {f.line_number})\n"
            f"  CWE: {f.cwe_id}\n"
            f"  Severity: {f.severity}\n"
            f"  Title: {f.title}\n"
            f"  Explanation: {f.explanation}\n"
            f"  Suggested Fix: {f.suggested_fix}\n"
            f"  Confidence: {f.confidence:.0%}\n"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report schema (what the agent outputs)
# ---------------------------------------------------------------------------

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "object",
            "description": "High-level overview of the scan results",
            "properties": {
                "total_findings": {"type": "integer"},
                "critical": {"type": "integer"},
                "high": {"type": "integer"},
                "medium": {"type": "integer"},
                "low": {"type": "integer"},
                "top_risk": {
                    "type": "string",
                    "description": "One sentence describing the most critical risk found",
                },
            },
            "required": ["total_findings", "critical", "high", "medium", "low", "top_risk"],
        },
        "findings": {
            "type": "array",
            "description": "All deduplicated findings, sorted by severity",
            "items": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "cwe_id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                    "title": {"type": "string"},
                    "explanation": {"type": "string"},
                    "suggested_fix": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": [
                    "file_path", "line_number", "cwe_id", "severity",
                    "title", "explanation", "suggested_fix", "confidence",
                ],
            },
        },
        "recommendations": {
            "type": "array",
            "description": "Top 3-5 prioritized remediation steps",
            "items": {"type": "string"},
        },
    },
    "required": ["summary", "findings", "recommendations"],
}

# ---------------------------------------------------------------------------
# The Agent
# ---------------------------------------------------------------------------

report_agent = Agent(
    name="Report Generator",
    instructions="""You are a security report generator. You receive deduplicated
vulnerability findings from multiple scanner agents and produce a structured
security report.

Your job:
1. Review all findings and ensure they are properly categorized
2. Write clear, actionable explanations (a developer should understand what to fix)
3. Write specific suggested fixes (show code changes, not vague advice)
4. Produce a summary with severity counts and the top risk
5. Provide 3-5 prioritized remediation recommendations (fix the most dangerous things first)

Rules:
- Do NOT invent findings that aren't in the input
- Do NOT remove findings — include every one
- If two findings describe the same root cause, merge them but keep the lower line number
- Severity must be exactly: Critical, High, Medium, or Low
- CWE IDs must be in format CWE-XXX
- Confidence must be between 0.0 and 1.0
- Be specific in suggested fixes — show the safe alternative code pattern

Output the report as JSON matching the provided schema.""",
    model="gpt-4o-mini",
    output_type=None,  # we'll parse JSON from the text response
)


# ---------------------------------------------------------------------------
# Public API — called by the orchestrator
# ---------------------------------------------------------------------------

async def generate_report(findings: list[Finding], repo_url: str = "") -> dict:
    """
    Generate a structured vulnerability report from raw findings.

    Args:
        findings: Raw findings from all scanner agents.
        repo_url: The scanned repository URL (for context in the report).

    Returns:
        Structured report dict matching REPORT_SCHEMA.
    """
    # Step 1: Deduplicate and rank (deterministic, no LLM needed)
    cleaned = deduplicate_findings(findings)
    ranked = rank_findings(cleaned)

    # Step 2: Build the prompt for the LLM
    findings_text = findings_to_text(ranked)
    prompt = f"""Generate a security vulnerability report for: {repo_url or 'unknown repository'}

Here are the deduplicated findings from our scanner agents:

{findings_text}

Produce a JSON report matching this schema:
{json.dumps(REPORT_SCHEMA, indent=2)}

Return ONLY valid JSON, no markdown fences or extra text."""

    # Step 3: Run the agent
    result = await Runner.run(report_agent, input=prompt)

    # Step 4: Parse the JSON response
    raw = result.final_output
    # Strip markdown code fences if present
    if "```" in raw:
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

    report = json.loads(raw)
    return report
