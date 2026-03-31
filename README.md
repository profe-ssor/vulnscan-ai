# VulnScan AI

Multi-agent system that scans any GitHub repository for security vulnerabilities. Give it a repo URL, get back an actionable vulnerability report with severity ratings, CWE classifications, and suggested fixes.

Built with LangGraph, OpenAI Agents SDK, MCP (Model Context Protocol), and RAG.

## Architecture

```
GitHub Repo URL
      |
[Input Guardrails] --> validate URL, size, rate limits, prompt injection
      |
[Orchestrator Agent - LangGraph] --> clone, detect language, fan out, collect, deduplicate, rank
      |
  +---+---+---+
  |   |       |
Static  Dependency  Config/Secrets
Analysis  Audit       Agent
Agent     Agent
  |   |       |
  +---+---+---+
      |
[Report Generator Agent]
      |
[Output Guardrails] --> validate CVEs, CWE IDs, file paths, redact secrets
      |
Vulnerability Report
```

## MCP Servers

Three FastMCP servers (stdio transport) that provide tools for the scanner agents:

### GitHub Server (`mcp_servers/github_server.py`)
Handles repo access — cloning, file listing, reading source code, and language detection.
- `clone_repo` — shallow-clones a GitHub repo to a temp directory
- `list_files` — lists source/config files, skipping irrelevant files (images, node_modules, etc.)
- `read_file` — reads file contents with line numbers for scanner reference
- `detect_languages` — counts file extensions to determine repo languages

### CVE/NVD Server (`mcp_servers/cve_server.py`)
Queries the National Vulnerability Database for known vulnerabilities in packages.
- `search_cves` — search by package name + version, returns CVEs with severity scores
- `get_cve_details` — full details for a specific CVE including CWE IDs and references

### OWASP Patterns Server (`mcp_servers/owasp_server.py`)
Fast regex/heuristic pattern matching for OWASP Top 10 vulnerability patterns.
- `scan_code` — scans source code against 13 vulnerability patterns (SQLi, XSS, command injection, hardcoded secrets, weak crypto, etc.)
- `list_patterns` — lists all available detection patterns with CWE mappings

## Report Generator

OpenAI Agents SDK agent (`report/report_generator.py`) that produces the final vulnerability report.
- Deduplicates findings from multiple scanners (same file + line + CWE = one finding)
- Ranks by severity (Critical > High > Medium > Low) and confidence
- Generates structured JSON report with summary, findings, and prioritized remediation recommendations

## Setup

```bash
# Install dependencies
uv sync

# Add your OpenAI API key
cp .env.example .env
# Edit .env with your key

# Run tests
PYTHONPATH=. uv run python tests/test_github_server.py
PYTHONPATH=. uv run python tests/test_cve_server.py
PYTHONPATH=. uv run python tests/test_owasp_server.py
PYTHONPATH=. uv run python tests/test_report_generator.py
```
