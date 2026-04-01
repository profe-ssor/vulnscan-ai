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
  +--------------------+--------------------+--------------------+
  |                    |                    |                    |
  | Static Analysis    | Dependency Audit   | Config/Secrets     |
  | Agent              | Agent              | Agent              |
  |                    |                    |                    |
  +--------------------+--------------------+--------------------+
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
# vulnscan-ai

AI-assisted vulnerability scanning pipeline built with a LangGraph orchestrator and guardrails.

## Overview

`vulnscan-ai` scans a target GitHub repository through a staged workflow:

1. Validate request input (URL and prompt-injection checks)
2. Clone repository
3. Detect languages/files
4. Run scanner agents
5. Deduplicate and rank findings
6. Validate and sanitize output findings

The project is organized so contributors can extend scanner agents without changing the full orchestration flow.

## Workflow Diagram

```text
Person A - LangGraph Orchestrator.

This is the master workflow. Think of it like a conveyor belt:

  START
    ↓
  [validate_input]     <- guardrails check the URL
    ↓
  [clone_repo]         <- download the repo to a temp folder
    ↓
  [detect_language]    <- figure out Python? JS? Java?
    ↓
  [scan_agents]        <- run Person B's 3 agents in parallel
    ↓
  [collect_findings]   <- gather all results
    ↓
  [deduplicate]        <- remove duplicate findings
    ↓
  [rank_findings]      <- sort by severity
    ↓
  [validate_output]    <- guardrails check the results
    ↓
  END -> return report
```

## Project Structure

- `orchestrator/` - workflow graph, state shape, and input/output guardrails
- `shared/` - shared schemas (`Finding`, `ScanState`)
- `agents/` - security scanner agent implementations (static analysis, dependency audit, config/secrets)
- `test_guardrails.py` - quick smoke test for input guardrail behavior
- `requirements.txt` - pinned Python dependencies



## Setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Quick Start

Run the guardrails smoke test:

```bash
python test_guardrails.py
```

Run the orchestrator directly:

```bash
python orchestrator/graph.py
```

Or run as a module:

```bash
python -m orchestrator.graph
```

## How To Test Your Changes

Use this checklist before opening a PR:

1. **Environment**
   - Activate venv: `source .venv/bin/activate`
   - Confirm interpreter: `which python`
2. **Guardrails**
   - Run: `python test_guardrails.py`
   - Expect:
     - valid GitHub URL passes
     - non-GitHub URL fails
     - prompt-injection-like URL fails
3. **Orchestrator smoke run**
   - Run: `python -m orchestrator.graph`
   - Verify it starts workflow and exits cleanly for your test scenario
4. **Optional import sanity checks**
   - `python -c "from orchestrator.graph import run_scan; print('ok')"`
   - `python -c "from orchestrator.guardrails import input_guardrails; print('ok')"`

## Notes For Contributors

- Keep `Finding` schema fields backward compatible unless intentionally versioning.
- If you add a new scanner agent, integrate it in `run_scan_agents()` inside `orchestrator/graph.py`.
- Guardrails are mandatory boundaries:
  - `input_guardrails()` before clone/scan
  - `output_guardrails()` before returning final findings
- Repositories cloned during scans are stored under `collected_repos/` (gitignored).

## Troubleshooting

- **`Import "langgraph.graph" could not be resolved`**
  - Ensure IDE uses `.venv` interpreter for this workspace.
  - Reinstall dependencies: `python -m pip install -r requirements.txt`
- **`ModuleNotFoundError: No module named 'orchestrator'`**
  - Run from repo root.
  - Prefer module mode: `python -m orchestrator.graph`
- **Slow/large repo scans**
  - Start with smaller target repos while developing.
  - Consider adding/adjusting repo-size guardrails.

## Git Hygiene

Common local artifacts are ignored via `.gitignore`, including:

- `.venv/`
- `__pycache__/`
- `collected_repos/`
- local cache/log files

## License

Add your project license here (for example, MIT).
