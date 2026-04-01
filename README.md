# vulnscan-ai


Agents module (/agents)
This directory contains the specialized LLM scanning engines. Each agent is responsible for traversing a specific subset of files in a target directory, applying security analysis, and enriching the findings via the RAG Knowledge Base.

Exported Agents
The module exposes three agent classes via __init__.py:

CodeAnalysisAgent: Scans core application logic (.py, .js, .go, etc.) for CWEs and SANS Top 25 flaws.

DependencyAuditAgent: Scans package manifests (requirements.txt, package.json, etc.) for vulnerable or outdated libraries.

SecretsAgent: Scans configuration and IaC files (.env, .yaml, Dockerfiles) for hardcoded credentials and severe misconfigurations.

🛠️ Interface & Integration Guide
To use these agents in the Orchestrator (graph.py), follow these rules:

1. Initialization Requirements
Every agent must be initialized with an instance of the DynamicSecurityKnowledgeBase (from the rag/ module) so it can perform its own CVE enrichment.

2. The Execution Method
Every agent exposes a single public asynchronous method:

Method: await scan_node(source_path: str)

Input: The absolute path to the directory being scanned. (The agent handles its own file filtering and directory ignoring internally).

Output: List[VulnerabilityFinding] (from shared.schemas). Returns an empty list [] if no vulnerabilities are found.

Example Orchestrator Integration
from shared.schemas import VulnerabilityFinding
from rag.retrieve import DynamicSecurityKnowledgeBase
from agents import CodeAnalysisAgent, DependencyAuditAgent, SecretsAgent

async def run_scanners(target_dir: str):
    # 1. Initialize the shared Knowledge Base ONCE
    kb = DynamicSecurityKnowledgeBase()
    
    # 2. Instantiate the agents and inject the KB
    sast_agent = CodeAnalysisAgent(kb=kb)
    dep_agent = DependencyAuditAgent(kb=kb)
    secrets_agent = SecretsAgent(kb=kb)
    
    # 3. Execute the agents (can be done concurrently via asyncio.gather)
    code_findings = await sast_agent.scan_node(target_dir)
    dep_findings = await dep_agent.scan_node(target_dir)
    secret_findings = await secrets_agent.scan_node(target_dir)
    
    # 4. Aggregate findings
    return code_findings + dep_findings + secret_findings
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
