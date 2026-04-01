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
