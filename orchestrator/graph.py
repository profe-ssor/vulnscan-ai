import os
import subprocess
import tempfile
import sys
import asyncio
from typing import List, Optional, Callable

from langgraph.graph import StateGraph, END

# Optional UI hook: progress_callback(step_label, detail) e.g. ("1/7", "Validating URL…")
_PROGRESS_CB: Optional[Callable[[str, str], None]] = None


def _progress(step: str, detail: str) -> None:
    line = f"[{step}] {detail}"
    print(line)
    cb = _PROGRESS_CB
    if cb:
        try:
            cb(step, detail)
        except Exception:
            pass

# Allow direct execution: `python orchestrator/graph.py`
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.state import GraphState
from orchestrator.guardrails import input_guardrails, output_guardrails
from shared.schemas import Finding

# Keep cloned repositories inside this project workspace.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLLECTED_REPOS_DIR = os.path.join(PROJECT_ROOT, "collected_repos")


# ─────────────────────────────────────────────
# SEVERITY ORDER (for ranking)
# ─────────────────────────────────────────────

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3
}


# ─────────────────────────────────────────────
# NODE FUNCTIONS
# Each function = one step in the workflow.
# Each receives the current state and returns updated fields.
# ─────────────────────────────────────────────

def validate_input(state: GraphState) -> GraphState:
    """
    Step 1: Run input guardrails on the repo URL.
    If it fails, set status to 'failed' and stop.
    """
    _progress("1/7 · Input guardrails", f"Checking URL: {state['repo_url']}")

    is_safe, error = input_guardrails(state["repo_url"])

    if not is_safe:
        _progress("1/7 · Input guardrails", f"Blocked: {error}")
        return {**state, "status": "failed"}

    return {**state, "status": "running"}


def clone_repo(state: GraphState) -> GraphState:
    """
    Step 2: Clone the GitHub repo into a temporary folder.
    We use a temp directory so it gets cleaned up automatically.
    """
    if state["status"] == "failed":
        return state   # skip if already failed

    _progress("2/7 · Clone", f"Cloning `{state['repo_url']}` …")

    # Create a clone directory inside this project workspace.
    os.makedirs(COLLECTED_REPOS_DIR, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix="vulnscan_", dir=COLLECTED_REPOS_DIR)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", state["repo_url"], tmp_dir],
            check=True,
            capture_output=True
        )
        _progress("2/7 · Clone", f"Done — `{tmp_dir}`")
        return {**state, "repo_path": tmp_dir}

    except subprocess.CalledProcessError as e:
        _progress("2/7 · Clone", f"Failed: {e.stderr.decode()[:200]}")
        return {**state, "status": "failed"}


def detect_language(state: GraphState) -> GraphState:
    """
    Step 3: Look at file extensions to figure out which languages are used.
    This helps agents know what patterns to look for.

    e.g. .py files → Python, .js files → JavaScript
    """
    if state["status"] == "failed":
        return state

    _progress("3/7 · Languages", "Scanning file extensions …")

    # Map file extensions to language names
    extension_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
        ".go": "go",
        ".cs": "csharp",
    }

    languages_found = set()
    all_files = []

    # Walk every file in the cloned repo
    for root, dirs, files in os.walk(state["repo_path"]):
        # Skip hidden folders like .git
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            full_path = os.path.join(root, filename)
            all_files.append(full_path)

            # Check extension
            _, ext = os.path.splitext(filename)
            if ext in extension_map:
                languages_found.add(extension_map[ext])

    _progress(
        "3/7 · Languages",
        f"Found: {', '.join(sorted(languages_found)) or '—'} · {len(all_files)} files",
    )

    return {
        **state,
        "languages": list(languages_found),
        "files": all_files
    }


def run_scan_agents(state: GraphState) -> GraphState:
    """
    Step 4: Call Person B's 3 scanner agents.

    In the real version these run in PARALLEL using asyncio.
    For now they run one by one (you can upgrade later).

    Person B will fill in the actual agent logic.
    We just call their functions here.
    """
    if state["status"] == "failed":
        return state

    _progress(
        "4/7 · Scanners",
        "Running static analysis, dependency audit, and config/secrets (LLM) …",
    )

    all_findings: List[Finding] = []

    try:
        from agents import CodeAnalysisAgent, DependencyAuditAgent, SecretsAgent
        from rag.retrieve import DynamicSecurityKnowledgeBase

        kb = DynamicSecurityKnowledgeBase()
        sast_agent = CodeAnalysisAgent(kb=kb)
        dep_agent = DependencyAuditAgent(kb=kb)
        secrets_agent = SecretsAgent(kb=kb)

        async def _run_all():
            return await asyncio.gather(
                sast_agent.scan_node(state["repo_path"]),
                dep_agent.scan_node(state["repo_path"]),
                secrets_agent.scan_node(state["repo_path"]),
                return_exceptions=True,
            )

        results = asyncio.run(_run_all())

        labels = ["Static analysis", "Dependency audit", "Config/secrets"]
        for label, result in zip(labels, results):
            if isinstance(result, Exception):
                _progress("4/7 · Scanners", f"{label}: skipped ({result})")
                continue
            all_findings.extend(result)
            _progress("4/7 · Scanners", f"{label}: {len(result)} raw finding(s)")
    except Exception as e:
        _progress("4/7 · Scanners", f"Agents unavailable: {e}")

    return {**state, "findings": all_findings}


def deduplicate_findings(state: GraphState) -> GraphState:
    """
    Step 5: Remove duplicate findings.

    Two findings are duplicates if they point to the same
    file + line + CWE ID combination.
    """
    if state["status"] == "failed":
        return state

    _progress("5/7 · Dedupe", f"Merging duplicates from {len(state['findings'])} findings …")

    seen = set()
    unique_findings = []

    for finding in state["findings"]:
        # Create a unique key for this finding
        key = (finding.file_path, finding.line_number, finding.cwe_id)

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    removed = len(state["findings"]) - len(unique_findings)
    _progress("5/7 · Dedupe", f"Removed {removed} duplicate(s); {len(unique_findings)} remain")

    return {**state, "findings": unique_findings}


def rank_findings(state: GraphState) -> GraphState:
    """
    Step 6: Sort findings by severity so Critical issues appear first.
    Order: Critical → High → Medium → Low
    """
    if state["status"] == "failed":
        return state

    _progress("6/7 · Rank", "Sorting by severity (Critical → Low) …")

    ranked = sorted(
        state["findings"],
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    return {**state, "findings": ranked}


def validate_output(state: GraphState) -> GraphState:
    """
    Step 7: Run output guardrails — validate CWEs, redact secrets.
    """
    if state["status"] == "failed":
        return state

    _progress("7/7 · Output guardrails", "Validating CWE/severity and redacting secrets …")

    clean_findings = output_guardrails(state["findings"])

    _progress("7/7 · Output guardrails", f"Complete — {len(clean_findings)} finding(s) kept")

    return {
        **state,
        "findings": clean_findings,
        "status": "complete"
    }


# ─────────────────────────────────────────────
# BUILD THE GRAPH
# Wire all the nodes together in order
# ─────────────────────────────────────────────

def build_graph():
    """
    Assemble the LangGraph workflow.
    Think of this like drawing arrows between steps on a whiteboard.
    """
    graph = StateGraph(GraphState)

    # Add each step as a node
    graph.add_node("validate_input", validate_input)
    graph.add_node("clone_repo", clone_repo)
    graph.add_node("detect_language", detect_language)
    graph.add_node("run_scan_agents", run_scan_agents)
    graph.add_node("deduplicate_findings", deduplicate_findings)
    graph.add_node("rank_findings", rank_findings)
    graph.add_node("validate_output", validate_output)

    # Connect them in order (the conveyor belt)
    graph.set_entry_point("validate_input")
    graph.add_edge("validate_input", "clone_repo")
    graph.add_edge("clone_repo", "detect_language")
    graph.add_edge("detect_language", "run_scan_agents")
    graph.add_edge("run_scan_agents", "deduplicate_findings")
    graph.add_edge("deduplicate_findings", "rank_findings")
    graph.add_edge("rank_findings", "validate_output")
    graph.add_edge("validate_output", END)

    return graph.compile()


# ─────────────────────────────────────────────
# ENTRY POINT
# This is what everyone calls to run a scan
# ─────────────────────────────────────────────

def run_scan(
    repo_url: str,
    progress_callback: Optional[Callable[[str, str], None]] = None,
) -> GraphState:
    """
    Main function. Give it a GitHub URL, get back a full report.

    Optional progress_callback(step_label, detail) runs from the worker thread
    (e.g. push to an asyncio.Queue via run_coroutine_threadsafe for Chainlit).

    Usage:
        from orchestrator.graph import run_scan
        result = run_scan("https://github.com/owner/repo")
        print(result["findings"])
    """
    global _PROGRESS_CB
    _PROGRESS_CB = progress_callback
    try:
        app = build_graph()

        initial_state: GraphState = {
            "repo_url": repo_url,
            "repo_path": "",
            "languages": [],
            "files": [],
            "findings": [],
            "status": "pending",
        }

        result = app.invoke(initial_state)
        return result
    finally:
        _PROGRESS_CB = None


# ─────────────────────────────────────────────
# QUICK TEST (run this file directly to test)
# python orchestrator/graph.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    result = run_scan("https://github.com/torvalds/linux")
    print(f"\nStatus: {result['status']}")
    print(f"Languages: {result['languages']}")
    print(f"Findings: {len(result['findings'])}")