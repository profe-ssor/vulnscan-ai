import os
import subprocess
import tempfile
import sys
from typing import List
from langgraph.graph import StateGraph, END

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
    print(f"[1/7] Validating input: {state['repo_url']}")

    is_safe, error = input_guardrails(state["repo_url"])

    if not is_safe:
        print(f"[GUARDRAIL] Input blocked: {error}")
        return {**state, "status": "failed"}

    return {**state, "status": "running"}


def clone_repo(state: GraphState) -> GraphState:
    """
    Step 2: Clone the GitHub repo into a temporary folder.
    We use a temp directory so it gets cleaned up automatically.
    """
    if state["status"] == "failed":
        return state   # skip if already failed

    print(f"[2/7] Cloning repo: {state['repo_url']}")

    # Create a clone directory inside this project workspace.
    os.makedirs(COLLECTED_REPOS_DIR, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix="vulnscan_", dir=COLLECTED_REPOS_DIR)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", state["repo_url"], tmp_dir],
            check=True,
            capture_output=True
        )
        print(f"      Cloned to: {tmp_dir}")
        return {**state, "repo_path": tmp_dir}

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Clone failed: {e.stderr.decode()}")
        return {**state, "status": "failed"}


def detect_language(state: GraphState) -> GraphState:
    """
    Step 3: Look at file extensions to figure out which languages are used.
    This helps agents know what patterns to look for.

    e.g. .py files → Python, .js files → JavaScript
    """
    if state["status"] == "failed":
        return state

    print(f"[3/7] Detecting languages in: {state['repo_path']}")

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

    print(f"      Found languages: {languages_found}")
    print(f"      Total files: {len(all_files)}")

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

    print(f"[4/7] Running scanner agents...")

    all_findings: List[Finding] = []

    # --- Import Person B's agents ---
    # (These will raise NotImplementedError until Person B builds them)
    try:
        from agents.static_analysis import run_static_analysis
        findings = run_static_analysis(state["files"], state["languages"])
        all_findings.extend(findings)
        print(f"      Static analysis: {len(findings)} findings")
    except NotImplementedError:
        print("      [SKIP] Static analysis agent not implemented yet")

    try:
        from agents.dependency_audit import run_dependency_audit
        findings = run_dependency_audit(state["repo_path"])
        all_findings.extend(findings)
        print(f"      Dependency audit: {len(findings)} findings")
    except NotImplementedError:
        print("      [SKIP] Dependency audit agent not implemented yet")

    try:
        from agents.config_secrets import run_config_secrets
        findings = run_config_secrets(state["files"])
        all_findings.extend(findings)
        print(f"      Config/secrets: {len(findings)} findings")
    except NotImplementedError:
        print("      [SKIP] Config/secrets agent not implemented yet")

    return {**state, "findings": all_findings}


def deduplicate_findings(state: GraphState) -> GraphState:
    """
    Step 5: Remove duplicate findings.

    Two findings are duplicates if they point to the same
    file + line + CWE ID combination.
    """
    if state["status"] == "failed":
        return state

    print(f"[5/7] Deduplicating {len(state['findings'])} findings...")

    seen = set()
    unique_findings = []

    for finding in state["findings"]:
        # Create a unique key for this finding
        key = (finding.file_path, finding.line_number, finding.cwe_id)

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    removed = len(state["findings"]) - len(unique_findings)
    print(f"      Removed {removed} duplicates. {len(unique_findings)} remain.")

    return {**state, "findings": unique_findings}


def rank_findings(state: GraphState) -> GraphState:
    """
    Step 6: Sort findings by severity so Critical issues appear first.
    Order: Critical → High → Medium → Low
    """
    if state["status"] == "failed":
        return state

    print(f"[6/7] Ranking findings by severity...")

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

    print(f"[7/7] Running output guardrails...")

    clean_findings = output_guardrails(state["findings"])

    print(f"      Final findings: {len(clean_findings)}")

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

def run_scan(repo_url: str) -> GraphState:
    """
    Main function. Give it a GitHub URL, get back a full report.

    Usage:
        from orchestrator.graph import run_scan
        result = run_scan("https://github.com/owner/repo")
        print(result["findings"])
    """
    app = build_graph()

    # Starting state — all empty, just the URL
    initial_state: GraphState = {
        "repo_url": repo_url,
        "repo_path": "",
        "languages": [],
        "files": [],
        "findings": [],
        "status": "pending"
    }

    # Run the full workflow
    result = app.invoke(initial_state)
    return result


# ─────────────────────────────────────────────
# QUICK TEST (run this file directly to test)
# python orchestrator/graph.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    result = run_scan("https://github.com/torvalds/linux")
    print(f"\nStatus: {result['status']}")
    print(f"Languages: {result['languages']}")
    print(f"Findings: {len(result['findings'])}")