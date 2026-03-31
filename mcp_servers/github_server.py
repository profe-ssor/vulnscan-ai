"""
GitHub MCP Server — provides tools for cloning repos and reading their contents.

This is the first thing that runs in the pipeline: the orchestrator calls
clone_repo, then detect_languages and list_files to figure out what scanners
to invoke, and the scanners call read_file to get actual source code.

Transport: stdio (launched as a subprocess by the orchestrator)
"""

import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Initialize the MCP server with a name (shows up in logs / client discovery)
mcp = FastMCP("github")

# Where cloned repos are stored temporarily
CLONE_DIR = Path(os.environ.get("VULNSCAN_CLONE_DIR", "/tmp/vulnscan_repos"))

# Map file extensions to language names
EXTENSION_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".php": "PHP",
    ".c": "C",
    ".cpp": "C++",
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".sh": "Shell",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".html": "HTML",
    ".css": "CSS",
    ".sql": "SQL",
    ".tf": "Terraform",
    ".dockerfile": "Docker",
}

# Files/dirs to skip when listing (not useful for vulnerability scanning)
IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", ".bundle",
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar",
    ".gz", ".lock", ".map",
}


@mcp.tool()
def clone_repo(repo_url: str) -> str:
    """
    Clone a GitHub repository to a local temp directory.

    Args:
        repo_url: Full GitHub URL, e.g. https://github.com/owner/repo

    Returns:
        The local path where the repo was cloned.
    """
    # Extract repo name from URL to create a unique folder
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    clone_path = CLONE_DIR / repo_name

    # If already cloned, remove and re-clone for fresh state
    if clone_path.exists():
        shutil.rmtree(clone_path)

    CLONE_DIR.mkdir(parents=True, exist_ok=True)

    # Shallow clone (depth=1) — we only need the latest code, not history
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(clone_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        return f"Error cloning repo: {result.stderr.strip()}"

    return str(clone_path)


@mcp.tool()
def list_files(repo_path: str, max_files: int = 500) -> list[str]:
    """
    List all source/config files in the cloned repo, skipping irrelevant
    files like images, binaries, and dependency directories.

    Args:
        repo_path: Local path to the cloned repo (returned by clone_repo).
        max_files: Maximum number of files to return (default 500).

    Returns:
        List of file paths relative to the repo root.
    """
    root = Path(repo_path)
    if not root.exists():
        return [f"Error: path {repo_path} does not exist"]

    files = []
    for path in sorted(root.rglob("*")):
        if len(files) >= max_files:
            break

        # Skip ignored directories
        if any(part in IGNORE_DIRS for part in path.parts):
            continue

        # Skip non-files and ignored extensions
        if not path.is_file():
            continue
        if path.suffix.lower() in IGNORE_EXTENSIONS:
            continue

        files.append(str(path.relative_to(root)))

    return files


@mcp.tool()
def read_file(repo_path: str, file_path: str, max_lines: int = 1000) -> str:
    """
    Read the contents of a single file from the cloned repo.

    Args:
        repo_path: Local path to the cloned repo.
        file_path: Path relative to repo root (as returned by list_files).
        max_lines: Maximum number of lines to return (default 1000).

    Returns:
        The file contents as a string, with line numbers prepended.
    """
    full_path = Path(repo_path) / file_path

    if not full_path.exists():
        return f"Error: file {file_path} not found"

    if not full_path.is_file():
        return f"Error: {file_path} is not a file"

    try:
        content = full_path.read_text(errors="replace")
    except Exception as e:
        return f"Error reading file: {e}"

    lines = content.splitlines()[:max_lines]

    # Prepend line numbers so agents can reference exact lines in findings
    numbered = [f"{i + 1:4d} | {line}" for i, line in enumerate(lines)]

    if len(content.splitlines()) > max_lines:
        numbered.append(f"\n... truncated ({len(content.splitlines())} total lines)")

    return "\n".join(numbered)


@mcp.tool()
def detect_languages(repo_path: str) -> dict[str, int]:
    """
    Detect programming languages used in the repo by counting file extensions.

    Args:
        repo_path: Local path to the cloned repo.

    Returns:
        Dict mapping language name to file count, sorted by count descending.
        Example: {"Python": 42, "JavaScript": 15, "YAML": 3}
    """
    root = Path(repo_path)
    if not root.exists():
        return {"error": f"path {repo_path} does not exist"}

    counts: Counter[str] = Counter()
    for path in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        ext = path.suffix.lower()
        lang = EXTENSION_MAP.get(ext)
        if lang:
            counts[lang] += 1

    # Also check for Dockerfiles (no extension)
    for path in root.rglob("Dockerfile*"):
        counts["Docker"] += 1

    return dict(counts.most_common())


if __name__ == "__main__":
    mcp.run()
