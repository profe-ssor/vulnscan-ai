"""
Person A — State file.
LangGraph needs to know the shape of our shared state.
We just import ScanState from schemas and re-export it.
"""
from typing import TypedDict, List
from shared.schemas import ScanState, Finding


# LangGraph uses TypedDict for its state
# This tells LangGraph what fields exist in our state
class GraphState(TypedDict):
    repo_url: str
    repo_path: str
    languages: List[str]
    files: List[str]
    findings: List[Finding]
    status: str