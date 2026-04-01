from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    file_path: str
    line_number: int
    cwe_id: str                
    severity: str             
    title: str
    explanation: str
    suggested_fix: str
    confidence: float          


@dataclass
class ScanState:
    repo_url: str
    repo_path: str
    languages: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    status: str = "pending"    


@dataclass
class RetrievalResult:
    """Returned by retrieve() — a single context chunk with metadata."""
    text: str
    source: str                
    doc_id: str
    score: float               


def retrieve(query: str, top_k: int = 5) -> list[str]:
    """
    Person C builds this; Person B's agents call it.
    Returns a list of plain-text context chunks relevant to `query`.
    Import path: from shared.schemas import retrieve
    The actual implementation lives in rag/retrieve.py and is
    monkey-patched here at startup — see rag/__init__.py.
    """
    raise NotImplementedError(
        "Call rag.init() before using retrieve(), "
        "or import directly from rag.retrieve"
    )
