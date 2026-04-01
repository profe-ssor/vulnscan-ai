from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single vulnerability finding from any scanner agent."""
    file_path: str
    line_number: int
    cwe_id: str          # e.g. "CWE-89"
    severity: str        # Critical | High | Medium | Low
    title: str
    explanation: str
    suggested_fix: str
    confidence: float    # 0.0 - 1.0

    def __post_init__(self):
        if not isinstance(self.line_number, int) or self.line_number <= 0:
            raise ValueError(f"line_number must be a positive integer, got {self.line_number}")
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")


@dataclass
class ScanState:
    """Shared state the orchestrator passes through the pipeline."""
    repo_url: str
    repo_path: str = ""
    languages: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    status: str = "pending"  # pending | cloning | scanning | reporting | done | error
from typing import List

@dataclass
class Finding:
    file_path: str        # which file has the vulnerability
    line_number: int      # which line
    cwe_id: str           # e.g. "CWE-89" (SQL Injection)
    severity: str         # Critical | High | Medium | Low
    title: str            # short name e.g. "SQL Injection"
    explanation: str      # what the problem is
    suggested_fix: str    # how to fix it
    confidence: float     # how sure the agent is (0.0 - 1.0)

@dataclass
class ScanState:
    repo_url: str = ""
    repo_path: str = ""
    languages: List[str] = field(default_factory=list)   # ["python", "javascript"]
    files: List[str] = field(default_factory=list)        # all file paths in repo
    findings: List[Finding] = field(default_factory=list) # all vulnerabilities found
    status: str = "pending"  # pending | running | complete | failed
