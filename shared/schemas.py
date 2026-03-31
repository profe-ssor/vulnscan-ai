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


@dataclass
class ScanState:
    """Shared state the orchestrator passes through the pipeline."""
    repo_url: str
    repo_path: str = ""
    languages: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    status: str = "pending"  # pending | cloning | scanning | reporting | done | error
