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
