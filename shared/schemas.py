from dataclasses import dataclass, field
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