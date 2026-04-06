from dataclasses import dataclass, field
from typing import List

from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    # Canonical fields expected by orchestrator/guardrails.
    file_path: str = ""
    line_number: int = 1
    cwe_id: str = "CWE-200"
    severity: str = "Low"
    title: str = ""
    explanation: str = ""
    suggested_fix: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    # Extra fields used by agent implementations.
    description: str = ""
    engine: str = ""
    authoritative_remediation: str = ""


# Backward-compatible alias used by existing orchestrator code.
Finding = VulnerabilityFinding


@dataclass
class ScanState:
    repo_url: str = ""
    repo_path: str = ""
    languages: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    status: str = "pending"
