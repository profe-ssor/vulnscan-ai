# VulnScan AI — Capstone Project Plan

## Overview

VulnScan AI is a multi-agent system that scans any GitHub repository for security vulnerabilities. You give it a repo URL, and it returns an actionable vulnerability report with severity ratings, CWE classifications, and suggested fixes.

## Architecture

```
GitHub Repo URL
      ↓
[Input Guardrails] — validate URL, size limits, rate limits, prompt injection filter
      ↓
[Orchestrator Agent (LangGraph)] — stateful workflow: clone → detect language → fan out → collect → deduplicate → rank
      ↓
┌─────────────────────┬──────────────────────┬──────────────────────┐
│ Static Analysis      │ Dependency Audit      │ Config / Secrets      │
│ Agent                │ Agent                 │ Agent                 │
│ (OpenAI Agents SDK)  │ (OpenAI Agents SDK)   │ (OpenAI Agents SDK)   │
└────────┬────────────┴──────────┬───────────┴──────────┬───────────┘
         │                       │                       │
    ┌────┴────┐             ┌────┴────┐                  │
    │ RAG     │             │ MCP     │                  │
    │ Vector  │             │ Tool    │                  │
    │ Store   │             │ Servers │                  │
    └─────────┘             └─────────┘                  │
         │                       │                       │
         └───────────┬───────────┘───────────────────────┘
                     ↓
          [Report Generator Agent]
                     ↓
            [Output Guardrails] — validate CVEs, CWE IDs, file paths, redact secrets
                     ↓
            Vulnerability Report
```

### Connection Patterns

Not every agent hits every service:

| Agent | RAG | MCP | Notes |
|---|---|---|---|
| Static Analysis | Always | On-demand (GitHub) | LLM + RAG does the analysis, MCP only to read extra files |
| Dependency Audit | On-demand | Always (CVE/NVD) | Needs real-time CVE data every time |
| Config/Secrets | Not needed | On-demand (GitHub) | Mostly pattern matching on file contents |
| Report Generator | No | No | Pure LLM aggregation task |

---

## Team Breakdown

```
Person A: Orchestrator + Guardrails
Person B: Scanner Agents
Person C: RAG Pipeline + Vector Store
Person D: MCP Servers + Report Generator
```

---

## Person A — Orchestrator & Guardrails

**Owns:** The brain of the system + safety layer

| Task | Details |
|---|---|
| LangGraph workflow | Build the stateful graph: `clone → detect language → fan out → collect → deduplicate → rank` |
| Input guardrails | URL validation, repo size check, rate limiting, prompt injection filter, auth |
| Output guardrails | Verify CVE/CWE IDs exist, file paths are real, confidence threshold, redact secrets |
| Conditional routing | Skip scanners that aren't relevant (no lock file = skip dependency audit) |
| State schema | Define the shared state object all agents read/write to |

**Delivers:** A working LangGraph app that accepts a repo URL and orchestrates the full pipeline

**Depends on:** Person B's agents, Person D's report generator

---

## Person B — Scanner Agents

**Owns:** The three scanning agents that do the actual vulnerability detection

| Task | Details |
|---|---|
| Static Analysis Agent | OpenAI Agents SDK agent that reads code and identifies insecure patterns (SQLi, XSS, command injection, auth flaws) |
| Dependency Audit Agent | Parses `package-lock.json`, `requirements.txt`, `Gemfile.lock`, checks versions against CVE data |
| Config/Secrets Agent | Scans for `.env` files, hardcoded API keys, insecure configs, exposed credentials |
| Agent-as-tool pattern | Expose each agent as a callable tool the orchestrator can invoke |
| Prompt engineering | Write the system prompts that make each agent accurate |

**Delivers:** Three agents that accept file contents and return structured findings

**Depends on:** Person C's RAG retrieval function, Person D's MCP tools

---

## Person C — RAG Pipeline & Vector Store

**Owns:** The knowledge base that makes the agents smart

| Task | Details |
|---|---|
| Data collection | Scrape/download OWASP Top 10 docs, CWE entries, known exploit patterns per language |
| Chunking & embedding | Process documents into chunks, embed with OpenAI embeddings, store in Chroma or FAISS |
| Retrieval function | Build a `retrieve(query, top_k)` function that Person B's agents call |
| Continuous ingestion | Scheduled job that syncs new CVEs from NVD RSS feed, GitHub Advisories, Exploit-DB |
| Evaluation | Test retrieval quality — does querying "SQL injection in Python" return useful context? |

**Delivers:** A vector store + retrieval API that agents query for vulnerability context

**Depends on:** Nobody — can start immediately

---

## Person D — MCP Servers & Report Generator

**Owns:** External tool access + final output

| Task | Details |
|---|---|
| GitHub MCP Server | FastMCP server: clone repo, list files, read file contents, detect language |
| CVE/NVD MCP Server | FastMCP server: query NVD API by package name + version, return CVE matches with severity |
| OWASP Patterns Server | FastMCP server: regex/heuristic pattern matching for common vulns |
| Report Generator Agent | OpenAI Agents SDK agent that deduplicates findings, formats into structured report |
| Output format | Define the report schema: file, line, CWE, severity, explanation, suggested fix, confidence |

**Delivers:** Three MCP servers + a report generator

**Depends on:** Nobody for MCP servers — can start immediately

---

## Shared Contracts

Agree on these interfaces before anyone writes code:

```python
# shared/schemas.py

class Finding:
    file_path: str
    line_number: int
    cwe_id: str          # e.g. "CWE-89"
    severity: str        # Critical | High | Medium | Low
    title: str
    explanation: str
    suggested_fix: str
    confidence: float    # 0.0 - 1.0

class ScanState:
    repo_url: str
    repo_path: str
    languages: list[str]
    files: list[str]
    findings: list[Finding]
    status: str

def retrieve(query: str, top_k: int = 5) -> list[str]:
    """Person C builds this, Person B's agents call it"""
```

---

## Repo Structure

```
vulnscan-ai/
├── orchestrator/          ← Person A
│   ├── graph.py
│   ├── guardrails.py
│   └── state.py
├── agents/                ← Person B
│   ├── static_analysis.py
│   ├── dependency_audit.py
│   ├── config_secrets.py
│   └── prompts/
├── rag/                   ← Person C
│   ├── ingest.py
│   ├── retrieve.py
│   ├── sync.py
│   └── data/
├── mcp_servers/           ← Person D
│   ├── github_server.py
│   ├── cve_server.py
│   ├── owasp_server.py
│   └── report_generator.py
├── shared/
│   └── schemas.py
├── tests/
├── requirements.txt
└── README.md
```

---

## Git Workflow

- `main` — protected, merge via PR only
- `feat/orchestrator` — Person A
- `feat/agents` — Person B
- `feat/rag` — Person C
- `feat/mcp-servers` — Person D
- Everyone imports from `shared/schemas.py` — that file gets merged first

---

## 4-Day Sprint

### Day 1 — Setup + Build Starts

**Morning (all 4, 1 hour together):**
- Create repo, agree on `shared/schemas.py`, push to main
- Everyone branches off and starts

**Then split:**

| Person | Day 1 Focus |
|---|---|
| **A** | LangGraph graph skeleton + input guardrails |
| **B** | Static Analysis Agent + prompts (hardest agent, start first) |
| **C** | Ingest OWASP Top 10 + CWE into vector store, expose `retrieve()` |
| **D** | GitHub MCP server + CVE/NVD MCP server |

### Day 2 — Core Features Done

| Person | Day 2 Focus |
|---|---|
| **A** | Output guardrails + conditional routing logic |
| **B** | Dependency Audit Agent + Config/Secrets Agent (simpler, faster to build) |
| **C** | Continuous ingestion from NVD feed + test retrieval quality |
| **D** | OWASP Patterns MCP server + Report Generator Agent |

**End of Day 2:** Every piece exists independently. PRs open.

### Day 3 — Integration

**Morning:** Merge all branches into main, resolve conflicts.

| Person | Day 3 Focus |
|---|---|
| **A + B** | Wire orchestrator → agents, test the full scan flow end-to-end |
| **C + D** | Wire agents → RAG retrieval + MCP servers, fix connection issues |

**Afternoon:** First full run against a real repo. Everyone debugs together.

### Day 4 — Test + Present

| Person | Day 4 Focus |
|---|---|
| **A** | Run against 2-3 known-vulnerable repos, fix edge cases |
| **B** | Tune agent prompts based on real results (reduce false positives) |
| **C** | Verify RAG is returning relevant context, fix bad chunks |
| **D** | Polish report output format, write README |

**Afternoon:** Demo dry run, prep presentation.

---

## What to Cut if Behind

If Day 3 integration is rough, drop these in priority order:

1. **Continuous ingestion** — use a static vector store, add sync later
2. **OWASP Patterns MCP server** — two MCP servers is enough
3. **Config/Secrets Agent** — two scanner agents still tells the story
4. **Output guardrails** — keep input guardrails, output can be manual review

**Minimum viable demo:** URL → input guardrails → orchestrator → 1 scanner agent + RAG + 1 MCP server → report

---


**Total time: ~4 minutes**

---

## Key Terms

- **CVE** (Common Vulnerabilities and Exposures) — a public catalog where every known vulnerability gets a unique ID like `CVE-2024-3094`. A universal naming system so everyone refers to the same bug the same way.
- **NVD** (National Vulnerability Database) — a US government database (run by NIST) that enriches CVE entries with severity scores (CVSS), affected versions, and references. The most comprehensive free API for checking if a package version has known vulnerabilities.
- **CWE** (Common Weakness Enumeration) — a categorization system for types of vulnerabilities. While CVE is a specific bug, CWE describes the class of mistake (e.g. CWE-89 = SQL Injection, CWE-79 = XSS, CWE-798 = Hardcoded Credentials).
- **MCP** (Model Context Protocol) — a protocol for exposing external tools as callable functions that LLM agents can invoke.
- **RAG** (Retrieval-Augmented Generation) — a technique where the LLM retrieves relevant context from a knowledge base before generating its response, improving accuracy.
