# vulnscan-ai


Agents module (/agents)
This directory contains the specialized LLM scanning engines. Each agent is responsible for traversing a specific subset of files in a target directory, applying security analysis, and enriching the findings via the RAG Knowledge Base.

Exported Agents
The module exposes three agent classes via __init__.py:

CodeAnalysisAgent: Scans core application logic (.py, .js, .go, etc.) for CWEs and SANS Top 25 flaws.

DependencyAuditAgent: Scans package manifests (requirements.txt, package.json, etc.) for vulnerable or outdated libraries.

SecretsAgent: Scans configuration and IaC files (.env, .yaml, Dockerfiles) for hardcoded credentials and severe misconfigurations.

🛠️ Interface & Integration Guide
To use these agents in the Orchestrator (graph.py), follow these rules:

1. Initialization Requirements
Every agent must be initialized with an instance of the DynamicSecurityKnowledgeBase (from the rag/ module) so it can perform its own CVE enrichment.

2. The Execution Method
Every agent exposes a single public asynchronous method:

Method: await scan_node(source_path: str)

Input: The absolute path to the directory being scanned. (The agent handles its own file filtering and directory ignoring internally).

Output: List[VulnerabilityFinding] (from shared.schemas). Returns an empty list [] if no vulnerabilities are found.

Example Orchestrator Integration
from shared.schemas import VulnerabilityFinding
from rag.retrieve import DynamicSecurityKnowledgeBase
from agents import CodeAnalysisAgent, DependencyAuditAgent, SecretsAgent

async def run_scanners(target_dir: str):
    # 1. Initialize the shared Knowledge Base ONCE
    kb = DynamicSecurityKnowledgeBase()
    
    # 2. Instantiate the agents and inject the KB
    sast_agent = CodeAnalysisAgent(kb=kb)
    dep_agent = DependencyAuditAgent(kb=kb)
    secrets_agent = SecretsAgent(kb=kb)
    
    # 3. Execute the agents (can be done concurrently via asyncio.gather)
    code_findings = await sast_agent.scan_node(target_dir)
    dep_findings = await dep_agent.scan_node(target_dir)
    secret_findings = await secrets_agent.scan_node(target_dir)
    
    # 4. Aggregate findings
    return code_findings + dep_findings + secret_findings