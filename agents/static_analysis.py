import os
import asyncio
from typing import List
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI

from shared.schemas import VulnerabilityFinding
from agents.prompts.security_prompts import STATIC_ANALYSIS_PROMPT

# Assuming the RAG component is in the rag/ directory
from rag.retrieve import DynamicSecurityKnowledgeBase

class LLMAnalysisResult(BaseModel):
    findings: List[VulnerabilityFinding] = Field(description="List of vulnerabilities found.")

class CodeAnalysisAgent:
    def __init__(self, kb: DynamicSecurityKnowledgeBase):
        self.name = "SAST_Agent"
        self.kb = kb
        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        self.chain = STATIC_ANALYSIS_PROMPT | self.llm.with_structured_output(LLMAnalysisResult)
        
        # Directories to skip to save time and tokens
        self.ignore_dirs = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}

    async def _analyze_file(self, file_path: str) -> List[VulnerabilityFinding]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if not content.strip() or len(content) > 100000: 
                return []

            result = await self.chain.ainvoke({"file_path": file_path, "code_content": content})
            
            for finding in result.findings:
                finding.engine = self.name
                finding.file_path = file_path
                # RAG Enrichment
                finding.authoritative_remediation = self.kb.get_authoritative_advice(finding.description)
                
            return result.findings
        except Exception as e:
            print(f"[{self.name}] Error analyzing {file_path}: {e}")
            return []

    async def scan_node(self, source_path: str) -> List[VulnerabilityFinding]:
        supported_exts = ('.py', '.js', '.ts', '.go', '.java', '.php', '.rb', '.cs', '.cpp', '.c')
        tasks = []
        
        for root, dirs, files in os.walk(source_path):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                if file.endswith(supported_exts):
                    tasks.append(self._analyze_file(os.path.join(root, file)))
        
        if not tasks: 
            return []
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_findings = []
        for res in results:
            if isinstance(res, list): 
                all_findings.extend(res)
                
        return all_findings
