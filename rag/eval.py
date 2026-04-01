from __future__ import annotations

import json
import math
import sys
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Ground truth test cases
# Each case has: a query, keywords that MUST appear in relevant results,
# and the minimum number of results expected above threshold.
# ---------------------------------------------------------------------------

TEST_CASES = [
    # OWASP 2025 coverage
    {"query": "SQL injection parameterized query Python",
     "keywords": ["sql", "injection", "parameterized"],
     "min_results": 1, "category": "OWASP-A05"},

    {"query": "OWASP broken access control IDOR privilege escalation",
     "keywords": ["access", "control", "idor"],
     "min_results": 1, "category": "OWASP-A01"},

    {"query": "software supply chain compromised dependency package",
     "keywords": ["supply chain", "dependency"],
     "min_results": 1, "category": "OWASP-A03"},

    {"query": "cryptographic failures weak encryption MD5 SHA1",
     "keywords": ["cryptograph", "md5", "sha"],
     "min_results": 1, "category": "OWASP-A04"},

    {"query": "authentication failures credential stuffing session fixation",
     "keywords": ["authentication", "session", "credential"],
     "min_results": 1, "category": "OWASP-A07"},

    {"query": "logging alerting failures no monitoring breach detection",
     "keywords": ["log", "monitor", "alert"],
     "min_results": 1, "category": "OWASP-A09"},

    {"query": "mishandling exceptional conditions fail open bare except",
     "keywords": ["exception", "fail", "bare except"],
     "min_results": 1, "category": "OWASP-A10"},

    # CWE coverage
    {"query": "CWE-89 SQL injection detection pattern prevention fix",
     "keywords": ["sql", "cwe-89", "injection"],
     "min_results": 1, "category": "CWE"},

    {"query": "CWE-798 hardcoded credentials API keys source code",
     "keywords": ["hardcoded", "credential"],
     "min_results": 1, "category": "CWE"},

    {"query": "CWE-502 deserialization untrusted data pickle yaml",
     "keywords": ["deserializ", "pickle"],
     "min_results": 1, "category": "CWE"},

    {"query": "CWE-22 path traversal directory ../  file access",
     "keywords": ["path", "traversal"],
     "min_results": 1, "category": "CWE"},

    # Language patterns
    {"query": "Python eval exec user input remote code execution",
     "keywords": ["eval", "exec", "python"],
     "min_results": 1, "category": "LangPatterns"},

    {"query": "JavaScript prototype pollution lodash merge XSS innerHTML",
     "keywords": ["javascript", "xss", "innerhtml"],
     "min_results": 1, "category": "LangPatterns"},

    {"query": "Java Spring PreparedStatement SQL injection deserialization",
     "keywords": ["java", "preparedstatement"],
     "min_results": 1, "category": "LangPatterns"},

    {"query": "Go command injection TLS InsecureSkipVerify crypto/rand",
     "keywords": ["go", "tls", "command"],
     "min_results": 1, "category": "LangPatterns"},

    # Cross-cutting / harder queries
    {"query": "SSRF server side request forgery internal network metadata",
     "keywords": ["ssrf", "request forgery"],
     "min_results": 1, "category": "CrossCutting"},

    {"query": "XSS cross site scripting template engine auto-escape",
     "keywords": ["xss", "cross-site"],
     "min_results": 1, "category": "CrossCutting"},

    {"query": "insecure design threat modeling business logic bypass",
     "keywords": ["design", "threat model"],
     "min_results": 1, "category": "CrossCutting"},
]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    query: str
    category: str
    num_results: int
    mrr: float                 # 0.0-1.0
    ndcg: float                # 0.0-1.0
    keyword_coverage: float    # 0-100 (percentage)
    passed: bool


def _is_relevant(chunk: str, keywords: list[str]) -> bool:
    """A chunk is relevant if it contains ALL required keywords (case-insensitive)."""
    text = chunk.lower()
    return all(kw.lower() in text for kw in keywords)


def _mrr(chunks: list[str], keywords: list[str]) -> float:
    """Mean Reciprocal Rank (for a single query: reciprocal of first relevant rank)."""
    for rank, chunk in enumerate(chunks, start=1):
        if _is_relevant(chunk, keywords):
            return 1.0 / rank
    return 0.0


def _ndcg(chunks: list[str], keywords: list[str], k: int = 5) -> float:
    """
    Normalized DCG@k.
    Relevance is binary: 1 if relevant, 0 if not.
    """
    relevances = [1 if _is_relevant(c, keywords) else 0 for c in chunks[:k]]
    dcg = sum(rel / math.log2(rank + 1) for rank, rel in enumerate(relevances, start=1))
    # Ideal DCG: all relevant docs at the top
    ideal = sum(1.0 / math.log2(i + 1) for i in range(1, min(sum(relevances) + 1, k + 1)))
    return dcg / ideal if ideal > 0 else 0.0


def _keyword_coverage(chunks: list[str], keywords: list[str]) -> float:
    """% of keywords found anywhere across all chunks."""
    if not keywords:
        return 100.0
    all_text = " ".join(chunks).lower()
    found = sum(1 for kw in keywords if kw.lower() in all_text)
    return (found / len(keywords)) * 100.0


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def evaluate_all(top_k: int = 5) -> list[EvalResult]:
    """Run all test cases and return EvalResult per case."""
    from rag.retrieve import retrieve  # lazy import avoids circular deps

    results = []
    for case in TEST_CASES:
        chunks = retrieve(case["query"], top_k=top_k, skip_guardrails=True)
        mrr = _mrr(chunks, case["keywords"])
        ndcg = _ndcg(chunks, case["keywords"])
        coverage = _keyword_coverage(chunks, case["keywords"])
        passed = (
            len(chunks) >= case["min_results"]
            and coverage >= 50.0  # at least half of keywords found
        )
        results.append(EvalResult(
            query=case["query"],
            category=case["category"],
            num_results=len(chunks),
            mrr=mrr,
            ndcg=ndcg,
            keyword_coverage=coverage,
            passed=passed,
        ))
    return results


def print_report(results: list[EvalResult]) -> None:
    """Print a color-coded terminal table."""
    GREEN = "\033[92m"
    AMBER = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    def color(val: float, green: float, amber: float) -> str:
        if val >= green:
            return f"{GREEN}{val:.3f}{RESET}"
        if val >= amber:
            return f"{AMBER}{val:.3f}{RESET}"
        return f"{RED}{val:.3f}{RESET}"

    print(f"\n{'Query':<55} {'Cat':<14} {'MRR':>6} {'nDCG':>6} {'Cov%':>6} {'Pass':>5}")
    print("-" * 100)

    by_category: dict[str, list[EvalResult]] = {}
    for r in results:
        by_category.setdefault(r.category, []).append(r)
        q = r.query[:53] + ".." if len(r.query) > 53 else r.query
        ok = f"{GREEN}✓{RESET}" if r.passed else f"{RED}✗{RESET}"
        print(
            f"{q:<55} {r.category:<14} "
            f"{color(r.mrr, 0.5, 0.25):>15} "
            f"{color(r.ndcg, 0.5, 0.25):>15} "
            f"{color(r.keyword_coverage, 80, 50):>15} "
            f"{ok:>8}"
        )

    # Summary
    avg_mrr = sum(r.mrr for r in results) / len(results)
    avg_ndcg = sum(r.ndcg for r in results) / len(results)
    avg_cov = sum(r.keyword_coverage for r in results) / len(results)
    passed = sum(1 for r in results if r.passed)

    print("-" * 100)
    print(f"{'OVERALL AVERAGE':<55} {'':14} "
          f"{color(avg_mrr, 0.5, 0.25):>15} "
          f"{color(avg_ndcg, 0.5, 0.25):>15} "
          f"{color(avg_cov, 80, 50):>15} "
          f"  {passed}/{len(results)}")

    print(f"\nBy category:")
    for cat, cat_results in sorted(by_category.items()):
        cat_mrr = sum(r.mrr for r in cat_results) / len(cat_results)
        cat_pass = sum(1 for r in cat_results if r.passed)
        bar = "█" * int(cat_mrr * 20)
        print(f"  {cat:<18} MRR={cat_mrr:.3f} {bar:<20} {cat_pass}/{len(cat_results)} passed")


def export_json(results: list[EvalResult]) -> dict:
    avg_mrr = sum(r.mrr for r in results) / len(results)
    avg_ndcg = sum(r.ndcg for r in results) / len(results)
    avg_cov = sum(r.keyword_coverage for r in results) / len(results)
    passed = sum(1 for r in results if r.passed)
    return {
        "summary": {
            "avg_mrr": round(avg_mrr, 4),
            "avg_ndcg": round(avg_ndcg, 4),
            "avg_keyword_coverage": round(avg_cov, 2),
            "passed": passed,
            "total": len(results),
            "pass_rate": round(passed / len(results), 4),
        },
        "results": [
            {
                "query": r.query,
                "category": r.category,
                "mrr": round(r.mrr, 4),
                "ndcg": round(r.ndcg, 4),
                "keyword_coverage": round(r.keyword_coverage, 2),
                "num_results": r.num_results,
                "passed": r.passed,
            }
            for r in results
        ],
    }


if __name__ == "__main__":
    as_json = "--json" in sys.argv

    print("Running retrieval evaluation...")
    results = evaluate_all(top_k=5)

    if as_json:
        print(json.dumps(export_json(results), indent=2))
    else:
        print_report(results)

    # Exit code 1 if pass rate < 80% (useful in CI)
    pass_rate = sum(1 for r in results if r.passed) / len(results)
    sys.exit(0 if pass_rate >= 0.80 else 1)
