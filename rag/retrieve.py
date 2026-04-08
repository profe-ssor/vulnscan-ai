from __future__ import annotations

import asyncio
import hashlib
import logging
from functools import lru_cache
from typing import Optional

from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

from rag.guardrails import (
    GuardrailError,
    filter_plain_results,
    filter_results,
    validate_query,
    validate_top_k,
    MIN_RESULT_SCORE,
)
from rag.ingest import DB_DIR, COLLECTION_NAME, EMBEDDING_MODEL_NAME, EMBEDDING_DEVICE

log = logging.getLogger(__name__)

DEFAULT_TOP_K = 5

# ---------------------------------------------------------------------------
# Speed layer 1 -- Query result cache
# ---------------------------------------------------------------------------

# Cache key: (query_text, top_k)  ->  list[str]
# maxsize=256 covers ~the full OWASP+CWE pattern space with room for NVD lookups.
# Cache is module-level so it survives across multiple retrieve() calls within one run.
_query_cache: dict[tuple[str, int], list[str]] = {}
_CACHE_MAX = 256


def _cache_key(query: str, top_k: int) -> tuple[str, int]:
    """Short hash of query text avoids key bloat for long queries."""
    h = hashlib.md5(query.encode(), usedforsecurity=False).hexdigest()[:16]
    return (h, top_k)


def _cache_get(query: str, top_k: int) -> Optional[list[str]]:
    return _query_cache.get(_cache_key(query, top_k))


def _cache_set(query: str, top_k: int, result: list[str]) -> None:
    if len(_query_cache) >= _CACHE_MAX:
        # Evict the oldest inserted key (dict insertion order, Python 3.7+)
        oldest = next(iter(_query_cache))
        del _query_cache[oldest]
    _query_cache[_cache_key(query, top_k)] = result


def cache_stats() -> dict:
    return {"size": len(_query_cache), "max": _CACHE_MAX}


def clear_cache() -> None:
    """Flush the query cache. Call after a sync/ingest to invalidate stale results."""
    _query_cache.clear()
    log.info("Query cache cleared.")


# ---------------------------------------------------------------------------
# Speed layer 3 -- DB connection (cached)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_db() -> Chroma:
    """
    Cached LangChain Chroma handle with explicit HNSW search parameters.

    Connects to the persistent ChromaDB collection using the same
    embedding model as ingest.py. Cached so the model loads only once.
    """
    log.info("Connecting to ChromaDB at %s (collection=%s)...", DB_DIR, COLLECTION_NAME)
    embeddings = HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL_NAME,
        model_kwargs={"device": EMBEDDING_DEVICE},
        encode_kwargs={"normalize_embeddings": True},
    )
    db = Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=embeddings,
        persist_directory=DB_DIR,
        # Note: hnsw:space and hnsw:ef are NOT set here.
        # ChromaDB 1.5.5+ (Rust backend) no longer accepts hnsw params in
        # collection_metadata — it raises InvalidArgumentError. The collection
        # uses its default HNSW config, which is sufficient for this KB size.
    )
    count = db._collection.count()
    log.info("RAG collection ready: %d chunks", count)
    return db


# ---------------------------------------------------------------------------
# Core search (used by all public functions)
# ---------------------------------------------------------------------------

def _search(query: str, top_k: int, where: Optional[dict] = None) -> list[tuple]:
    """
    Run one similarity search. Returns list of (Document, score) tuples.
    This is the only place we hit ChromaDB directly.
    """
    db = _get_db()
    collection_size = db._collection.count()
    if collection_size == 0:
        log.warning("Collection is empty -- run rag.ingest first")
        return []

    n = min(top_k, collection_size)
    kwargs: dict = {"k": n}
    if where:
        kwargs["filter"] = where

    return db.similarity_search_with_relevance_scores(query, **kwargs)


# ---------------------------------------------------------------------------
# Speed layer 2 -- Async concurrent batch retrieval
# ---------------------------------------------------------------------------

async def _retrieve_one_async(
    query: str,
    top_k: int,
    caller_id: str,
) -> list[str]:
    """Single async retrieve, runs _search in a thread pool executor."""
    # Check cache first -- no I/O needed
    cached = _cache_get(query, top_k)
    if cached is not None:
        log.debug("Cache HIT: '%s'", query[:50])
        return cached

    validation = validate_query(query, caller_id=caller_id)
    clean_query = validation.clean_query
    top_k = validate_top_k(top_k)

    loop = asyncio.get_event_loop()
    # Run the blocking ChromaDB + embedding call in a thread so the event loop
    # isn't blocked. Multiple queries run concurrently via asyncio.gather().
    results_with_scores = await loop.run_in_executor(
        None,  # default ThreadPoolExecutor
        lambda: _search(clean_query, top_k),
    )

    chunks = [
        doc.page_content
        for doc, score in results_with_scores
        if score >= MIN_RESULT_SCORE
    ]
    chunks = filter_plain_results(chunks)
    _cache_set(clean_query, top_k, chunks)
    return chunks


async def retrieve_batch_async(
    queries: list[str],
    top_k: int = DEFAULT_TOP_K,
    caller_id: str = "batch",
) -> list[list[str]]:
    """
    Retrieve results for multiple queries CONCURRENTLY.

    This is the fastest option when multiple agents need context at the same
    time. Person A's orchestrator can call this once with all three agents'
    queries instead of letting each agent call retrieve() serially.

    Args:
        queries:   List of query strings (one per agent or pattern).
        top_k:     Max chunks per query.
        caller_id: For rate-limit tracking.

    Returns:
        List of results in the same order as queries.
        results[0] corresponds to queries[0], etc.

    Example:
        results = asyncio.run(retrieve_batch_async([
            "SQL injection Python string concatenation",
            "hardcoded API key environment variable",
            "OWASP A03:2025 supply chain compromised package",
        ]))
        static_context, config_context, dep_context = results
    """
    tasks = [
        _retrieve_one_async(q, top_k, caller_id)
        for q in queries
    ]
    return await asyncio.gather(*tasks)


def retrieve_batch(
    queries: list[str],
    top_k: int = DEFAULT_TOP_K,
    caller_id: str = "batch",
) -> list[list[str]]:
    """
    Sync wrapper around retrieve_batch_async.
    Use this when you're not already in an async context.

    Example:
        from rag.retrieve import retrieve_batch
        static_ctx, dep_ctx, secrets_ctx = retrieve_batch([
            "SQL injection Python",
            "outdated dependency CVE pip requirements",
            "hardcoded credentials .env file",
        ])
    """
    return asyncio.run(retrieve_batch_async(queries, top_k=top_k, caller_id=caller_id))


# ---------------------------------------------------------------------------
# Public single-query API (with caching)
# ---------------------------------------------------------------------------

def retrieve(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    caller_id: str = "default",
    skip_guardrails: bool = False,
) -> list[str]:
    """
    Return the top-k most relevant text chunks for the given query.

    Checks the query cache first -- repeated calls with the same query
    return instantly without touching ChromaDB or running embeddings.

    This is the function Person B's agents call.

    Args:
        query:           Natural language vulnerability description.
        top_k:           Max chunks to return (clamped to 10).
        caller_id:       Agent name for rate-limit tracking.
        skip_guardrails: Set True only in tests.

    Returns:
        list[str] -- context chunks, best match first. Empty list on no results.

    Raises:
        GuardrailError: If input guardrails block the query.
    """
    # Speed layer 1: cache check
    cached = _cache_get(query, top_k)
    if cached is not None:
        log.debug("Cache HIT: '%s'", query[:50])
        return cached

    # Input guardrails
    if not skip_guardrails:
        validation = validate_query(query, caller_id=caller_id)
        if validation.warnings:
            for w in validation.warnings:
                log.warning("[guardrail] %s", w)
        query = validation.clean_query
        top_k = validate_top_k(top_k)

    results_with_scores = _search(query, top_k)

    chunks = [
        doc.page_content
        for doc, score in results_with_scores
        if score >= MIN_RESULT_SCORE
    ]

    if not skip_guardrails:
        chunks = filter_plain_results(chunks)

    # Store in cache for next call
    _cache_set(query, top_k, chunks)

    log.debug(
        "Cache MISS -> search: '%s' top_k=%d -> %d results",
        query[:50], top_k, len(chunks),
    )
    return chunks


def retrieve_rich(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    filter_source: Optional[str] = None,
    filter_language: Optional[str] = None,
    caller_id: str = "default",
    skip_guardrails: bool = False,
) -> list[dict]:
    """
    Extended retrieval with metadata and similarity scores.

    Note: rich results are NOT cached because metadata filters change the
    result set unpredictably. Use retrieve() for the cached path.

    Returns:
        list[dict] -- {text, source, doc_id, score, metadata}, sorted by score desc.
    """
    if not skip_guardrails:
        validation = validate_query(query, caller_id=caller_id)
        query = validation.clean_query
        top_k = validate_top_k(top_k)

    where: Optional[dict] = None
    if filter_source and filter_language:
        where = {"$and": [{"source": filter_source}, {"language": filter_language}]}
    elif filter_source:
        where = {"source": filter_source}
    elif filter_language:
        where = {"language": filter_language}

    results_with_scores = _search(query, top_k, where=where)

    raw = [
        {
            "text": doc.page_content,
            "source": doc.metadata.get("source", "unknown"),
            "doc_id": (
                doc.metadata.get("cve_id")
                or doc.metadata.get("cwe_id")
                or doc.metadata.get("owasp_id")
                or "unknown"
            ),
            "score": round(score, 4),
            "metadata": doc.metadata,
        }
        for doc, score in results_with_scores
    ]

    raw.sort(key=lambda r: r["score"], reverse=True)

    if not skip_guardrails:
        return filter_results(raw, min_score=MIN_RESULT_SCORE)
    return [r for r in raw if r["score"] >= MIN_RESULT_SCORE]


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def retrieve_for_cwe(cwe_id: str, top_k: int = 3) -> list[str]:
    """Fetch context for a specific CWE ID. Cached after first call."""
    return retrieve(
        query=f"{cwe_id} vulnerability detection pattern prevention fix",
        top_k=top_k,
        caller_id="cwe_lookup",
    )


def retrieve_for_owasp(owasp_id: str, top_k: int = 3) -> list[str]:
    """Fetch context for an OWASP 2025 category. Cached after first call."""
    return retrieve(
        query=f"OWASP {owasp_id} vulnerability prevention examples",
        top_k=top_k,
        caller_id="owasp_lookup",
    )


def collection_stats() -> dict:
    """Collection health check including cache stats."""
    try:
        db = _get_db()
        count = db._collection.count()
        sample = db._collection.peek(limit=5)
        sources = {m.get("source", "unknown") for m in (sample.get("metadatas") or []) if m}
        return {
            "collection": COLLECTION_NAME,
            "total_chunks": count,
            "path": DB_DIR,
            "sample_sources": sorted(sources),
            "status": "ready" if count > 0 else "empty",
            "cache": cache_stats(),
            
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Dual retrieval (borrowed pattern from comparison.txt, adapted for VulnScan)
#
# comparison.txt uses: rewrite_query (LLM) + dual search + rerank (LLM)
# VulnScan adaptation:  expand_query (rules-based) + dual search + score-merge
#
# Why no LLM reranker: VulnScan calls retrieve() ~630x per repo scan.
# The comparison.txt system calls it once per human message. Adding an LLM
# call per retrieve() would add ~21 minutes and $0.63 per scan.
# The dual search alone (two vector searches, no LLM) gives the recall
# improvement without the latency cost.
# ---------------------------------------------------------------------------

_SECURITY_EXPANSIONS: dict[str, str] = {
    "sql": "SQL injection CWE-89 parameterized query database",
    "xss": "cross-site scripting CWE-79 innerHTML user input",
    "rce": "remote code execution command injection eval",
    "sqli": "SQL injection CWE-89 string concatenation cursor.execute",
    "ssrf": "server-side request forgery CWE-918 internal network",
    "xxe": "XML external entity injection CWE-611 DOCTYPE",
    "idor": "insecure direct object reference broken access control CWE-284",
    "csrf": "cross-site request forgery CWE-352 token validation",
    "lfi": "local file inclusion path traversal CWE-22",
    "rfi": "remote file inclusion path traversal",
    "deserialization": "insecure deserialization CWE-502 pickle yaml",
    "supply chain": "software supply chain OWASP A03:2025 dependency CVE",
}


def _expand_query(query: str) -> Optional[str]:
    """
    Rules-based query expansion -- no LLM, no latency.

    Maps short/abbreviated agent queries to richer KB-aligned phrases.
    Returns None if no expansion applies (caller uses original query only).

    Examples:
      "sql"  → "SQL injection CWE-89 parameterized query database"
      "check this python code"  → None (too vague, expansion won't help)
      "CWE-89 Python"  → None (already specific enough)
    """
    q_lower = query.lower().strip()
    for trigger, expansion in _SECURITY_EXPANSIONS.items():
        if trigger in q_lower and expansion.lower() not in q_lower:
            return expansion
    return None


def retrieve_dual(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    caller_id: str = "default",
    skip_guardrails: bool = False,
) -> list[str]:
    """
    Dual retrieval with score-based merge -- better recall than single retrieve().

    Runs two vector searches:
      1. Original query
      2. Expanded query (rules-based, no LLM -- see _expand_query)

    Results are merged and deduplicated by content hash, then sorted by best
    score across both searches. Falls back to single-search retrieve() if no
    expansion applies.

    Use this instead of retrieve() when you want higher recall, e.g. for the
    Static Analysis Agent which may receive terse pattern names from Person B.

    The result is cached per (query, top_k) just like retrieve().

    Args:
        query:           Search query from the agent.
        top_k:           Max chunks to return.
        caller_id:       For rate-limit tracking.
        skip_guardrails: Set True only in tests.

    Returns:
        list[str] -- deduplicated chunks, best match first.
    """
    # Check cache first
    cached = _cache_get(query, top_k)
    if cached is not None:
        log.debug("Cache HIT (dual): '%s'", query[:50])
        return cached

    # Input guardrails
    if not skip_guardrails:
        validation = validate_query(query, caller_id=caller_id)
        if validation.warnings:
            for w in validation.warnings:
                log.warning("[guardrail] %s", w)
        query = validation.clean_query
        top_k = validate_top_k(top_k)

    # Search 1: original query
    results1 = _search(query, top_k)

    # Search 2: expanded query (if one applies)
    expanded = _expand_query(query)
    results2 = _search(expanded, top_k) if expanded else []

    if expanded:
        log.debug("Dual retrieval: '%s' → expanded '%s'", query[:40], expanded[:40])

    # Merge: keep best score per unique content
    seen: dict[str, float] = {}   # content_hash → best_score
    ordered: dict[str, str] = {}  # content_hash → text

    for doc, score in results1 + results2:
        if score < MIN_RESULT_SCORE:
            continue
        # Use first 120 chars as a dedup key (avoids storing full text twice)
        key = doc.page_content[:120]
        if key not in seen or score > seen[key]:
            seen[key] = score
            ordered[key] = doc.page_content

    # Sort by score descending, return text only
    chunks = [
        ordered[k]
        for k in sorted(seen, key=lambda k: seen[k], reverse=True)
    ][:top_k]

    if not skip_guardrails:
        chunks = filter_plain_results(chunks)

    _cache_set(query, top_k, chunks)
    log.debug(
        "retrieve_dual('%s'): %d from search1, %d from search2, %d merged",
        query[:40], len(results1), len(results2), len(chunks),
    )
    return chunks


# ---------------------------------------------------------------------------
# Adapter for scanner agents (Person B) — orchestrator injects one instance
# ---------------------------------------------------------------------------


class DynamicSecurityKnowledgeBase:
    """
    Thin facade over retrieve() so agents can call get_authoritative_advice().

    If Chroma is empty or retrieval fails, returns an empty string (agents still run).
    """

    def get_authoritative_advice(self, text: str) -> str:
        q = (text or "").strip()
        if not q:
            return ""
        try:
            # Internal enrichment only (trusted agent text). skip_guardrails avoids
            # per-caller rate limits when many files are scanned in parallel.
            chunks = retrieve(q, top_k=3, caller_id="kb_enrich", skip_guardrails=True)
            if not chunks:
                return ""
            return "\n\n---\n\n".join(chunks)
        except Exception as e:
            log.warning("get_authoritative_advice failed: %s", e)
            return ""
