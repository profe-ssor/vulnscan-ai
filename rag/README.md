# Person C — RAG Pipeline & Vector Store

**Owns:** The knowledge base that makes the scanner agents smart.

---

## What This Delivers

A ChromaDB vector store pre-loaded with OWASP Top 10, CWE entries, and language-specific exploit patterns — plus a `retrieve(query, top_k)` function that Person B's agents call to get relevant vulnerability context.

---

## Setup

```bash
pip install -r requirements.txt


# No API key needed — embeddings run locally (BAAI/bge-large-en-v1.5, ~1.3 GB first run)
# Optional — NVD API key (50 req/30s with key vs 5 req/30s without)
export NVD_API_KEY="your-nvd-key"

# Optional — for GitHub Advisories sync (higher rate limits)
export GITHUB_TOKEN="ghp_..."
```

---

## Usage (for Person B's agents)

```python
# Option 1 — Import from the rag package directly (recommended)
from rag.retrieve import retrieve

context = retrieve("SQL injection in Python using string concatenation", top_k=5)
# Returns: list[str] — plain text chunks, best match first

# Option 2 — Import from shared.schemas (after rag is initialized)
import rag  # triggers the patch
from shared.schemas import retrieve

context = retrieve("hardcoded API keys in environment variables")
```

### Convenience wrappers

```python
from rag.retrieve import retrieve_for_cwe, retrieve_for_owasp, retrieve_rich

# Fetch context for a specific CWE
context = retrieve_for_cwe("CWE-89")

# Fetch context for a specific OWASP category
context = retrieve_for_owasp("A03:2025")  # Supply Chain Failures

# Rich results with metadata and similarity scores
results = retrieve_rich("XSS attack", top_k=5, filter_source="OWASP")
for r in results:
    print(r["score"], r["source"], r["text"][:100])
```

---

## Building the Knowledge Base

### Full ingest (run this first)

```bash
python -m rag.ingest
```

### Ingest a specific source

```bash
python -m rag.ingest --source owasp
python -m rag.ingest --source cwe
python -m rag.ingest --source patterns
```

### Ingest a custom JSONL file

Each line: `{"text": "...", "source": "MySource", "id": "unique_id", ...metadata}`

```bash
python -m rag.ingest --jsonl rag/data/custom_vulns.jsonl
```

---

## Live Sync (NVD + GitHub Advisories)

### One-shot sync

```bash
python -m rag.sync
```

### Scheduled sync (every 6 hours — runs until stopped)

```bash
python -m rag.sync --schedule
```

### Sync a specific source

```bash
python -m rag.sync --source nvd
python -m rag.sync --source ghsa
```

Sync state is saved to `rag/data/sync_state.json` — each run only fetches CVEs newer than the last sync.

---

## Running Tests

```bash
# Run ingest first, then:
pytest tests/test_rag.py -v
```

Key test cases:
- Collection health (not empty, sources present)
- Semantic relevance: "SQL injection in Python" → returns SQL injection content
- CWE-targeted retrieval: `retrieve_for_cwe("CWE-89")` returns relevant chunks
- Metadata filtering: `retrieve_rich(source="OWASP")` returns only OWASP chunks
- Edge cases: long queries, unicode, special characters

---

## File Structure

```
rag/
├── __init__.py          # patches shared.schemas.retrieve()
├── guardrails.py        # input validation + output redaction
├── ingest.py            # data collection, chunking, embedding
├── retrieve.py          # retrieve() + retrieve_rich() API
├── sync.py              # live NVD/GHSA sync job
└── data/
    ├── chroma/          # ChromaDB persistent store (git-ignored)
    └── sync_state.json  # last sync timestamps
```

---

## What's in the Knowledge Base

| Source | Content | Chunks (approx) |
|--------|---------|-----------------|
| OWASP Top 10 (2025) | All 10 categories — description, examples, prevention | ~80 |
| CWE Entries | CWE-89, 79, 798, 78, 22, 502, 284, 311, 918, 611 + detection patterns | ~60 |
| Language Patterns | Python, JavaScript, Java, Go security anti-patterns | ~50 |
| NVD (after sync) | Recent CVEs with severity + affected packages | varies |
| GHSA (after sync) | GitHub Security Advisories | varies |

---

## Integration Notes for Person B

- Call `retrieve()` at the start of each agent scan to get relevant context before prompting the LLM.
- Use `retrieve_for_cwe(cwe_id)` after a pattern match to enrich the finding with explanation text.
- The function is safe to call concurrently — ChromaDB handles it.
- If the collection is not ready, `retrieve()` returns `[]` gracefully rather than raising.
