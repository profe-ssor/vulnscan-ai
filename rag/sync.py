from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import os

import httpx
import schedule
from langchain_core.documents import Document

from rag.ingest import _get_db, chunk_text   # LangChain Chroma handle + chunker

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

STATE_FILE = Path(__file__).parent / "data" / "sync_state.json"
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API_URL = "https://api.github.com/advisories"

SYNC_INTERVAL_HOURS = 6
HTTP_TIMEOUT = 30
NVD_API_PAGE_SIZE = 100
NVD_SYNC_CAP = 500       # max CVEs per sync cycle to avoid very long runs
# NVD rate limits: 5 req/30s without API key, 50 req/30s with key.
# Match the same env var used in 1_download_raw_cves.py.
_NVD_API_KEY = os.environ.get("NVD_API_KEY")
NVD_SLEEP_SECS = 0.6 if _NVD_API_KEY else 6.1   # stay safely under rate limit


# ---------------------------------------------------------------------------
# Sync state
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if STATE_FILE.exists():
        with STATE_FILE.open() as f:
            return json.load(f)
    return {
        "last_nvd_sync": None,
        "last_ghsa_sync": None,
        "total_cves_synced": 0,
        "total_advisories_synced": 0,
    }


def save_state(state: dict) -> None:
    with STATE_FILE.open("w") as f:
        json.dump(state, f, indent=2)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Shared: add documents to Chroma via LangChain
# ---------------------------------------------------------------------------

def _add_to_db(documents: list[Document], ids: list[str]) -> None:
    """
    Upsert a batch of LangChain Documents into the shared ChromaDB collection.
    Uses the same _get_db() handle as ingest.py -- no duplicate connections.
    """
    if not documents:
        return
    db = _get_db()
    # LangChain Chroma.add_documents handles batching internally
    db.add_documents(documents=documents, ids=ids)
    log.info("Synced %d chunks into ChromaDB", len(documents))


# ---------------------------------------------------------------------------
# NVD CVE sync
# ---------------------------------------------------------------------------

def _build_nvd_params(last_sync: Optional[str], start_index: int = 0) -> dict:
    params: dict[str, Any] = {
        "resultsPerPage": NVD_API_PAGE_SIZE,
        "startIndex": start_index,
    }
    if last_sync:
        dt = datetime.fromisoformat(last_sync).strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubStartDate"] = dt
        params["pubEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    return params


def _parse_nvd_cve(vuln: dict) -> Optional[dict]:
    try:
        cve = vuln["cve"]
        cve_id = cve["id"]

        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No English description available.",
        )

        severity = "Unknown"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = cve.get("metrics", {}).get(key, [])
            if metric_list:
                severity = metric_list[0].get("cvssData", {}).get("baseSeverity", severity)
                break

        cwe_ids = [
            desc.get("value", "")
            for w in cve.get("weaknesses", [])
            for desc in w.get("description", [])
            if desc.get("value", "").startswith("CWE-")
        ]

        affected_packages: list[str] = []
        for config in cve.get("configurations", [])[:2]:
            for node in config.get("nodes", [])[:3]:
                for cpe in node.get("cpeMatch", [])[:3]:
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 4:
                        affected_packages.append(f"{parts[3]} {parts[4]}")

        return {
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "cwe_ids": cwe_ids,
            "affected_packages": affected_packages,
            "published": cve.get("published", ""),
        }
    except (KeyError, IndexError) as exc:
        log.debug("Failed to parse CVE: %s", exc)
        return None


def sync_nvd(last_sync: Optional[str] = None) -> int:
    """
    Fetch CVEs from NVD API and upsert into the vector store.

    Args:
        last_sync: ISO timestamp of last successful sync.
                   If None, fetches the most recent NVD_SYNC_CAP CVEs.

    Returns:
        Number of chunks upserted.
    """
    log.info("Starting NVD sync (last_sync=%s)...", last_sync or "full")
    total_results: Optional[int] = None
    start_index = 0
    documents: list[Document] = []
    ids: list[str] = []

    nvd_headers = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {}
    with httpx.Client(timeout=HTTP_TIMEOUT, headers=nvd_headers) as client:
        while True:
            params = _build_nvd_params(last_sync, start_index=start_index)
            try:
                resp = client.get(NVD_API_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as exc:
                log.error("NVD API error: %s", exc)
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                log.info("NVD: %d CVEs to fetch", total_results)

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                record = _parse_nvd_cve(vuln)
                if not record:
                    continue

                text = (
                    f"{record['cve_id']} -- Severity: {record['severity']}\n"
                    f"CWEs: {', '.join(record['cwe_ids']) or 'None'}\n"
                    f"Affected: {', '.join(record['affected_packages'][:5]) or 'Unknown'}\n\n"
                    f"{record['description']}"
                )
                for chunk_idx, chunk in enumerate(chunk_text(text)):
                    doc_id = f"nvd_{record['cve_id'].replace('-', '_')}_{chunk_idx}"
                    documents.append(Document(
                        page_content=chunk,
                        metadata={
                            "source": "NVD",
                            "cve_id": record["cve_id"],
                            "severity": record["severity"],
                            "cwe_ids": json.dumps(record["cwe_ids"]),
                            "published": record["published"],
                            "chunk_index": chunk_idx,
                        },
                    ))
                    ids.append(doc_id)

            start_index += len(vulnerabilities)
            time.sleep(NVD_SLEEP_SECS)  # respects NVD_API_KEY env var

            if start_index >= (total_results or 0):
                break
            if start_index >= NVD_SYNC_CAP:
                log.info("NVD: reached %d-CVE cap for this sync cycle", NVD_SYNC_CAP)
                break

    _add_to_db(documents, ids)
    log.info("NVD sync complete: %d chunks", len(documents))
    return len(documents)


# ---------------------------------------------------------------------------
# GitHub Security Advisories sync
# ---------------------------------------------------------------------------

def sync_github_advisories(
    last_sync: Optional[str] = None,
    token: Optional[str] = None,
) -> int:
    """
    Fetch GitHub Security Advisories (GHSA) and upsert into vector store.

    Args:
        last_sync: ISO timestamp of last successful sync.
        token:     GitHub personal access token (higher rate limits).

    Returns:
        Number of chunks upserted.
    """
    log.info("Starting GitHub Advisories sync...")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params: dict[str, Any] = {
        "per_page": 100,
        "type": "reviewed",
        "direction": "desc",
    }
    if last_sync:
        params["updated_after"] = last_sync

    documents: list[Document] = []
    ids: list[str] = []
    page = 1

    with httpx.Client(timeout=HTTP_TIMEOUT) as client:
        while page <= 5:  # cap at 500 advisories per sync
            try:
                resp = client.get(
                    GHSA_API_URL, headers=headers, params={**params, "page": page}
                )
                resp.raise_for_status()
                advisories = resp.json()
            except httpx.HTTPError as exc:
                log.error("GitHub Advisories API error: %s", exc)
                break

            if not advisories:
                break

            for advisory in advisories:
                ghsa_id = advisory.get("ghsa_id", "UNKNOWN")
                summary = advisory.get("summary", "")
                description = advisory.get("description", "") or summary
                severity = advisory.get("severity", "unknown").title()
                cwe_ids = [c["cwe_id"] for c in advisory.get("cwes", [])]

                package_info = ""
                for vuln in advisory.get("vulnerabilities", [])[:3]:
                    pkg = vuln.get("package", {})
                    name = pkg.get("name", "")
                    eco = pkg.get("ecosystem", "")
                    ver = vuln.get("vulnerable_version_range", "")
                    if name:
                        package_info += f"{eco}/{name} {ver}; "

                text = (
                    f"{ghsa_id} -- {summary}\n"
                    f"Severity: {severity}\n"
                    f"CWEs: {', '.join(cwe_ids) or 'None'}\n"
                    f"Affected: {package_info or 'Unknown'}\n\n"
                    f"{description[:800]}"
                )
                for chunk_idx, chunk in enumerate(chunk_text(text)):
                    doc_id = f"ghsa_{ghsa_id.replace('-', '_')}_{chunk_idx}"
                    documents.append(Document(
                        page_content=chunk,
                        metadata={
                            "source": "GHSA",
                            "ghsa_id": ghsa_id,
                            "severity": severity,
                            "cwe_ids": json.dumps(cwe_ids),
                            "chunk_index": chunk_idx,
                        },
                    ))
                    ids.append(doc_id)

            if 'rel="next"' not in resp.headers.get("Link", ""):
                break
            page += 1
            time.sleep(0.3)

    _add_to_db(documents, ids)
    log.info("GitHub Advisories sync complete: %d chunks", len(documents))
    return len(documents)


# ---------------------------------------------------------------------------
# Combined sync job
# ---------------------------------------------------------------------------

def run_sync(github_token: Optional[str] = None) -> dict[str, int]:
    """
    Run the full sync pipeline (NVD + GHSA).
    Called by the scheduler; can also be imported directly.

    Returns:
        Dict of {source: chunks_upserted}
    """
    log.info("=== VulnScan sync job started at %s ===", now_iso())
    state = load_state()
    results: dict[str, int] = {}

    try:
        results["nvd"] = sync_nvd(last_sync=state.get("last_nvd_sync"))
        state["last_nvd_sync"] = now_iso()
        state["total_cves_synced"] = state.get("total_cves_synced", 0) + results["nvd"]
    except Exception as exc:
        log.error("NVD sync failed: %s", exc)
        results["nvd"] = 0

    try:
        results["ghsa"] = sync_github_advisories(
            last_sync=state.get("last_ghsa_sync"),
            token=github_token,
        )
        state["last_ghsa_sync"] = now_iso()
        state["total_advisories_synced"] = (
            state.get("total_advisories_synced", 0) + results["ghsa"]
        )
    except Exception as exc:
        log.error("GHSA sync failed: %s", exc)
        results["ghsa"] = 0

    save_state(state)
    new_chunks = sum(results.values())
    log.info("=== Sync complete. %d new chunks. State saved. ===", new_chunks)

    # Invalidate query cache so next retrieve() calls see the new data
    if new_chunks > 0:
        try:
            from rag.retrieve import clear_cache
            clear_cache()
            log.info("Query cache cleared after sync (%d new chunks).", new_chunks)
        except ImportError:
            pass  # retrieve not yet loaded -- cache will be empty anyway

    return results


def run_scheduler(github_token: Optional[str] = None) -> None:
    """Block and run sync every SYNC_INTERVAL_HOURS hours."""
    log.info("Scheduler started (every %d hours).", SYNC_INTERVAL_HOURS)
    run_sync(github_token=github_token)  # run immediately on start
    schedule.every(SYNC_INTERVAL_HOURS).hours.do(run_sync, github_token=github_token)
    while True:
        schedule.run_pending()
        time.sleep(60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description="VulnScan RAG Continuous Sync")
    parser.add_argument("--schedule", action="store_true",
                        help="Run on a recurring schedule")
    parser.add_argument("--source", choices=["nvd", "ghsa", "all"], default="all")
    args = parser.parse_args()

    gh_token = os.environ.get("GITHUB_TOKEN")

    if args.schedule:
        run_scheduler(github_token=gh_token)
    elif args.source == "nvd":
        state = load_state()
        sync_nvd(last_sync=state.get("last_nvd_sync"))
    elif args.source == "ghsa":
        state = load_state()
        sync_github_advisories(last_sync=state.get("last_ghsa_sync"), token=gh_token)
    else:
        run_sync(github_token=gh_token)
