"""
Chainlit UI for VulnScan AI.

Run locally:
  chainlit run app.py --host 0.0.0.0 --port 8000

Docker / Hugging Face Spaces (Docker SDK):
  chainlit run app.py --host 0.0.0.0 --port 7860

Requires OPENAI_API_KEY in the environment (use HF Space secrets in production).
"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlparse

import chainlit as cl

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _is_github_repo_url(text: str) -> bool:
    text = (text or "").strip()
    if not text.startswith("https://github.com/"):
        return False
    parsed = urlparse(text)
    if parsed.netloc != "github.com":
        return False
    parts = parsed.path.strip("/").split("/")
    return len(parts) >= 2


def _format_result(result: dict) -> str:
    lines = [
        "## Scan complete",
        "",
        f"**Status:** `{result.get('status', '')}`",
        f"**Clone path:** `{result.get('repo_path', '')}`",
        f"**Languages:** {', '.join(result.get('languages') or []) or '(none detected)'}",
        f"**Findings:** {len(result.get('findings') or [])}",
        "",
    ]
    findings = result.get("findings") or []
    if not findings:
        lines.append("_No findings returned (scan may have failed or agents returned empty)._")
        return "\n".join(lines)

    lines.append("### Findings (up to 40)")
    lines.append("")
    for i, f in enumerate(findings[:40], 1):
        title = getattr(f, "title", "") or "(no title)"
        sev = getattr(f, "severity", "")
        cwe = getattr(f, "cwe_id", "")
        path = getattr(f, "file_path", "")
        ln = getattr(f, "line_number", "")
        expl = (getattr(f, "explanation", "") or "")[:600]
        fix = (getattr(f, "suggested_fix", "") or "")[:400]
        lines.append(f"#### {i}. [{sev}] {cwe} — {title}")
        lines.append(f"- **File:** `{path}:{ln}`")
        if expl:
            lines.append(f"- **Explanation:** {expl}")
        if fix:
            lines.append(f"- **Suggested fix:** {fix}")
        lines.append("")
    if len(findings) > 40:
        lines.append(f"_…and {len(findings) - 40} more (truncated)._")
    return "\n".join(lines)


@cl.on_chat_start
async def on_chat_start() -> None:
    await cl.Message(
        content=(
            "# VulnScan AI\n\n"
            "Send a **public GitHub repository URL** to scan, for example:\n\n"
            "`https://github.com/owner/repo`\n\n"
            "**Requirements**\n"
            "- `OPENAI_API_KEY` must be set in the environment (Hugging Face: Space **Settings → Repository secrets**).\n"
            "- Large repositories may time out; use a **small** repo for testing.\n"
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    url = (message.content or "").strip()
    if not _is_github_repo_url(url):
        await cl.Message(
            content="Please send a valid `https://github.com/owner/repo` URL."
        ).send()
        return

    if not os.environ.get("OPENAI_API_KEY"):
        await cl.Message(
            content=(
                "Missing **OPENAI_API_KEY**. Add it to your environment or "
                "Hugging Face Space secrets."
            )
        ).send()
        return

    lines: list[str] = ["### Scan progress\n", "\n", "_Queued — starting pipeline …_\n"]
    status_msg = await cl.Message(content="".join(lines)).send()

    loop = asyncio.get_running_loop()
    progress_q: asyncio.Queue[tuple[str, str]] = asyncio.Queue()

    def sync_progress(step: str, detail: str) -> None:
        asyncio.run_coroutine_threadsafe(progress_q.put((step, detail)), loop)

    async def _flush_queue_into_lines() -> None:
        while True:
            try:
                step, detail = progress_q.get_nowait()
            except asyncio.QueueEmpty:
                break
            lines.append(f"- **{step}** — {detail}\n")
        try:
            await status_msg.update(content="".join(lines))
        except Exception:
            pass

    try:
        from orchestrator.graph import run_scan

        scan_task = asyncio.create_task(asyncio.to_thread(run_scan, url, sync_progress))

        while not scan_task.done():
            try:
                step, detail = await asyncio.wait_for(progress_q.get(), timeout=0.35)
                lines.append(f"- **{step}** — {detail}\n")
                try:
                    await status_msg.update(content="".join(lines))
                except Exception:
                    await cl.Message(content=f"**{step}** — {detail}").send()
            except asyncio.TimeoutError:
                continue

        await _flush_queue_into_lines()
        result = await scan_task
    except Exception as e:
        await _flush_queue_into_lines()
        await cl.Message(
            content=f"**Scan failed:** `{type(e).__name__}: {e}`"
        ).send()
        return

    await cl.Message(content=_format_result(result)).send()
