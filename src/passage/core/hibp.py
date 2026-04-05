"""Have I Been Pwned (HIBP) integration using k-anonymity model.

Uses aiohttp for async batch requests when available; falls back to
urllib (stdlib) otherwise so the package works without external deps.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_HEADERS = {"User-Agent": "Passage-CLI/1.0"}


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def _parse_hibp_response(text: str, sha1_suffix: str) -> int:
    """Parse HIBP range response. Returns count (0 = not found, -1 = error)."""
    suffix_upper = sha1_suffix.upper()
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix_upper:
            return int(parts[1])
    return 0


# ---------------------------------------------------------------------------
# urllib-based sync check (no external deps)
# ---------------------------------------------------------------------------

def _check_password_sync(sha1_prefix: str, sha1_suffix: str, timeout: int = 10) -> int:
    url = HIBP_RANGE_URL.format(prefix=sha1_prefix)
    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode()
            return _parse_hibp_response(text, sha1_suffix)
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("HIBP request failed: %s", exc)
        return -1


# ---------------------------------------------------------------------------
# Async batch (uses aiohttp if available, else concurrent urllib)
# ---------------------------------------------------------------------------

def _try_aiohttp_batch(items: list[dict], timeout: int, concurrency: int) -> dict[int, int] | None:
    try:
        import aiohttp  # noqa: F401
    except ImportError:
        return None

    import aiohttp as _aiohttp

    async def _run() -> dict[int, int]:
        results: dict[int, int] = {}
        sem = asyncio.Semaphore(concurrency)

        async def check_one(item: dict, sess: _aiohttp.ClientSession) -> None:
            async with sem:
                prefix = item["sha1_prefix"]
                suffix = item["sha1_full"][5:]
                url = HIBP_RANGE_URL.format(prefix=prefix)
                try:
                    async with sess.get(
                        url,
                        headers=_HEADERS,
                        timeout=_aiohttp.ClientTimeout(total=timeout),
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            results[item["account_id"]] = _parse_hibp_response(text, suffix)
                        else:
                            results[item["account_id"]] = -1
                except Exception as exc:
                    logger.warning("HIBP aiohttp error: %s", exc)
                    results[item["account_id"]] = -1
                await asyncio.sleep(0.1)

        async with _aiohttp.ClientSession() as session:
            await asyncio.gather(*[check_one(i, session) for i in items])
        return results

    return asyncio.run(_run())


def _stdlib_batch(items: list[dict], timeout: int) -> dict[int, int]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results: dict[int, int] = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            ex.submit(
                _check_password_sync,
                item["sha1_prefix"],
                item["sha1_full"][5:],
                timeout,
            ): item["account_id"]
            for item in items
        }
        for fut in as_completed(futures):
            aid = futures[fut]
            try:
                results[aid] = fut.result()
            except Exception:
                results[aid] = -1
    return results


def run_batch_check(items: list[dict], timeout: int = 10) -> dict[int, int]:
    """Check multiple passwords against HIBP. Returns {account_id: breach_count}."""
    if not items:
        return {}
    result = _try_aiohttp_batch(items, timeout, concurrency=5)
    if result is None:
        result = _stdlib_batch(items, timeout)
    return result


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def should_refresh_breach_check(last_check_date: str | None, cache_days: int) -> bool:
    if not last_check_date:
        return True
    try:
        last = datetime.fromisoformat(last_check_date)
        return datetime.now() - last > timedelta(days=cache_days)
    except ValueError:
        return True
