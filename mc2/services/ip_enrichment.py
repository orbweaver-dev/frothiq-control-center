"""
IP Enrichment Service — geolocation, reverse DNS, and bot/human classification.

Uses ip-api.com batch endpoint (free tier, no API key).
Results are cached in Redis with a 24-hour TTL so each IP is only queried once per day.
"""

from __future__ import annotations

import json
import logging

import httpx

logger = logging.getLogger(__name__)

_REDIS_PREFIX = "ip:info:"
_REDIS_TTL = 86_400  # 24 hours
_BATCH_URL = "http://ip-api.com/batch"
_FIELDS = "status,country,countryCode,regionName,city,isp,org,hosting,proxy,mobile,reverse"


async def enrich_ips(ip_list: list[str], redis) -> dict[str, dict]:
    """
    Return enrichment data for a list of IPs. Checks Redis cache first;
    uncached IPs are fetched from ip-api.com in a single batch request.
    """
    result: dict[str, dict] = {}
    uncached: list[str] = []

    for ip in ip_list:
        raw = await redis.get(f"{_REDIS_PREFIX}{ip}")
        if raw:
            try:
                result[ip] = json.loads(raw)
                continue
            except Exception:
                pass
        uncached.append(ip)

    if not uncached:
        return result

    # Fetch up to 100 at a time (ip-api.com batch limit)
    batch = uncached[:100]
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(
                _BATCH_URL,
                json=[{"query": ip, "fields": _FIELDS} for ip in batch],
            )
            if resp.status_code == 200:
                for i, entry in enumerate(resp.json()):
                    ip = batch[i] if i < len(batch) else None
                    if not ip:
                        continue
                    info = _parse(entry)
                    result[ip] = info
                    try:
                        await redis.setex(
                            f"{_REDIS_PREFIX}{ip}", _REDIS_TTL, json.dumps(info)
                        )
                    except Exception:
                        pass
    except Exception as exc:
        logger.warning("ip_enrichment: batch fetch failed: %s", exc)

    return result


def _parse(entry: dict) -> dict:
    hosting = bool(entry.get("hosting"))
    proxy   = bool(entry.get("proxy"))
    # Classify: datacenter/hosting IPs and proxies are almost certainly automated
    ip_type = "bot/server" if (hosting or proxy) else "human"
    return {
        "country":      entry.get("country", ""),
        "country_code": entry.get("countryCode", ""),
        "region":       entry.get("regionName", ""),
        "city":         entry.get("city", ""),
        "isp":          entry.get("isp", ""),
        "org":          entry.get("org", ""),
        "hostname":     entry.get("reverse", ""),
        "is_hosting":   hosting,
        "is_proxy":     proxy,
        "is_mobile":    bool(entry.get("mobile")),
        "type":         ip_type,
    }


def classify_ua(user_agent: str) -> str | None:
    """
    Supplement ip-api bot detection with user-agent string analysis.
    Returns 'bot' if the UA looks automated, None otherwise.
    """
    if not user_agent:
        return None
    ua = user_agent.lower()
    bot_signals = [
        "bot", "crawler", "spider", "scraper", "wget", "curl",
        "python-requests", "httpx", "go-http-client", "java/",
        "libwww", "okhttp", "axios", "node-fetch",
    ]
    return "bot" if any(s in ua for s in bot_signals) else None
