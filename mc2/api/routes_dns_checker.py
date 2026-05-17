"""
DNS Propagation Checker — query 25 global public resolvers in parallel using dnspython.
Mimics dnschecker.org: returns per-resolver status, resolved values, and response time.
"""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import dns.exception
import dns.rdatatype
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, Query

from .routes_auth import require_super_admin

router = APIRouter(prefix="/webops", tags=["dns-checker"])

# ---------------------------------------------------------------------------
# Resolver registry — 25 public resolvers across regions
# ---------------------------------------------------------------------------

RESOLVERS: list[dict] = [
    {"name": "Google",         "ip": "8.8.8.8",         "country": "United States", "flag": "🇺🇸", "provider": "Google"},
    {"name": "Google #2",      "ip": "8.8.4.4",         "country": "United States", "flag": "🇺🇸", "provider": "Google"},
    {"name": "Cloudflare",     "ip": "1.1.1.1",         "country": "Global",        "flag": "🌐",   "provider": "Cloudflare"},
    {"name": "Cloudflare #2",  "ip": "1.0.0.1",         "country": "Global",        "flag": "🌐",   "provider": "Cloudflare"},
    {"name": "Quad9",          "ip": "9.9.9.9",         "country": "United States", "flag": "🇺🇸", "provider": "Quad9"},
    {"name": "OpenDNS",        "ip": "208.67.222.222",  "country": "United States", "flag": "🇺🇸", "provider": "Cisco"},
    {"name": "OpenDNS #2",     "ip": "208.67.220.220",  "country": "United States", "flag": "🇺🇸", "provider": "Cisco"},
    {"name": "Level3",         "ip": "4.2.2.1",         "country": "United States", "flag": "🇺🇸", "provider": "Level3"},
    {"name": "Level3 #2",      "ip": "4.2.2.2",         "country": "United States", "flag": "🇺🇸", "provider": "Level3"},
    {"name": "Verisign",       "ip": "64.6.64.6",       "country": "United States", "flag": "🇺🇸", "provider": "Verisign"},
    {"name": "Verisign #2",    "ip": "64.6.65.6",       "country": "United States", "flag": "🇺🇸", "provider": "Verisign"},
    {"name": "Comodo",         "ip": "8.26.56.26",      "country": "United States", "flag": "🇺🇸", "provider": "Comodo"},
    {"name": "Neustar",        "ip": "156.154.70.1",    "country": "United States", "flag": "🇺🇸", "provider": "Neustar"},
    {"name": "NextDNS",        "ip": "45.90.28.0",      "country": "Global",        "flag": "🌐",   "provider": "NextDNS"},
    {"name": "Yandex",         "ip": "77.88.8.8",       "country": "Russia",        "flag": "🇷🇺", "provider": "Yandex"},
    {"name": "Yandex #2",      "ip": "77.88.8.1",       "country": "Russia",        "flag": "🇷🇺", "provider": "Yandex"},
    {"name": "DNS.WATCH",      "ip": "84.200.69.80",    "country": "Germany",       "flag": "🇩🇪", "provider": "DNS.WATCH"},
    {"name": "DNS.WATCH #2",   "ip": "84.200.70.40",    "country": "Germany",       "flag": "🇩🇪", "provider": "DNS.WATCH"},
    {"name": "AdGuard",        "ip": "176.103.130.130", "country": "Cyprus",        "flag": "🇨🇾", "provider": "AdGuard"},
    {"name": "AdGuard #2",     "ip": "176.103.130.131", "country": "Cyprus",        "flag": "🇨🇾", "provider": "AdGuard"},
    {"name": "114DNS",         "ip": "114.114.114.114", "country": "China",         "flag": "🇨🇳", "provider": "114DNS"},
    {"name": "AliDNS",         "ip": "223.5.5.5",       "country": "China",         "flag": "🇨🇳", "provider": "Alibaba"},
    {"name": "AliDNS #2",      "ip": "223.6.6.6",       "country": "China",         "flag": "🇨🇳", "provider": "Alibaba"},
    {"name": "Baidu",          "ip": "180.76.76.76",    "country": "China",         "flag": "🇨🇳", "provider": "Baidu"},
    {"name": "TWNIC",          "ip": "101.102.103.104", "country": "Taiwan",        "flag": "🇹🇼", "provider": "TWNIC"},
]

VALID_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_rdata(rdata) -> str:
    rdtype = rdata.rdtype
    if rdtype == dns.rdatatype.MX:
        return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
    if rdtype in (dns.rdatatype.NS, dns.rdatatype.CNAME, dns.rdatatype.PTR):
        return str(rdata.target).rstrip(".")
    if rdtype == dns.rdatatype.SOA:
        return f"{str(rdata.mname).rstrip('.')} serial={rdata.serial}"
    if rdtype == dns.rdatatype.TXT:
        return " ".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
    if rdtype == dns.rdatatype.SRV:
        return f"{rdata.priority} {rdata.weight} {rdata.port} {str(rdata.target).rstrip('.')}"
    return str(rdata)


def _sync_query(resolver_ip: str, domain: str, record_type: str, timeout: float) -> dict:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = timeout
    r.lifetime = timeout
    start = time.monotonic()
    try:
        answers = r.resolve(domain, record_type)
        elapsed = int((time.monotonic() - start) * 1000)
        values = sorted(_format_rdata(rdata) for rdata in answers)
        return {"raw_status": "ok", "values": values, "response_ms": elapsed}
    except dns.resolver.NXDOMAIN:
        return {"raw_status": "nxdomain",  "values": [], "response_ms": int((time.monotonic() - start) * 1000)}
    except dns.resolver.NoAnswer:
        return {"raw_status": "no_answer", "values": [], "response_ms": int((time.monotonic() - start) * 1000)}
    except dns.exception.Timeout:
        return {"raw_status": "timeout",   "values": [], "response_ms": int(timeout * 1000)}
    except Exception as exc:
        return {"raw_status": "error",     "values": [], "response_ms": int((time.monotonic() - start) * 1000), "detail": str(exc)[:120]}


def _classify(raw: dict, expected: str | None) -> str:
    s = raw["raw_status"]
    if s in ("nxdomain", "no_answer", "timeout", "error"):
        return s
    # Got records
    if not expected:
        return "propagated"
    norm = expected.strip().lower().rstrip(".")
    for v in raw["values"]:
        if norm in v.lower().rstrip("."):
            return "match"
    return "no_match"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.get("/dns/check")
async def dns_propagation_check(
    domain: str = Query(..., description="Domain to check (e.g. example.com)"),
    record_type: str = Query("A", description="DNS record type"),
    expected_value: str | None = Query(None, description="Optional value to match against"),
    _user=Depends(require_super_admin),
):
    # Normalise domain — strip protocol and path
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].rstrip(".")

    record_type = record_type.upper()
    if record_type not in VALID_TYPES:
        raise HTTPException(400, f"Unsupported record type. Valid: {', '.join(sorted(VALID_TYPES))}")

    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, _sync_query, res["ip"], domain, record_type, 3.0)
        for res in RESOLVERS
    ]
    raw_results = await asyncio.gather(*tasks)

    results = []
    counts: dict[str, int] = {}
    for resolver, raw in zip(RESOLVERS, raw_results):
        status = _classify(raw, expected_value)
        counts[status] = counts.get(status, 0) + 1
        results.append({
            "resolver": resolver,
            "status": status,
            "values": raw.get("values", []),
            "response_ms": raw.get("response_ms", 0),
        })

    resolved = sum(counts.get(s, 0) for s in ("propagated", "match", "no_match"))

    return {
        "domain": domain,
        "record_type": record_type,
        "expected_value": expected_value,
        "results": results,
        "summary": {
            "total": len(RESOLVERS),
            "resolved": resolved,
            **{k: counts.get(k, 0) for k in ("propagated", "match", "no_match", "nxdomain", "no_answer", "timeout", "error")},
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }
