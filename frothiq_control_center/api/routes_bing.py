"""WebOps Analytics — Microsoft Bing Webmaster Tools API integration.

API key stored at /var/lib/mc3/bing-api-key.txt (plain text, single line).
Obtain from: https://www.bing.com/webmasters/api.aspx
"""
import datetime
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .routes_auth import require_super_admin

router = APIRouter(prefix="/analytics/bing", tags=["analytics-bing"])

BING_KEY_FILE = Path("/var/lib/mc3/bing-api-key.txt")
BING_BASE = "https://ssl.bing.com/webmaster/api.svc/json"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _key() -> str:
    if not BING_KEY_FILE.exists():
        raise HTTPException(503, "Bing Webmaster API key not configured")
    try:
        val = BING_KEY_FILE.read_text().strip()
    except PermissionError:
        raise HTTPException(503, f"Bing API key file is not readable — fix ownership: chown frothiq {BING_KEY_FILE}")
    if not val:
        raise HTTPException(503, "Bing Webmaster API key not configured")
    return val


def _bing_get(method: str, params: dict, key: str | None = None) -> dict:
    """GET request to the Bing Webmaster JSON API."""
    k = key or _key()
    p = {"apikey": k, **params}
    url = f"{BING_BASE}/{method}?{urllib.parse.urlencode(p)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            msg = json.loads(raw).get("Message") or raw[:300]
        except Exception:
            msg = raw[:300]
        raise HTTPException(exc.code, f"Bing API error: {msg}") from exc


def _bing_post(method: str, body: dict, key: str | None = None) -> dict:
    """POST request to the Bing Webmaster JSON API."""
    k = key or _key()
    url = f"{BING_BASE}/{method}?apikey={urllib.parse.quote(k)}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8", "Accept": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        raw = resp.read()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            msg = json.loads(raw).get("Message") or raw[:300]
        except Exception:
            msg = raw[:300]
        raise HTTPException(exc.code, f"Bing API error: {msg}") from exc


def _parse_ms_date(d: str | None) -> str | None:
    """Convert /Date(milliseconds)/ WCF format to ISO date string."""
    if not d:
        return None
    if d.startswith("/Date("):
        try:
            ms = int(d[6:d.index(")")])
            return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            return None
    return d


def _date_range(days: int) -> tuple[str, str]:
    end = datetime.date.today() - datetime.timedelta(days=1)
    start = end - datetime.timedelta(days=days - 1)
    return str(start), str(end)


# ── API Key Management ────────────────────────────────────────────────────────

@router.get("/key/status")
def key_status(_: dict = Depends(require_super_admin)):
    configured = BING_KEY_FILE.exists() and bool(BING_KEY_FILE.read_text().strip())
    return {"configured": configured}


class KeyBody(BaseModel):
    api_key: str


@router.post("/key")
def save_key(body: KeyBody, _: dict = Depends(require_super_admin)):
    if not body.api_key.strip():
        raise HTTPException(400, "API key cannot be empty")
    BING_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    BING_KEY_FILE.write_text(body.api_key.strip())
    BING_KEY_FILE.chmod(0o600)
    # Validate the key immediately
    try:
        _bing_get("GetUserSites", {}, key=body.api_key.strip())
    except HTTPException as exc:
        BING_KEY_FILE.unlink(missing_ok=True)
        raise HTTPException(400, f"Invalid API key: {exc.detail}") from exc
    return {"ok": True}


# ── Sites ─────────────────────────────────────────────────────────────────────

@router.get("/sites")
def list_sites(_: dict = Depends(require_super_admin)):
    data = _bing_get("GetUserSites", {})
    entries = data.get("d") or []
    sites = [
        {
            "url": e.get("Url", ""),
            "verified": e.get("VerificationState", 0) == 1,
            "id": e.get("Id"),
        }
        for e in (entries if isinstance(entries, list) else [])
    ]
    return {"sites": sites, "count": len(sites)}


# ── Traffic Overview ──────────────────────────────────────────────────────────

@router.get("/traffic")
def site_traffic(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    _: dict = Depends(require_super_admin),
):
    """Aggregate traffic by summing top-pages data for the period."""
    start, end = _date_range(days)
    data = _bing_get("GetTopPages", {
        "siteUrl": site_url,
        "startDate": start,
        "endDate": end,
        "country": "",
        "language": "",
        "pageNum": 0,
    })
    rows = data.get("d") or []
    if not isinstance(rows, list):
        rows = []

    total_clicks = sum(int(r.get("Clicks", 0) or 0) for r in rows)
    total_impressions = sum(int(r.get("Impressions", 0) or 0) for r in rows)
    avg_rank = (
        sum(float(r.get("AvgClickRank", 0) or 0) for r in rows) / len(rows)
        if rows else 0.0
    )
    avg_impression_rank = (
        sum(float(r.get("AvgImpressionRank", 0) or 0) for r in rows) / len(rows)
        if rows else 0.0
    )
    ctr = (total_clicks / total_impressions * 100) if total_impressions else 0.0

    return {
        "summary": {
            "clicks": total_clicks,
            "impressions": total_impressions,
            "ctr": round(ctr, 2),
            "avg_click_rank": round(avg_rank, 1),
            "avg_impression_rank": round(avg_impression_rank, 1),
            "pages_tracked": len(rows),
        },
        "period": {"start": start, "end": end, "days": days},
    }


# ── Top Keywords ──────────────────────────────────────────────────────────────

@router.get("/keywords")
def top_keywords(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    page: int = Query(0, ge=0),
    _: dict = Depends(require_super_admin),
):
    start, end = _date_range(days)
    data = _bing_get("GetTopKeywords", {
        "siteUrl": site_url,
        "startDate": start,
        "endDate": end,
        "country": "",
        "language": "",
        "pageNum": page,
    })
    rows = data.get("d") or []
    if not isinstance(rows, list):
        rows = []
    result = [
        {
            "query": r.get("Query", ""),
            "impressions": int(r.get("Impressions", 0) or 0),
            "clicks": int(r.get("Clicks", 0) or 0),
            "ctr": round(
                int(r.get("Clicks", 0) or 0) / max(int(r.get("Impressions", 1) or 1), 1) * 100, 1
            ),
            "avg_rank": round(float(r.get("AvgClickRank", 0) or 0), 1),
            "avg_impression_rank": round(float(r.get("AvgImpressionRank", 0) or 0), 1),
        }
        for r in rows
        if r.get("Query")
    ]
    return {"rows": result, "count": len(result), "page": page}


# ── Top Pages ─────────────────────────────────────────────────────────────────

@router.get("/pages")
def top_pages(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    page: int = Query(0, ge=0),
    _: dict = Depends(require_super_admin),
):
    start, end = _date_range(days)
    data = _bing_get("GetTopPages", {
        "siteUrl": site_url,
        "startDate": start,
        "endDate": end,
        "country": "",
        "language": "",
        "pageNum": page,
    })
    rows = data.get("d") or []
    if not isinstance(rows, list):
        rows = []
    result = [
        {
            "url": r.get("Url", ""),
            "impressions": int(r.get("Impressions", 0) or 0),
            "clicks": int(r.get("Clicks", 0) or 0),
            "ctr": round(
                int(r.get("Clicks", 0) or 0) / max(int(r.get("Impressions", 1) or 1), 1) * 100, 1
            ),
            "avg_rank": round(float(r.get("AvgClickRank", 0) or 0), 1),
        }
        for r in rows
        if r.get("Url")
    ]
    return {"rows": result, "count": len(result), "page": page}


# ── Crawl Stats & Issues ──────────────────────────────────────────────────────

@router.get("/crawl")
def crawl_stats(
    site_url: str = Query(...),
    _: dict = Depends(require_super_admin),
):
    stats_data = _bing_get("GetCrawlStats", {"siteUrl": site_url})
    issues_data = _bing_get("GetCrawlIssues", {"siteUrl": site_url})

    raw_stats = stats_data.get("d") or {}
    raw_issues = issues_data.get("d") or []

    issues = []
    for entry in (raw_issues if isinstance(raw_issues, list) else []):
        url = entry.get("Url", "")
        for err in entry.get("CrawlErrors", []):
            issues.append({
                "url": url,
                "code": err.get("Error") or err.get("StatusCode", 0),
                "text": err.get("ErrorText") or err.get("StatusText", "Unknown"),
            })

    stats = {}
    if isinstance(raw_stats, dict):
        stats = {
            "crawled_pages": int(raw_stats.get("CrawledPages", 0) or 0),
            "crawl_errors": int(raw_stats.get("CrawlErrors", 0) or 0),
            "blocked_by_robots": int(raw_stats.get("BlockedByRobots", raw_stats.get("CrawlBlockedByRobots", 0)) or 0),
            "blocked_by_noindex": int(raw_stats.get("BlockedByNoIndex", raw_stats.get("CrawlBlockedByNoIndex", 0)) or 0),
            "in_index": int(raw_stats.get("InIndex", 0) or 0),
            "inbound_links": int(raw_stats.get("InboundLinks", 0) or 0),
            "crawl_progress": int(raw_stats.get("CrawlProgress", 0) or 0),
        }
    else:
        stats = {
            "crawled_pages": 0, "crawl_errors": 0, "blocked_by_robots": 0,
            "blocked_by_noindex": 0, "in_index": 0, "inbound_links": 0, "crawl_progress": 0,
        }

    return {"stats": stats, "issues": issues[:100], "issue_count": len(issues)}


# ── Sitemaps ──────────────────────────────────────────────────────────────────

@router.get("/sitemaps")
def list_sitemaps(
    site_url: str = Query(...),
    _: dict = Depends(require_super_admin),
):
    data = _bing_get("GetSitemaps", {"siteUrl": site_url})
    raw = data.get("d") or []
    sitemaps = []
    for s in (raw if isinstance(raw, list) else []):
        contents = s.get("ContentsCount") or []
        total_urls = sum(c.get("Count", 0) for c in (contents if isinstance(contents, list) else []))
        sitemaps.append({
            "url": s.get("Url", ""),
            "is_default": s.get("IsDefault", False),
            "last_crawled": _parse_ms_date(s.get("LastCrawled")),
            "submitted": _parse_ms_date(s.get("SubmittedUtc")),
            "discovered": _parse_ms_date(s.get("DiscoveredUtc")),
            "url_count": total_urls,
        })
    return {"sitemaps": sitemaps, "count": len(sitemaps)}


class SitemapBody(BaseModel):
    site_url: str
    feed_url: str


@router.post("/sitemaps/submit")
def submit_sitemap(body: SitemapBody, _: dict = Depends(require_super_admin)):
    _bing_post("SubmitSitemap", {"siteUrl": body.site_url, "feedUrl": body.feed_url})
    return {"ok": True, "feed_url": body.feed_url}


@router.post("/sitemaps/remove")
def remove_sitemap(body: SitemapBody, _: dict = Depends(require_super_admin)):
    _bing_post("RemoveSitemap", {"siteUrl": body.site_url, "feedUrl": body.feed_url})
    return {"ok": True, "feed_url": body.feed_url}


# ── URL Submission ────────────────────────────────────────────────────────────

class UrlSubmitBody(BaseModel):
    site_url: str
    urls: list[str]


@router.post("/url/submit")
def submit_urls(body: UrlSubmitBody, _: dict = Depends(require_super_admin)):
    if not body.urls:
        raise HTTPException(400, "urls list is empty")
    if len(body.urls) > 500:
        raise HTTPException(400, "Maximum 500 URLs per batch")

    if len(body.urls) == 1:
        result = _bing_post("SubmitUrl", {"siteUrl": body.site_url, "url": body.urls[0]})
    else:
        result = _bing_post("SubmitUrlBatch", {"siteUrl": body.site_url, "urlList": body.urls})

    quota_used = result.get("d") if result else None
    return {"ok": True, "submitted": len(body.urls), "quota_remaining": quota_used}


# ── URL Info ──────────────────────────────────────────────────────────────────

@router.get("/url/info")
def url_info(
    site_url: str = Query(...),
    url: str = Query(...),
    _: dict = Depends(require_super_admin),
):
    data = _bing_get("GetUrlInfo", {"siteUrl": site_url, "url": url})
    raw = data.get("d") or {}
    if not isinstance(raw, dict):
        return {"url": url, "raw": raw}
    return {
        "url": url,
        "http_code": raw.get("HttpCode"),
        "date_last_crawled": _parse_ms_date(raw.get("DateLastCrawled")),
        "is_cached": raw.get("IsCached"),
        "crawl_state": raw.get("CrawlState"),
        "in_sitemap": raw.get("InSitemap"),
        "linked_from_external": raw.get("LinkedFromExternal"),
        "linked_from_internal": raw.get("LinkedFromInternal"),
        "page_rank": raw.get("PageRank"),
        "redirected_to": raw.get("RedirectedTo"),
    }


# ── Backlinks ─────────────────────────────────────────────────────────────────

@router.get("/backlinks")
def backlinks(
    site_url: str = Query(...),
    offset: int = Query(0, ge=0),
    count: int = Query(50, ge=10, le=100),
    _: dict = Depends(require_super_admin),
):
    data = _bing_get("GetLinksToSite", {
        "siteUrl": site_url,
        "page": offset // count,
    })
    raw = data.get("d") or []
    links = [
        {
            "source_url": r.get("Url", ""),
            "target_url": r.get("Page", ""),
            "anchor_text": r.get("Anchor", ""),
        }
        for r in (raw if isinstance(raw, list) else [])
    ]
    return {"links": links, "count": len(links)}
