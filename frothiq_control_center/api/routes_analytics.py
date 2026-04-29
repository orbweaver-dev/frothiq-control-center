"""WebOps Analytics — Google Search Console integration via service account JWT auth."""
import base64
import datetime
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .routes_auth import require_super_admin

router = APIRouter(prefix="/analytics", tags=["analytics"])

SA_KEY_FILE = Path("/var/lib/mc3/gsc-sa-key.json")
GSC_BASE = "https://searchconsole.googleapis.com/webmasters/v3"
GSC_V1_BASE = "https://searchconsole.googleapis.com/v1"


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_sa_token(scope: str) -> str:
    if not SA_KEY_FILE.exists():
        raise HTTPException(503, "GSC service account key not configured at /var/lib/mc3/gsc-sa-key.json")
    try:
        raw = SA_KEY_FILE.read_text()
    except PermissionError:
        raise HTTPException(503, f"GSC service account key is not readable — fix ownership: chown frothiq {SA_KEY_FILE}")
    try:
        key_data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(503, f"GSC service account key is malformed JSON: {exc}") from exc
    try:
        private_key = serialization.load_pem_private_key(key_data["private_key"].encode(), password=None)
    except (KeyError, Exception) as exc:
        raise HTTPException(503, f"GSC service account key has invalid private_key: {exc}") from exc
    now = int(time.time())
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": key_data["client_email"],
        "scope": scope,
        "aud": "https://oauth2.googleapis.com/token",
        "exp": now + 3600,
        "iat": now,
    }).encode()).rstrip(b"=")
    signing_input = header + b"." + payload
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    jwt = signing_input + b"." + base64.urlsafe_b64encode(sig).rstrip(b"=")
    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt.decode(),
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())["access_token"]
    except Exception as exc:
        raise HTTPException(503, f"SA token error: {exc}") from exc


def _gsc(method: str, path: str, token: str, body: dict | None = None, base: str = GSC_BASE) -> dict:
    url = f"{base}/{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers: dict = {"Authorization": f"Bearer {token}"}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        raw = resp.read()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            msg = json.loads(raw)["error"]["message"]
        except Exception:
            msg = raw[:300]
        raise HTTPException(exc.code, msg) from exc


def _date_range(days: int) -> tuple[str, str, str, str]:
    end = datetime.date.today() - datetime.timedelta(days=2)  # GSC lags ~2 days
    start = end - datetime.timedelta(days=days - 1)
    prev_end = start - datetime.timedelta(days=1)
    prev_start = prev_end - datetime.timedelta(days=days - 1)
    return str(start), str(end), str(prev_start), str(prev_end)


# ── Sites ─────────────────────────────────────────────────────────────────────

@router.get("/gsc/sites")
def list_gsc_sites(_: dict = Depends(require_super_admin)):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    data = _gsc("GET", "sites", token)
    entries = data.get("siteEntry", [])
    sites = [{"url": e["siteUrl"], "permission": e.get("permissionLevel", "unknown")} for e in entries]
    return {"sites": sites, "count": len(sites)}


# ── Performance ───────────────────────────────────────────────────────────────

@router.get("/gsc/performance")
def gsc_performance(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    start, end, prev_start, prev_end = _date_range(days)
    site_enc = urllib.parse.quote(site_url, safe="")

    current = _gsc("POST", f"sites/{site_enc}/searchAnalytics/query", token, {
        "startDate": start, "endDate": end, "dimensions": ["date"], "rowLimit": 90,
    })
    prev = _gsc("POST", f"sites/{site_enc}/searchAnalytics/query", token, {
        "startDate": prev_start, "endDate": prev_end, "rowLimit": 1,
    })

    rows = current.get("rows", [])
    chart = [{"date": r["keys"][0], "clicks": int(r["clicks"]), "impressions": int(r["impressions"])} for r in rows]

    total_clicks = sum(r["clicks"] for r in rows)
    total_impressions = sum(r["impressions"] for r in rows)
    avg_ctr = (total_clicks / total_impressions * 100) if total_impressions else 0.0
    avg_position = (sum(r["position"] for r in rows) / len(rows)) if rows else 0.0

    prev_rows = prev.get("rows", [])
    prev_clicks = sum(int(r["clicks"]) for r in prev_rows)
    prev_impressions = sum(int(r["impressions"]) for r in prev_rows)

    return {
        "summary": {
            "clicks": int(total_clicks),
            "impressions": int(total_impressions),
            "ctr": round(avg_ctr, 2),
            "position": round(avg_position, 1),
            "prev_clicks": prev_clicks,
            "prev_impressions": prev_impressions,
        },
        "chart": chart,
        "period": {"start": start, "end": end},
    }


# ── Queries ───────────────────────────────────────────────────────────────────

@router.get("/gsc/queries")
def gsc_queries(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    limit: int = Query(25, ge=5, le=100),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    start, end, _, __ = _date_range(days)
    site_enc = urllib.parse.quote(site_url, safe="")
    data = _gsc("POST", f"sites/{site_enc}/searchAnalytics/query", token, {
        "startDate": start, "endDate": end, "dimensions": ["query"], "rowLimit": limit,
    })
    rows = [{
        "query": r["keys"][0],
        "clicks": int(r["clicks"]),
        "impressions": int(r["impressions"]),
        "ctr": round(r["ctr"] * 100, 1),
        "position": round(r["position"], 1),
    } for r in data.get("rows", [])]
    return {"rows": rows, "count": len(rows)}


# ── Pages ─────────────────────────────────────────────────────────────────────

@router.get("/gsc/pages")
def gsc_pages(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    limit: int = Query(25, ge=5, le=100),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    start, end, _, __ = _date_range(days)
    site_enc = urllib.parse.quote(site_url, safe="")
    data = _gsc("POST", f"sites/{site_enc}/searchAnalytics/query", token, {
        "startDate": start, "endDate": end, "dimensions": ["page"], "rowLimit": limit,
    })
    rows = [{
        "page": r["keys"][0],
        "clicks": int(r["clicks"]),
        "impressions": int(r["impressions"]),
        "ctr": round(r["ctr"] * 100, 1),
        "position": round(r["position"], 1),
    } for r in data.get("rows", [])]
    return {"rows": rows, "count": len(rows)}


# ── Devices ───────────────────────────────────────────────────────────────────

@router.get("/gsc/devices")
def gsc_devices(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    start, end, _, __ = _date_range(days)
    site_enc = urllib.parse.quote(site_url, safe="")
    data = _gsc("POST", f"sites/{site_enc}/searchAnalytics/query", token, {
        "startDate": start, "endDate": end, "dimensions": ["device"], "rowLimit": 10,
    })
    rows = [{
        "device": r["keys"][0].capitalize(),
        "clicks": int(r["clicks"]),
        "impressions": int(r["impressions"]),
        "ctr": round(r["ctr"] * 100, 1),
        "position": round(r["position"], 1),
    } for r in data.get("rows", [])]
    return {"rows": rows}


# ── Countries ─────────────────────────────────────────────────────────────────

@router.get("/gsc/countries")
def gsc_countries(
    site_url: str = Query(...),
    days: int = Query(28, ge=7, le=90),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    start, end, _, __ = _date_range(days)
    site_enc = urllib.parse.quote(site_url, safe="")
    data = _gsc("POST", f"sites/{site_enc}/searchAnalytics/query", token, {
        "startDate": start, "endDate": end, "dimensions": ["country"], "rowLimit": 20,
    })
    rows = [{
        "country": r["keys"][0].upper(),
        "clicks": int(r["clicks"]),
        "impressions": int(r["impressions"]),
        "ctr": round(r["ctr"] * 100, 1),
        "position": round(r["position"], 1),
    } for r in data.get("rows", [])]
    return {"rows": rows}


# ── Sitemaps ──────────────────────────────────────────────────────────────────

@router.get("/gsc/sitemaps")
def gsc_sitemaps(
    site_url: str = Query(...),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    site_enc = urllib.parse.quote(site_url, safe="")
    data = _gsc("GET", f"sites/{site_enc}/sitemaps", token)
    sitemaps = []
    for s in data.get("sitemap", []):
        contents = s.get("contents", [])
        submitted = sum(c.get("submitted", 0) for c in contents)
        indexed = sum(c.get("indexed", 0) for c in contents)
        sitemaps.append({
            "path": s["path"],
            "lastSubmitted": s.get("lastSubmitted"),
            "lastDownloaded": s.get("lastDownloaded"),
            "isPending": s.get("isPending", False),
            "isSitemapsIndex": s.get("isSitemapsIndex", False),
            "errors": int(s.get("errors", 0)),
            "warnings": int(s.get("warnings", 0)),
            "submitted": submitted,
            "indexed": indexed,
        })
    return {"sitemaps": sitemaps, "count": len(sitemaps)}


class SitemapBody(BaseModel):
    site_url: str
    feed_path: str


@router.post("/gsc/sitemaps/submit")
def submit_sitemap(body: SitemapBody, _: dict = Depends(require_super_admin)):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters")
    site_enc = urllib.parse.quote(body.site_url, safe="")
    feed_enc = urllib.parse.quote(body.feed_path, safe="")
    _gsc("PUT", f"sites/{site_enc}/sitemaps/{feed_enc}", token)
    return {"ok": True, "feed_path": body.feed_path}


@router.post("/gsc/sitemaps/delete")
def delete_sitemap(body: SitemapBody, _: dict = Depends(require_super_admin)):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters")
    site_enc = urllib.parse.quote(body.site_url, safe="")
    feed_enc = urllib.parse.quote(body.feed_path, safe="")
    _gsc("DELETE", f"sites/{site_enc}/sitemaps/{feed_enc}", token)
    return {"ok": True, "feed_path": body.feed_path}


# ── URL Inspection ────────────────────────────────────────────────────────────

@router.get("/gsc/inspect")
def inspect_url(
    site_url: str = Query(...),
    inspection_url: str = Query(...),
    _: dict = Depends(require_super_admin),
):
    token = _get_sa_token("https://www.googleapis.com/auth/webmasters.readonly")
    data = _gsc("POST", "urlInspection/index:inspect", token, {
        "inspectionUrl": inspection_url,
        "siteUrl": site_url,
        "languageCode": "en",
    }, base=GSC_V1_BASE)

    result = data.get("inspectionResult", {})
    index_status = result.get("indexStatusResult", {})
    mobile = result.get("mobileUsabilityResult", {})
    rich_results = result.get("richResultsResult", {})

    return {
        "url": inspection_url,
        "verdict": index_status.get("verdict"),
        "coverageState": index_status.get("coverageState"),
        "robotsTxtState": index_status.get("robotsTxtState"),
        "indexingState": index_status.get("indexingState"),
        "lastCrawlTime": index_status.get("lastCrawlTime"),
        "pageFetchState": index_status.get("pageFetchState"),
        "googleCanonical": index_status.get("googleCanonical"),
        "userCanonical": index_status.get("userCanonical"),
        "crawledAs": index_status.get("crawledAs"),
        "referringUrls": index_status.get("referringUrls", [])[:5],
        "sitemap": index_status.get("sitemap", []),
        "mobile": {
            "verdict": mobile.get("verdict"),
            "issues": [i.get("issueType") for i in mobile.get("issues", [])],
        },
        "richResults": {
            "verdict": rich_results.get("verdict"),
            "detectedItems": [
                {"name": item.get("richResultType"), "issues": len(item.get("items", [{}])[0].get("issues", []))}
                for item in rich_results.get("detectedItems", [])
            ],
        },
    }
