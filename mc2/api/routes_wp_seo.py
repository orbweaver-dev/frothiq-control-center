"""
WordPress SEO & Plugin Compliance — WP-CLI based analysis for sites on this server.

Covers:
  - Yoast SEO / RankMath detection and sitemap status
  - Plugin inventory with update + security flags
  - Plugin Check (PCP) style compliance scan
  - Robots.txt and sitemap.xml reachability
  - Meta tag extraction from the WordPress homepage
"""
from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/wp-seo", tags=["wp-seo"])
Auth = Annotated[TokenPayload, Depends(require_super_admin)]

WP_CLI = "/usr/local/bin/wp"
WP_USER = "www-data"  # user to run WP-CLI as


def _wp(path: str, args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run WP-CLI in the given WordPress docroot."""
    cmd = ["sudo", "-u", WP_USER, WP_CLI, "--path=" + path, "--allow-root"] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _safe_path(path: str) -> str:
    """Validate WordPress docroot path."""
    p = Path(path)
    if not p.is_absolute():
        raise HTTPException(400, "Path must be absolute")
    if not (p / "wp-config.php").exists() and not (p / "wp-settings.php").exists():
        raise HTTPException(400, f"No WordPress installation found at: {path}")
    return str(p)


def _http_get(url: str, timeout: int = 8) -> tuple[int, str]:
    """Simple HTTP GET — returns (status_code, body_preview)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MC3-SEO-Check/1.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read(4096).decode(errors="replace")
        return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


@router.get("/discover")
def discover_wp_sites(_: Auth = None):
    """Auto-discover WordPress installations under /home/*/public_html."""
    sites = []
    home = Path("/home")
    if not home.exists():
        return {"sites": []}
    for user_dir in sorted(home.iterdir()):
        for candidate in ["public_html", "www", "htdocs", "web"]:
            docroot = user_dir / candidate
            if (docroot / "wp-config.php").exists():
                rc, url_out, _ = _wp(str(docroot), ["option", "get", "siteurl"])
                sites.append({
                    "path": str(docroot),
                    "user": user_dir.name,
                    "url": url_out if rc == 0 else f"https://{user_dir.name}",
                })
                break
    return {"sites": sites, "count": len(sites)}


@router.get("/plugins")
def list_plugins(path: str = Query(..., description="Absolute WordPress docroot"), _: Auth = None):
    """List all plugins with status, version, and update availability."""
    safe = _safe_path(path)
    rc, out, err = _wp(safe, ["plugin", "list", "--format=json"])
    if rc != 0:
        raise HTTPException(500, err or "wp plugin list failed")
    try:
        plugins = json.loads(out)
    except json.JSONDecodeError:
        raise HTTPException(500, "Failed to parse plugin list JSON")

    # Flag known security / compliance issues
    PROBLEMATIC = {
        "query-monitor": "debug",
        "debug-bar": "debug",
        "log-deprecated-notices": "debug",
    }
    SEO_PLUGINS = {"wordpress-seo", "rank-math-seo", "all-in-one-seo-pack", "the-seo-framework"}
    SECURITY_PLUGINS = {"wordfence", "sucuri-scanner", "jetpack", "better-wp-security", "wp-cerber"}

    for p in plugins:
        name = p.get("name", "")
        p["is_seo"] = name in SEO_PLUGINS
        p["is_security"] = name in SECURITY_PLUGINS
        p["is_debug"] = name in PROBLEMATIC
        p["needs_update"] = p.get("update") == "available"

    seo = [p for p in plugins if p["is_seo"] and p.get("status") == "active"]
    active_count = sum(1 for p in plugins if p.get("status") == "active")
    needs_update = [p for p in plugins if p["needs_update"]]

    return {
        "plugins": plugins,
        "total": len(plugins),
        "active": active_count,
        "needs_update": len(needs_update),
        "seo_plugin": seo[0]["name"] if seo else None,
        "seo_active": bool(seo),
    }


@router.get("/seo-check")
def seo_check(path: str = Query(...), _: Auth = None):
    """Run a comprehensive SEO analysis on a WordPress site."""
    safe = _safe_path(path)

    # Get site URL
    rc, site_url, _ = _wp(safe, ["option", "get", "siteurl"])
    if rc != 0 or not site_url:
        raise HTTPException(500, "Could not read siteurl from WordPress options")
    site_url = site_url.rstrip("/")

    results: dict = {"url": site_url, "checks": []}

    # --- robots.txt ---
    robots_status, robots_body = _http_get(f"{site_url}/robots.txt")
    has_sitemap_in_robots = "sitemap" in robots_body.lower()
    results["checks"].append({
        "name": "robots.txt",
        "status": "ok" if robots_status == 200 else "fail",
        "message": f"HTTP {robots_status}" if robots_status != 200 else (
            "Found, mentions sitemap" if has_sitemap_in_robots else "Found, no sitemap directive"
        ),
        "detail": robots_body[:500] if robots_status == 200 else "",
    })

    # --- XML Sitemap ---
    for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]:
        sitemap_status, sitemap_body = _http_get(f"{site_url}{sitemap_path}")
        if sitemap_status == 200:
            url_count = sitemap_body.count("<url>") + sitemap_body.count("<sitemap>")
            results["checks"].append({
                "name": "XML Sitemap",
                "status": "ok",
                "message": f"{sitemap_path} reachable — ~{url_count} entries",
                "detail": sitemap_path,
            })
            results["sitemap_url"] = f"{site_url}{sitemap_path}"
            break
    else:
        results["checks"].append({
            "name": "XML Sitemap",
            "status": "warn",
            "message": "No sitemap found at /sitemap.xml, /sitemap_index.xml, or /wp-sitemap.xml",
            "detail": "",
        })
        results["sitemap_url"] = None

    # --- Meta tags from homepage ---
    hp_status, hp_body = _http_get(site_url)
    if hp_status == 200:
        import re
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", hp_body, re.IGNORECASE)
        desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', hp_body, re.IGNORECASE)
        og_match = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', hp_body, re.IGNORECASE)
        canonical_match = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', hp_body, re.IGNORECASE)

        title = (title_match.group(1).strip() if title_match else "")
        desc = (desc_match.group(1).strip() if desc_match else "")
        og_title = (og_match.group(1).strip() if og_match else "")
        canonical = (canonical_match.group(1).strip() if canonical_match else "")

        title_len = len(title)
        desc_len = len(desc)

        results["homepage"] = {
            "title": title,
            "title_length": title_len,
            "description": desc,
            "description_length": desc_len,
            "og_title": og_title,
            "canonical": canonical,
        }
        results["checks"].append({
            "name": "Page Title",
            "status": "ok" if 30 <= title_len <= 70 else ("warn" if title else "fail"),
            "message": f"{title_len} chars — {'optimal' if 30 <= title_len <= 70 else 'too short' if title_len < 30 else 'too long'}" if title else "Missing title tag",
            "detail": title,
        })
        results["checks"].append({
            "name": "Meta Description",
            "status": "ok" if 100 <= desc_len <= 165 else ("warn" if desc else "fail"),
            "message": f"{desc_len} chars — {'optimal' if 100 <= desc_len <= 165 else 'too short' if desc_len < 100 else 'too long'}" if desc else "Missing meta description",
            "detail": desc,
        })
        results["checks"].append({
            "name": "Open Graph Tags",
            "status": "ok" if og_title else "warn",
            "message": "og:title present" if og_title else "og:title missing — social sharing may not work",
            "detail": og_title,
        })
        results["checks"].append({
            "name": "Canonical URL",
            "status": "ok" if canonical else "warn",
            "message": "Canonical tag found" if canonical else "No canonical tag on homepage",
            "detail": canonical,
        })
    else:
        results["checks"].append({
            "name": "Homepage",
            "status": "fail",
            "message": f"Could not reach homepage — HTTP {hp_status}",
            "detail": "",
        })
        results["homepage"] = None

    # --- WordPress SEO plugin detection ---
    rc2, plugins_out, _ = _wp(safe, ["plugin", "list", "--status=active", "--format=json"])
    seo_plugin = None
    if rc2 == 0:
        try:
            active_plugins = json.loads(plugins_out)
            SEO_MAP = {
                "wordpress-seo": "Yoast SEO",
                "rank-math-seo": "RankMath SEO",
                "all-in-one-seo-pack": "All-in-One SEO",
                "the-seo-framework": "The SEO Framework",
                "seopress": "SEOPress",
            }
            for p in active_plugins:
                name = p.get("name", "")
                if name in SEO_MAP:
                    seo_plugin = {"name": name, "label": SEO_MAP[name], "version": p.get("version", "")}
                    break
        except json.JSONDecodeError:
            pass

    results["seo_plugin"] = seo_plugin
    results["checks"].append({
        "name": "SEO Plugin",
        "status": "ok" if seo_plugin else "warn",
        "message": f"{seo_plugin['label']} {seo_plugin['version']} active" if seo_plugin else "No SEO plugin detected — install Yoast SEO or RankMath",
        "detail": seo_plugin["name"] if seo_plugin else "",
    })

    # --- HTTPS check ---
    is_https = site_url.startswith("https://")
    results["checks"].append({
        "name": "HTTPS",
        "status": "ok" if is_https else "fail",
        "message": "Site uses HTTPS" if is_https else "Site URL does not use HTTPS",
        "detail": site_url,
    })

    # Score
    status_scores = {"ok": 2, "warn": 1, "fail": 0}
    total = sum(status_scores.get(c["status"], 0) for c in results["checks"])
    max_score = len(results["checks"]) * 2
    results["score"] = round((total / max_score) * 100) if max_score > 0 else 0

    return results


class SubmitUrlRequest(BaseModel):
    site_url: str
    url: str


@router.post("/submit-bing")
async def submit_url_bing(payload: SubmitUrlRequest, _: Auth = None):
    """Submit a URL to Bing Webmaster (delegates to /analytics/bing submit endpoint)."""
    from .routes_bing import _bing_post, _key
    key = _key()
    result = _bing_post("SubmitUrl", {"siteUrl": payload.site_url, "url": payload.url}, key=key)
    return {"ok": True, "result": result}
