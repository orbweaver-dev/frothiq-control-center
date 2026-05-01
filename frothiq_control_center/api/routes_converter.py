"""
Site Converter — WordPress & Joomla → Frappe migration engine.

Pipeline:
  discover  — detect CMS type/version from a public URL
  analyze   — enumerate content via CMS REST API (pages, posts, users, media)
  plan      — compute a DocType mapping and migration manifest
  stage     — validate the target Frappe site, list conflicts
  execute   — import content into Frappe via bench execute commands
"""

from __future__ import annotations

import base64
import html as html_mod
import json
import logging
import re
import textwrap
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from frothiq_control_center.auth import require_super_admin
from frothiq_control_center.api.routes_frappe import _bench, _sudo_cat, SITES_DIR

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/converter", tags=["converter"])

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class DiscoverRequest(BaseModel):
    url: str

class AnalyzeRequest(BaseModel):
    url: str
    cms: str                      # "wordpress" | "joomla"
    username: str = ""
    password: str = ""            # WP app password  OR  Joomla API token

class PlanRequest(BaseModel):
    analysis: dict
    target_site: str              # Frappe site name (on this bench)

class StageRequest(BaseModel):
    plan: dict
    target_site: str
    frappe_username: str = "Administrator"
    frappe_password: str = ""

class ExecuteRequest(BaseModel):
    plan: dict
    target_site: str
    frappe_username: str = "Administrator"
    frappe_password: str = ""
    dry_run: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def _b64(user: str, pwd: str) -> str:
    return base64.b64encode(f"{user}:{pwd}".encode()).decode()

def _strip_html(text: str) -> str:
    """Stdlib-only HTML stripper (no BS4 dependency for small strings)."""
    return re.sub(r"<[^>]+>", "", html_mod.unescape(text or "")).strip()

def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:80]

async def _get_json(client: httpx.AsyncClient, url: str, headers: dict = None) -> dict | list | None:
    try:
        r = await client.get(url, headers=headers or {}, timeout=_TIMEOUT, follow_redirects=True)
        if r.status_code == 200:
            ct = r.headers.get("content-type", "")
            if "json" in ct:
                return r.json()
    except Exception as exc:
        logger.debug("GET %s → %s", url, exc)
    return None

async def _paginate_wp(client: httpx.AsyncClient, url: str, headers: dict) -> list[dict]:
    """Collect all pages from a WP REST endpoint (handles X-WP-TotalPages)."""
    results: list[dict] = []
    page = 1
    while True:
        sep = "&" if "?" in url else "?"
        r = await client.get(
            f"{url}{sep}per_page=100&page={page}",
            headers=headers, timeout=_TIMEOUT, follow_redirects=True,
        )
        if r.status_code != 200:
            break
        try:
            batch = r.json()
        except Exception:
            break
        if not isinstance(batch, list) or not batch:
            break
        results.extend(batch)
        total_pages = int(r.headers.get("X-WP-TotalPages", 1))
        if page >= total_pages:
            break
        page += 1
    return results


# ---------------------------------------------------------------------------
# WordPress analysis helpers
# ---------------------------------------------------------------------------

async def _analyse_wordpress(url: str, username: str, password: str) -> dict:
    base = url
    auth_hdrs = {"Authorization": f"Basic {_b64(username, password)}"} if username else {}

    async with httpx.AsyncClient() as client:
        # Site info
        info = await _get_json(client, f"{base}/wp-json/", auth_hdrs) or {}

        # Content
        pages_raw  = await _paginate_wp(client, f"{base}/wp-json/wp/v2/pages?_fields=id,title,slug,content,status,date,link", auth_hdrs)
        posts_raw  = await _paginate_wp(client, f"{base}/wp-json/wp/v2/posts?_fields=id,title,slug,content,excerpt,status,date,categories,link", auth_hdrs)
        cats_raw   = await _paginate_wp(client, f"{base}/wp-json/wp/v2/categories?_fields=id,name,slug,description", auth_hdrs)
        tags_raw   = await _paginate_wp(client, f"{base}/wp-json/wp/v2/tags?_fields=id,name,slug", auth_hdrs)
        users_raw  = await _paginate_wp(client, f"{base}/wp-json/wp/v2/users?_fields=id,name,slug,email", auth_hdrs) if username else []
        media_raw  = await _paginate_wp(client, f"{base}/wp-json/wp/v2/media?_fields=id,title,source_url,mime_type", auth_hdrs)

        # Plugins (needs manage_options; tolerate 401)
        plugins_raw: list[dict] = []
        if username:
            r = await client.get(f"{base}/wp-json/wp/v2/plugins", headers=auth_hdrs, timeout=_TIMEOUT, follow_redirects=True)
            if r.status_code == 200:
                try:
                    plugins_raw = r.json()
                except Exception:
                    pass

    def _clean_post(p: dict) -> dict:
        raw_html = p.get("content", {}).get("rendered", "")
        return {
            "id": p.get("id"),
            "title": _strip_html(p.get("title", {}).get("rendered", "")),
            "slug": p.get("slug", ""),
            "excerpt": _strip_html(p.get("excerpt", {}).get("rendered", ""))[:500],
            "content": _strip_html(raw_html)[:3000],
            "raw_content_html": raw_html[:50000],
            "status": p.get("status", ""),
            "date": p.get("date", ""),
            "link": p.get("link", ""),
            "categories": p.get("categories", []),
        }

    pages = [_clean_post(p) for p in pages_raw]
    posts = [_clean_post(p) for p in posts_raw]
    cats  = [{"id": c["id"], "name": c.get("name",""), "slug": c.get("slug",""), "description": c.get("description","")} for c in cats_raw]
    tags  = [{"id": t["id"], "name": t.get("name",""), "slug": t.get("slug","")} for t in tags_raw]
    users = [{"id": u["id"], "name": u.get("name",""), "email": u.get("email","")} for u in users_raw]
    media = [{"id": m["id"], "title": _strip_html(m.get("title",{}).get("rendered","")), "url": m.get("source_url",""), "mime": m.get("mime_type","")} for m in media_raw]

    return {
        "cms": "wordpress",
        "source_url": url,
        "site_name": info.get("name", ""),
        "site_description": info.get("description", ""),
        "summary": {
            "pages": len(pages),
            "posts": len(posts),
            "categories": len(cats),
            "tags": len(tags),
            "users": len(users),
            "media": len(media),
            "plugins": len(plugins_raw),
        },
        "pages": pages,
        "posts": posts,
        "categories": cats,
        "tags": tags,
        "users": users,
        "media": media[:50],   # cap to avoid huge payloads
        "plugins": [{"name": p.get("name",""), "status": p.get("status","")} for p in plugins_raw],
    }


# ---------------------------------------------------------------------------
# Joomla analysis helpers
# ---------------------------------------------------------------------------

async def _analyse_joomla(url: str, username: str, token: str) -> dict:
    base = url
    # Joomla v4 REST API uses X-Joomla-Token header
    auth_hdrs = {"X-Joomla-Token": token} if token else {}

    async with httpx.AsyncClient() as client:
        articles_r = await _get_json(client, f"{base}/api/index.php/v1/content/articles?page[limit]=100", auth_hdrs)
        cats_r     = await _get_json(client, f"{base}/api/index.php/v1/content/categories?page[limit]=100", auth_hdrs)
        users_r    = await _get_json(client, f"{base}/api/index.php/v1/users?page[limit]=100", auth_hdrs) if token else None
        menus_r    = await _get_json(client, f"{base}/api/index.php/v1/menus/items?page[limit]=100", auth_hdrs)

    def _j_items(raw) -> list[dict]:
        if not raw or not isinstance(raw, dict):
            return []
        return raw.get("data", [])

    def _j_attr(item: dict, key: str) -> str:
        return (item.get("attributes", {}) or {}).get(key, "")

    articles_data = _j_items(articles_r)
    cats_data     = _j_items(cats_r)
    users_data    = _j_items(users_r) if users_r else []
    menus_data    = _j_items(menus_r) if menus_r else []

    articles = [
        {
            "id": item.get("id"),
            "title": _j_attr(item, "title"),
            "alias": _j_attr(item, "alias"),
            "introtext": _strip_html(_j_attr(item, "introtext"))[:1000],
            "fulltext":  _strip_html(_j_attr(item, "fulltext"))[:3000],
            "state": _j_attr(item, "state"),
            "catid": _j_attr(item, "catid"),
            "created": _j_attr(item, "created"),
        }
        for item in articles_data
    ]
    cats = [
        {
            "id": item.get("id"),
            "title": _j_attr(item, "title"),
            "alias": _j_attr(item, "alias"),
            "description": _strip_html(_j_attr(item, "description"))[:500],
        }
        for item in cats_data
    ]
    users = [
        {
            "id": item.get("id"),
            "name": _j_attr(item, "name"),
            "email": _j_attr(item, "email"),
        }
        for item in users_data
    ]
    menus = [
        {
            "id": item.get("id"),
            "title": _j_attr(item, "title"),
            "link": _j_attr(item, "link"),
        }
        for item in menus_data
    ]

    return {
        "cms": "joomla",
        "source_url": url,
        "site_name": "",
        "site_description": "",
        "summary": {
            "articles": len(articles),
            "categories": len(cats),
            "users": len(users),
            "menus": len(menus),
        },
        "articles": articles,
        "categories": cats,
        "users": users,
        "menus": menus,
    }


# ---------------------------------------------------------------------------
# Migration plan builder
# ---------------------------------------------------------------------------

def _build_plan(analysis: dict, target_site: str) -> dict:
    cms = analysis.get("cms", "unknown")
    steps: list[dict] = []
    warnings: list[str] = []

    if cms == "wordpress":
        cats = analysis.get("categories", [])
        posts = analysis.get("posts", [])
        pages = analysis.get("pages", [])
        users = analysis.get("users", [])
        media = analysis.get("media", [])
        plugins = analysis.get("plugins", [])

        if cats:
            steps.append({
                "step": "import_categories",
                "label": "Import Blog Categories",
                "doctype": "Blog Category",
                "count": len(cats),
                "items": [{"name": c["name"], "slug": c["slug"]} for c in cats],
            })
        if posts:
            steps.append({
                "step": "import_posts",
                "label": "Import Blog Posts",
                "doctype": "Blog Post",
                "count": len(posts),
                "items": [{"title": p["title"], "slug": p["slug"]} for p in posts[:20]],
            })
        if pages:
            steps.append({
                "step": "import_pages",
                "label": "Import Web Pages",
                "doctype": "Web Page",
                "count": len(pages),
                "items": [{"title": p["title"], "slug": p["slug"]} for p in pages[:20]],
            })
        if media:
            warnings.append(f"{len(media)} media files detected — media import is informational only; download and attach manually.")
        if plugins:
            active = [p["name"] for p in plugins if p.get("status") == "active"]
            if active:
                warnings.append(f"Active plugins: {', '.join(active[:8])}. Review which functionality needs to be replicated in Frappe.")
        if users:
            warnings.append(f"{len(users)} WordPress users found. User accounts will not be auto-created — assign content to Administrator.")

    elif cms == "joomla":
        cats = analysis.get("categories", [])
        articles = analysis.get("articles", [])
        users = analysis.get("users", [])

        if cats:
            steps.append({
                "step": "import_categories",
                "label": "Import Blog Categories",
                "doctype": "Blog Category",
                "count": len(cats),
                "items": [{"name": c["title"], "slug": c["alias"]} for c in cats],
            })
        if articles:
            steps.append({
                "step": "import_posts",
                "label": "Import Articles as Blog Posts",
                "doctype": "Blog Post",
                "count": len(articles),
                "items": [{"title": a["title"], "slug": a["alias"]} for a in articles[:20]],
            })
        if users:
            warnings.append(f"{len(users)} Joomla users found — user accounts will not be auto-created.")

    steps.append({
        "step": "publish",
        "label": "Set Frappe Site as Public",
        "doctype": None,
        "count": 1,
        "items": [],
    })

    return {
        "cms": cms,
        "source_url": analysis.get("source_url", ""),
        "site_name": analysis.get("site_name", ""),
        "target_site": target_site,
        "steps": steps,
        "warnings": warnings,
        "total_items": sum(s["count"] for s in steps),
        "analysis": analysis,
    }


# ---------------------------------------------------------------------------
# Frappe bench helpers for execution
# ---------------------------------------------------------------------------

def _bench_exec(site: str, code: str, timeout: int = 30) -> tuple[str, str, int]:
    """Run a Python snippet in Frappe context via bench execute."""
    one_liner = code.replace("\n", "; ").replace("\"", "\\\"")
    return _bench(["--site", site, "execute", "--args", f'"{one_liner}"'], timeout=timeout)


def _bench_python(site: str, python_code: str, timeout: int = 60) -> tuple[str, str, int]:
    """Run multi-line Python in Frappe context by writing to a tmp file and using bench execute."""
    import tempfile, os, subprocess
    # Write code to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
        f.write(python_code)
        tmp = f.name
    try:
        cmd = [
            "sudo", "-u", "frappe", "/usr/local/bin/frothiq-bench",
            "--site", site, "execute",
            f"exec(open('{tmp}').read())",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd="/tmp")
        return result.stdout, result.stderr, result.returncode
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _frappe_create_or_get(site: str, doctype: str, filters: dict, values: dict) -> tuple[bool, str]:
    """
    Insert a Frappe document if it doesn't exist. Returns (created, name).
    Uses bench execute for direct DB access.
    """
    filters_json = json.dumps(filters).replace("'", "\\'")
    values_json  = json.dumps({**filters, **values}).replace("'", "\\'")

    code = textwrap.dedent(f"""
import frappe
existing = frappe.db.get_value('{doctype}', {json.dumps(filters)}, 'name')
if existing:
    print('EXISTS:' + existing)
else:
    doc = frappe.get_doc({json.dumps({**filters, **values, 'doctype': doctype})})
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    print('CREATED:' + doc.name)
""").strip()

    with __import__("tempfile").NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
        f.write(code)
        tmp = f.name

    import subprocess, os
    try:
        cmd = [
            "sudo", "-u", "frappe", "/usr/local/bin/frothiq-bench",
            "--site", site, "execute",
            f"exec(open('{tmp}').read())",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd="/tmp")
        out = r.stdout + r.stderr
        for line in out.splitlines():
            if line.startswith("CREATED:"):
                return True, line[8:].strip()
            if line.startswith("EXISTS:"):
                return False, line[7:].strip()
        return False, f"error: {out[:200]}"
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# WordPress REST API enabler — mu-plugin injection for local sites
# ---------------------------------------------------------------------------

_MU_PLUGIN_FILENAME = "frothiq-migration-api.php"
_MU_PLUGIN_CONTENT = """\
<?php
/**
 * FrothIQ Migration — Temporary REST API enabler.
 * Created automatically by FrothIQ Control Center.
 * Removed when migration is complete.
 */
defined('ABSPATH') || exit;

// Any filter that returns WP_Error on rest_authentication_errors disables the API.
// Run at maximum priority (PHP_INT_MAX) so this overrides security plugins.
add_filter('rest_authentication_errors', function($result) {
    return ($result instanceof WP_Error) ? null : $result;
}, PHP_INT_MAX);
"""


class WpApiRequest(BaseModel):
    docroot: str


@router.post("/local-wp-enable-api")
async def local_wp_enable_api(req: WpApiRequest, _: str = Depends(require_super_admin)) -> dict:
    """Inject a must-use plugin that re-enables the WordPress REST API for migration."""
    import asyncio
    import subprocess as sp

    docroot = req.docroot.rstrip("/")
    mu_dir = f"{docroot}/wp-content/mu-plugins"
    plugin_path = f"{mu_dir}/{_MU_PLUGIN_FILENAME}"

    def _do() -> dict:
        r = sp.run(["sudo", "mkdir", "-p", mu_dir], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return {"ok": False, "error": f"mkdir failed: {r.stderr.strip()}"}

        r = sp.run(["sudo", "tee", plugin_path], input=_MU_PLUGIN_CONTENT,
                   capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return {"ok": False, "error": f"write failed: {r.stderr.strip()}"}

        # Match ownership to the docroot so WordPress can see the file
        stat_r = sp.run(["sudo", "stat", "-c", "%U:%G", docroot],
                        capture_output=True, text=True, timeout=5)
        if stat_r.returncode == 0:
            owner = stat_r.stdout.strip()
            sp.run(["sudo", "chown", owner, plugin_path], capture_output=True, timeout=5)

        return {"ok": True, "plugin_path": plugin_path}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do)


@router.post("/local-wp-disable-api")
async def local_wp_disable_api(req: WpApiRequest, _: str = Depends(require_super_admin)) -> dict:
    """Remove the must-use plugin created by local_wp_enable_api."""
    import asyncio
    import subprocess as sp

    docroot = req.docroot.rstrip("/")
    plugin_path = f"{docroot}/wp-content/mu-plugins/{_MU_PLUGIN_FILENAME}"

    def _do() -> dict:
        r = sp.run(["sudo", "rm", "-f", plugin_path], capture_output=True, timeout=10)
        return {"ok": r.returncode == 0}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do)


# ---------------------------------------------------------------------------
# Local site scanner — reads Apache vhosts, fingerprints DocumentRoots
# ---------------------------------------------------------------------------

def _read_file_safe(path: str) -> str:
    """Read a file via sudo cat, tolerating permission errors."""
    import subprocess
    try:
        r = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, timeout=5)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""

def _path_exists_safe(path: str) -> bool:
    import subprocess
    try:
        r = subprocess.run(["sudo", "stat", path], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def _detect_docroot_apps(docroot: str, servername: str, port: int) -> list[dict]:
    """Fingerprint a DocumentRoot and return detected applications."""
    apps: list[dict] = []
    proto = "https" if port == 443 else "http"
    base_url = f"{proto}://{servername}"

    # ── WordPress ──────────────────────────────────────────────────────────
    if _path_exists_safe(f"{docroot}/wp-config.php") or _path_exists_safe(f"{docroot}/wp-login.php"):
        version = ""
        ver_txt = _read_file_safe(f"{docroot}/wp-includes/version.php")
        m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", ver_txt)
        if m:
            version = m.group(1)
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "wordpress", "label": "WordPress",
            "version": version, "url": base_url,
            "convertible": True,
        })

    # ── Joomla! ────────────────────────────────────────────────────────────
    elif _path_exists_safe(f"{docroot}/configuration.php") and _path_exists_safe(f"{docroot}/components"):
        version = ""
        ver_xml = _read_file_safe(f"{docroot}/libraries/src/Version.php") or \
                  _read_file_safe(f"{docroot}/includes/defines.php")
        m = re.search(r"RELEASE\s*=\s*['\"]([^'\"]+)['\"]", ver_xml) or \
            re.search(r"JVERSION\s*=\s*['\"]([^'\"]+)['\"]", ver_xml)
        if m:
            version = m.group(1)
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "joomla", "label": "Joomla!",
            "version": version, "url": base_url,
            "convertible": True,
        })

    # ── phpMyAdmin ─────────────────────────────────────────────────────────
    elif (_path_exists_safe(f"{docroot}/config.inc.php") or _path_exists_safe(f"{docroot}/config.sample.inc.php")) \
         and _path_exists_safe(f"{docroot}/index.php") \
         and (_path_exists_safe(f"{docroot}/libraries") or _path_exists_safe(f"{docroot}/src")):
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "phpmyadmin", "label": "phpMyAdmin",
            "version": "", "url": base_url,
            "convertible": False,
        })

    # ── Roundcube Webmail ──────────────────────────────────────────────────
    elif _path_exists_safe(f"{docroot}/config/config.inc.php") and \
         _path_exists_safe(f"{docroot}/program/lib/Roundcube"):
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "roundcube", "label": "Roundcube Webmail",
            "version": "", "url": base_url,
            "convertible": False,
        })

    # ── Drupal ─────────────────────────────────────────────────────────────
    elif _path_exists_safe(f"{docroot}/core/lib/Drupal.php") or \
         (_path_exists_safe(f"{docroot}/includes/bootstrap.inc") and _path_exists_safe(f"{docroot}/sites")):
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "drupal", "label": "Drupal",
            "version": "", "url": base_url,
            "convertible": False,
        })

    # ── Laravel ────────────────────────────────────────────────────────────
    elif _path_exists_safe(f"{docroot}/../artisan") and _path_exists_safe(f"{docroot}/../app"):
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "laravel", "label": "Laravel",
            "version": "", "url": base_url,
            "convertible": False,
        })

    # ── Generic PHP site (public_html present, has index.php) ──────────────
    elif _path_exists_safe(f"{docroot}/index.php"):
        apps.append({
            "servername": servername, "docroot": docroot,
            "app": "php", "label": "PHP Site",
            "version": "", "url": base_url,
            "convertible": False,
        })

    return apps


def _scan_apache_vhosts() -> list[dict]:
    """Parse /etc/apache2/sites-enabled to get (servername, docroot, port) tuples."""
    import pathlib
    vhosts: list[dict] = []
    seen: set[str] = set()

    sites_dir = pathlib.Path("/etc/apache2/sites-enabled")
    if not sites_dir.exists():
        return vhosts

    for cf in sites_dir.iterdir():
        content = _read_file_safe(str(cf))
        if not content:
            continue
        # Group 1 = VirtualHost header (IP:port), Group 2 = block body
        for vh_header, block in re.findall(
            r'<VirtualHost([^>]*)>(.*?)</VirtualHost>', content, re.DOTALL | re.IGNORECASE
        ):
            port = 80
            m_port = re.search(r':(\d+)', vh_header)
            if m_port:
                port = int(m_port.group(1))
            sn = re.search(r'^\s*ServerName\s+(\S+)', block, re.MULTILINE | re.IGNORECASE)
            dr = re.search(r'^\s*DocumentRoot\s+(\S+)', block, re.MULTILINE | re.IGNORECASE)
            if sn and dr:
                name = sn.group(1).strip("\"'")
                root = dr.group(1).strip("\"'")
                key = f"{name}|{port}"
                if key not in seen:
                    seen.add(key)
                    vhosts.append({"servername": name, "docroot": root, "port": port})

    return vhosts


def _scan_nginx_vhosts() -> list[dict]:
    """Parse /etc/nginx/sites-enabled to get (servername, docroot, port) tuples."""
    import pathlib
    vhosts: list[dict] = []
    seen: set[str] = set()

    sites_dir = pathlib.Path("/etc/nginx/sites-enabled")
    if not sites_dir.exists():
        return vhosts

    for cf in sites_dir.iterdir():
        if cf.name.startswith('.'):
            continue
        content = _read_file_safe(str(cf))
        if not content:
            continue

        lines = content.splitlines()
        i = 0
        while i < len(lines):
            if re.match(r'^\s*server\s*\{', lines[i]):
                depth = 0
                block_lines: list[str] = []
                while i < len(lines):
                    line = lines[i]
                    depth += line.count('{') - line.count('}')
                    block_lines.append(line)
                    i += 1
                    if depth <= 0:
                        break

                block = '\n'.join(block_lines)

                ports = [int(m.group(1)) for m in re.finditer(r'\blisten\s+(?:\S+:)?(\d+)', block)]
                port = 443 if 443 in ports else (ports[0] if ports else 80)

                sn_match = re.search(r'\bserver_name\s+([^;]+);', block)
                root_match = re.search(r'^\s*root\s+(\S+)\s*;', block, re.MULTILINE)

                if sn_match and root_match:
                    names = sn_match.group(1).split()
                    root = root_match.group(1).strip("\"'")
                    name = next(
                        (n for n in names if not n.startswith('_') and '*' not in n and n != 'localhost'),
                        None,
                    )
                    if name:
                        key = f"{name}|{port}"
                        if key not in seen:
                            seen.add(key)
                            vhosts.append({"servername": name, "docroot": root, "port": port})
            else:
                i += 1

    return vhosts


@router.get("/local-scan")
async def scan_local_sites(_: str = Depends(require_super_admin)) -> dict:
    """
    Scan local Apache and Nginx virtual hosts for installed CMS and web applications.
    Results are grouped by domain name; HTTPS vhost takes precedence over HTTP.
    """
    import asyncio

    def _scan() -> list[dict]:
        all_vhosts = _scan_apache_vhosts() + _scan_nginx_vhosts()

        # Deduplicate by domain: one entry per servername, HTTPS preferred over HTTP
        domain_vhosts: dict[str, dict] = {}
        for vhost in all_vhosts:
            name = vhost["servername"]
            if name not in domain_vhosts or vhost["port"] == 443:
                domain_vhosts[name] = vhost

        sites: list[dict] = []
        for vhost in domain_vhosts.values():
            apps = _detect_docroot_apps(vhost["docroot"], vhost["servername"], vhost["port"])
            sites.extend(apps)
        return sites

    loop = asyncio.get_event_loop()
    sites = await loop.run_in_executor(None, _scan)
    return {"sites": sites, "total": len(sites)}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/discover")
async def discover_site(req: DiscoverRequest, _: str = Depends(require_super_admin)) -> dict:
    """Auto-detect CMS type and version from a URL."""
    url = _normalise(req.url)
    signals: list[str] = []
    detected_cms: str | None = None
    rest_api = False
    wp_info: dict = {}

    async with httpx.AsyncClient() as client:
        # ── WordPress REST API ──────────────────────────────────────────────
        try:
            r = await client.get(f"{url}/wp-json/", timeout=_TIMEOUT, follow_redirects=True)
            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                data = r.json()
                if isinstance(data, dict) and ("namespaces" in data or "name" in data):
                    detected_cms = "wordpress"
                    rest_api = True
                    wp_info = {
                        "name": data.get("name", ""),
                        "description": data.get("description", ""),
                        "gmt_offset": data.get("gmt_offset", 0),
                        "namespaces": data.get("namespaces", []),
                    }
                    signals.append("WP REST API /wp-json/ responded")
        except Exception:
            pass

        # ── WordPress HTML signals ──────────────────────────────────────────
        homepage_body = ""
        if not detected_cms:
            try:
                r = await client.get(url, timeout=_TIMEOUT, follow_redirects=True)
                homepage_body = r.text
                if "wp-content" in homepage_body or "wp-includes" in homepage_body:
                    detected_cms = "wordpress"
                    signals.append("WordPress fingerprint in page HTML (wp-content/wp-includes)")
                elif "wp-login.php" in homepage_body:
                    detected_cms = "wordpress"
                    signals.append("WordPress login link detected in HTML")
                elif re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress', homepage_body, re.I):
                    detected_cms = "wordpress"
                    signals.append("WordPress generator meta tag detected")
            except Exception:
                pass

        # ── WordPress xmlrpc probe (fires only if HTML check also missed) ───
        if not detected_cms:
            try:
                r = await client.get(f"{url}/xmlrpc.php", timeout=_TIMEOUT, follow_redirects=True)
                if r.status_code == 405 or (r.status_code == 200 and "XML-RPC" in r.text):
                    detected_cms = "wordpress"
                    signals.append("WordPress XML-RPC endpoint detected at /xmlrpc.php")
            except Exception:
                pass

        # ── Joomla REST API ─────────────────────────────────────────────────
        # Require HTTP 200 + JSON with Joomla-specific structure.
        # Do NOT treat 401/403 as evidence — any web server can return those
        # for an unknown path, causing WordPress sites to be mis-detected.
        if not detected_cms:
            try:
                r = await client.get(f"{url}/api/index.php/v1/", timeout=_TIMEOUT, follow_redirects=True)
                if r.status_code == 200:
                    ct = r.headers.get("content-type", "")
                    if "json" in ct:
                        try:
                            jdata = r.json()
                            # Joomla v4 API root returns {"data": [...], "links": {...}}
                            if isinstance(jdata, dict) and ("data" in jdata or "links" in jdata):
                                detected_cms = "joomla"
                                rest_api = True
                                signals.append("Joomla v4 REST API at /api/index.php/v1/ confirmed (HTTP 200 + JSON)")
                        except Exception:
                            pass
            except Exception:
                pass

        # ── Joomla HTML signals ─────────────────────────────────────────────
        if not detected_cms:
            try:
                body = homepage_body or (await client.get(url, timeout=_TIMEOUT, follow_redirects=True)).text
                body_lower = body.lower()
                has_joomla_tag = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla', body, re.I)
                has_joomla_text = "joomla" in body_lower and "/administrator" in body_lower
                if has_joomla_tag or has_joomla_text:
                    detected_cms = "joomla"
                    signals.append("Joomla fingerprint in page HTML")
            except Exception:
                pass

    if not detected_cms:
        detected_cms = "unknown"
        signals.append("No recognizable CMS detected — may be a custom or unsupported platform")

    return {
        "url": url,
        "cms": detected_cms,
        "rest_api_available": rest_api,
        "signals": signals,
        "wp_info": wp_info,
    }


@router.post("/analyze")
async def analyze_site(req: AnalyzeRequest, _: str = Depends(require_super_admin)) -> dict:
    """Enumerate content from a WordPress or Joomla site via its REST API."""
    url = _normalise(req.url)
    if req.cms == "wordpress":
        return await _analyse_wordpress(url, req.username, req.password)
    elif req.cms == "joomla":
        return await _analyse_joomla(url, req.username, req.password)
    raise HTTPException(400, f"Unsupported CMS type: {req.cms!r}")


@router.post("/plan")
async def plan_migration(req: PlanRequest, _: str = Depends(require_super_admin)) -> dict:
    """Compute a migration manifest from an analysis result."""
    return _build_plan(req.analysis, req.target_site)


@router.post("/stage")
async def stage_migration(req: StageRequest, _: str = Depends(require_super_admin)) -> dict:
    """Validate Frappe target site and check for existing content conflicts."""
    site = req.target_site

    # Verify site exists
    site_config_path = SITES_DIR / site / "site_config.json"
    content = _sudo_cat(str(site_config_path))
    if not content:
        raise HTTPException(404, f"Site '{site}' not found on this bench")

    plan = req.plan
    checks: list[dict] = []

    # Check each doctype involved
    doctypes_used = list({s["doctype"] for s in plan.get("steps", []) if s.get("doctype")})
    for dt in doctypes_used:
        # Check if the DocType module exists in Frappe
        import tempfile, os, subprocess
        code = textwrap.dedent(f"""
import frappe
try:
    meta = frappe.get_meta('{dt}')
    existing = frappe.db.count('{dt}')
    print(f'OK:{dt}:{{existing}}')
except Exception as e:
    print(f'MISSING:{dt}:{{e}}')
""").strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write(code)
            tmp = f.name
        try:
            cmd = ["sudo", "-u", "frappe", "/usr/local/bin/frothiq-bench",
                   "--site", site, "execute", f"exec(open('{tmp}').read())"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd="/tmp")
            out = (r.stdout + r.stderr).strip()
            for line in out.splitlines():
                if line.startswith(f"OK:{dt}:"):
                    existing_count = int(line.split(":")[-1])
                    checks.append({"doctype": dt, "available": True, "existing_count": existing_count,
                                   "warning": f"{existing_count} existing {dt} records will be skipped (no duplicates)" if existing_count else None})
                elif line.startswith(f"MISSING:{dt}:"):
                    checks.append({"doctype": dt, "available": False, "existing_count": 0,
                                   "warning": f"DocType '{dt}' not found — install the required Frappe app first"})
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    return {
        "ok": all(c["available"] for c in checks),
        "target_site": site,
        "checks": checks,
        "plan_summary": {
            "steps": len(plan.get("steps", [])),
            "total_items": plan.get("total_items", 0),
            "warnings": plan.get("warnings", []),
        },
    }


@router.post("/execute")
async def execute_migration(req: ExecuteRequest, _: str = Depends(require_super_admin)) -> dict:
    """Run the migration: import content into Frappe."""
    import tempfile, os, subprocess

    site = req.target_site
    plan = req.plan
    dry_run = req.dry_run
    analysis = plan.get("analysis", {})
    cms = plan.get("cms", "")

    results: list[dict] = []
    errors: list[str] = []

    # Load media URL mapping produced by /media/migrate (if run)
    _url_map: dict[str, str] = {}
    try:
        import pathlib
        _map_path = pathlib.Path(f"/tmp/wpmedia_mapping_{site}.json")
        if _map_path.exists():
            _url_map = json.loads(_map_path.read_text())
    except Exception:
        pass

    def _run_code(code: str, label: str, timeout: int = 120) -> tuple[str, bool]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write(code)
            tmp = f.name
        try:
            cmd = ["sudo", "-u", "frappe", "/usr/local/bin/frothiq-bench",
                   "--site", site, "execute", f"exec(open('{tmp}').read())"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd="/tmp")
            out = (r.stdout + r.stderr).strip()
            ok = r.returncode == 0
            return out, ok
        except subprocess.TimeoutExpired:
            return f"Timed out after {timeout}s", False
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    for step in plan.get("steps", []):
        step_name = step["step"]
        doctype   = step.get("doctype")

        if step_name == "import_categories":
            if cms == "wordpress":
                cats = analysis.get("categories", [])
            else:
                cats = [{"name": c.get("title",""), "slug": c.get("alias","")} for c in analysis.get("categories", [])]

            created = skipped = failed = 0
            for cat in cats:
                name = (cat.get("name") or "").strip()
                slug = (cat.get("slug") or _slug(name)).strip()
                if not name:
                    continue
                if dry_run:
                    created += 1
                    continue
                code = textwrap.dedent(f"""
import frappe
name_val = {json.dumps(name)}
slug_val = {json.dumps(slug)}
existing = frappe.db.get_value('Blog Category', {{'title': name_val}}, 'name')
if existing:
    print('SKIP:' + existing)
else:
    doc = frappe.get_doc({{'doctype': 'Blog Category', 'title': name_val, 'route': 'blog/' + slug_val}})
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    print('OK:' + doc.name)
""").strip()
                out, ok = _run_code(code, f"Category: {name}")
                for line in out.splitlines():
                    if line.startswith("OK:"):
                        created += 1
                    elif line.startswith("SKIP:"):
                        skipped += 1
                    elif not ok:
                        failed += 1
                        errors.append(f"Category '{name}': {out[:200]}")
                        break

            results.append({"step": step_name, "label": step["label"], "created": created,
                            "skipped": skipped, "failed": failed, "dry_run": dry_run})

        elif step_name == "import_posts":
            if cms == "wordpress":
                posts = analysis.get("posts", [])
            else:
                posts = [{"title": a.get("title",""), "slug": a.get("alias",""),
                          "content": (a.get("introtext","") + "\n\n" + a.get("fulltext","")).strip()} for a in analysis.get("articles", [])]

            created = skipped = failed = 0
            for post in posts:
                title   = (post.get("title") or "").strip()
                slug    = (post.get("slug") or post.get("alias") or _slug(title)).strip()
                raw_html = post.get("raw_content_html") or post.get("content") or post.get("introtext", "")
                content = _clean_wp_content(raw_html, _url_map)
                if not title:
                    continue
                if dry_run:
                    created += 1
                    continue

                # Determine blog category (use first category if mapped)
                cat_ids = post.get("categories", [])
                cat_name: str | None = None
                if cat_ids and cms == "wordpress":
                    cats_by_id = {c["id"]: c["name"] for c in analysis.get("categories", [])}
                    cat_name = cats_by_id.get(cat_ids[0])

                code = textwrap.dedent(f"""
import frappe
title_val   = {json.dumps(title)}
slug_val    = {json.dumps(slug or _slug(title))}
content_val = {json.dumps(content[:50000])}
cat_val     = {json.dumps(cat_name)}

existing = frappe.db.get_value('Blog Post', {{'title': title_val}}, 'name')
if existing:
    print('SKIP:' + existing)
else:
    # Resolve blog category
    blog_category = None
    if cat_val:
        blog_category = frappe.db.get_value('Blog Category', {{'title': cat_val}}, 'name')
    if not blog_category:
        # Use or create a default category
        default_cat = frappe.db.get_value('Blog Category', {{}}, 'name')
        if not default_cat:
            c = frappe.get_doc({{'doctype': 'Blog Category', 'title': 'Imported'}})
            c.insert(ignore_permissions=True)
            default_cat = c.name
        blog_category = default_cat

    doc = frappe.get_doc({{
        'doctype': 'Blog Post',
        'title': title_val,
        'route': 'blog/' + slug_val,
        'blog_category': blog_category,
        'blogger': 'Administrator',
        'content': content_val,
        'published': 1,
        'meta_title': title_val,
    }})
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    print('OK:' + doc.name)
""").strip()
                out, ok = _run_code(code, f"Post: {title}")
                for line in out.splitlines():
                    if line.startswith("OK:"):
                        created += 1
                    elif line.startswith("SKIP:"):
                        skipped += 1
                    elif not ok:
                        failed += 1
                        errors.append(f"Post '{title}': {out[:200]}")
                        break

            results.append({"step": step_name, "label": step["label"], "created": created,
                            "skipped": skipped, "failed": failed, "dry_run": dry_run})

        elif step_name == "import_pages" and cms == "wordpress":
            pages = analysis.get("pages", [])
            created = skipped = failed = 0
            for page in pages:
                title   = (page.get("title") or "").strip()
                route   = (page.get("slug") or _slug(title)).strip()
                # Prefer raw HTML — clean WP artifacts and replace media URLs
                raw_html = page.get("raw_content_html") or page.get("content") or ""
                content = _clean_wp_content(raw_html, _url_map)
                if not title:
                    continue
                if dry_run:
                    created += 1
                    continue
                code = textwrap.dedent(f"""
import frappe
title_val   = {json.dumps(title)}
route_val   = {json.dumps(route)}
content_val = {json.dumps(content[:50000])}

existing = frappe.db.get_value('Web Page', {{'title': title_val}}, 'name')
if existing:
    print('SKIP:' + existing)
else:
    doc = frappe.get_doc({{
        'doctype': 'Web Page',
        'title': title_val,
        'route': route_val,
        'main_section_html': content_val,
        'content_type': 'HTML',
        'published': 1,
        'meta_title': title_val,
    }})
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    print('OK:' + doc.name)
""").strip()
                out, ok = _run_code(code, f"Page: {title}")
                for line in out.splitlines():
                    if line.startswith("OK:"):
                        created += 1
                    elif line.startswith("SKIP:"):
                        skipped += 1
                    elif not ok:
                        failed += 1
                        errors.append(f"Page '{title}': {out[:200]}")
                        break

            results.append({"step": step_name, "label": step["label"], "created": created,
                            "skipped": skipped, "failed": failed, "dry_run": dry_run})

        elif step_name == "publish":
            results.append({"step": step_name, "label": step["label"], "created": 1,
                            "skipped": 0, "failed": 0, "note": "Set site_config: maintenance_mode=0 to go live",
                            "dry_run": dry_run})

    total_created = sum(r.get("created", 0) for r in results)
    total_failed  = sum(r.get("failed", 0) for r in results)

    return {
        "ok": total_failed == 0,
        "dry_run": dry_run,
        "target_site": site,
        "results": results,
        "errors": errors[:20],
        "summary": {
            "total_created": total_created,
            "total_failed": total_failed,
            "steps_completed": len(results),
        },
    }


# ---------------------------------------------------------------------------
# Content cleaner — removes WP-specific markup, replaces media URLs
# ---------------------------------------------------------------------------

def _clean_wp_content(html: str, url_map: dict | None = None) -> str:
    """Strip WordPress shortcodes, Gutenberg block comments, and replace media URLs."""
    if not html:
        return ""
    # Gutenberg block comments
    html = re.sub(r"<!-- wp:[^>]*?-->", "", html)
    html = re.sub(r"<!-- /wp:[^>]*?-->", "", html)
    # Captioned images shortcode (has body)
    html = re.sub(r"\[caption[^\]]*\].*?\[/caption\]", "", html, flags=re.DOTALL)
    # Embedded content shortcode
    html = re.sub(r"\[embed[^\]]*\].*?\[/embed\]", "", html, flags=re.DOTALL)
    # Gallery, audio, video shortcodes (self-closing)
    html = re.sub(r"\[gallery[^\]]*\]", "", html)
    html = re.sub(r"\[audio[^\]]*\]", "", html)
    html = re.sub(r"\[video[^\]]*\]", "", html)
    # Any remaining shortcodes
    html = re.sub(r"\[[^\]]{1,60}\]", "", html)
    # Replace media URLs
    if url_map:
        for old, new in url_map.items():
            html = html.replace(old, new)
    # Clean excess whitespace
    html = re.sub(r"\n{3,}", "\n\n", html).strip()
    return html


# ---------------------------------------------------------------------------
# MEDIA MIGRATION — download all WP media → Frappe File DocType
# ---------------------------------------------------------------------------

class MediaMigrateRequest(BaseModel):
    url: str
    username: str = ""
    password: str = ""
    target_site: str


@router.post("/media/migrate")
async def migrate_media(req: MediaMigrateRequest, _: str = Depends(require_super_admin)) -> dict:
    """Download ALL WordPress media files and upload them into Frappe File DocType."""
    import os, subprocess, tempfile, pathlib

    url = _normalise(req.url)
    site = req.target_site
    auth_hdrs = {"Authorization": f"Basic {_b64(req.username, req.password)}"} if req.username else {}

    # Fetch complete media list — no cap, full pagination
    async with httpx.AsyncClient() as client:
        media_raw = await _paginate_wp(
            client,
            f"{url}/wp-json/wp/v2/media?_fields=id,title,source_url,mime_type",
            auth_hdrs,
        )

    url_map: dict[str, str] = {}
    results: list[dict] = []
    errors: list[str] = []

    for item in media_raw:
        source_url = item.get("source_url", "").strip()
        if not source_url:
            continue
        filename = source_url.split("?")[0].split("/")[-1]
        if not filename:
            continue

        tmp_media = f"/tmp/wpmedia_{filename}"

        # Download
        try:
            async with httpx.AsyncClient() as dl:
                resp = await dl.get(source_url, timeout=httpx.Timeout(60.0), follow_redirects=True)
            if resp.status_code != 200:
                errors.append(f"HTTP {resp.status_code}: {source_url}")
                results.append({"source_url": source_url, "filename": filename, "frappe_url": None, "status": "http_error"})
                continue
            with open(tmp_media, "wb") as fh:
                fh.write(resp.content)
        except Exception as exc:
            errors.append(f"Download failed {source_url}: {exc}")
            results.append({"source_url": source_url, "filename": filename, "frappe_url": None, "status": "download_failed"})
            continue

        # Upload into Frappe File DocType via bench
        bench_code = textwrap.dedent(f"""
import frappe, json, os
from frappe.utils.file_manager import save_file

tmp    = {json.dumps(tmp_media)}
fname  = {json.dumps(filename)}
oldurl = {json.dumps(source_url)}

try:
    existing = frappe.db.get_value('File', {{'file_name': fname, 'is_private': 0}}, 'file_url')
    if existing:
        print(json.dumps({{'status': 'exists', 'old': oldurl, 'new': existing}}))
    else:
        with open(tmp, 'rb') as fh:
            fd = save_file(fname=fname, content=fh.read(), dt=None, dn=None, is_private=0)
        frappe.db.commit()
        print(json.dumps({{'status': 'created', 'old': oldurl, 'new': fd.file_url}}))
except Exception as e:
    print(json.dumps({{'status': 'error', 'old': oldurl, 'error': str(e)[:200]}}))
finally:
    try:
        os.unlink(tmp)
    except Exception:
        pass
""").strip()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write(bench_code)
            tmp_script = f.name

        try:
            cmd = ["sudo", "-u", "frappe", "/usr/local/bin/frothiq-bench",
                   "--site", site, "execute", f"exec(open('{tmp_script}').read())"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd="/tmp")
            out = (r.stdout + r.stderr).strip()

            frappe_url = None
            status = "failed"
            for line in out.splitlines():
                try:
                    data = json.loads(line)
                    status = data.get("status", "failed")
                    frappe_url = data.get("new")
                    if data.get("error"):
                        errors.append(f"{filename}: {data['error']}")
                    break
                except Exception:
                    continue

            if frappe_url:
                url_map[source_url] = frappe_url

            results.append({"source_url": source_url, "filename": filename,
                            "frappe_url": frappe_url, "status": status})

        except subprocess.TimeoutExpired:
            errors.append(f"Timeout uploading {filename}")
            results.append({"source_url": source_url, "filename": filename,
                            "frappe_url": None, "status": "timeout"})
        finally:
            try:
                os.unlink(tmp_script)
            except Exception:
                pass

    # Persist mapping so execute endpoint can use it for URL replacement
    mapping_path = pathlib.Path(f"/tmp/wpmedia_mapping_{site}.json")
    mapping_path.write_text(json.dumps(url_map))

    migrated = len([r for r in results if r["status"] in ("created", "exists")])
    return {
        "total": len(media_raw),
        "migrated": migrated,
        "failed": len(results) - migrated,
        "mapping": url_map,
        "results": results,
        "errors": errors[:30],
    }


# ---------------------------------------------------------------------------
# PLUGIN INTELLIGENCE — WP.org lookup + classification
# ---------------------------------------------------------------------------

class PluginAnalyzeRequest(BaseModel):
    plugins: list[dict]  # [{name, status, slug?}]


def _wp_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


async def _lookup_wp_org(slug: str, client: httpx.AsyncClient) -> dict:
    url = (
        "https://api.wordpress.org/plugins/info/1.2/"
        f"?action=plugin_information&request[slug]={slug}"
        "&request[fields][short_description]=1"
        "&request[fields][tags]=1"
        "&request[fields][active_installs]=1"
    )
    try:
        r = await client.get(url, timeout=_TIMEOUT, follow_redirects=True)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and data.get("slug"):
                return data
    except Exception:
        pass
    return {}


def _classify_plugin(name: str, tags: dict, desc: str, installs: int) -> dict:
    """Classify a plugin into purpose / features / complexity / recommended_action."""
    corpus = f"{name.lower()} {desc.lower()} {' '.join(tags.keys() if isinstance(tags, dict) else [])}"
    complexity = "high" if installs >= 1_000_000 else ("medium" if installs >= 100_000 else "low")

    _rules = [
        (["woocommerce", "ecommerce", "e-commerce", "shop", "cart", "checkout", "payment gateway"],
         "E-commerce / Online store",
         ["Product catalog", "Shopping cart", "Checkout flow", "Payment gateways"], "rebuild"),
        (["yoast", "rank math", "seo", "sitemap", "meta tag", "open graph", "schema markup"],
         "Search engine optimisation (SEO)",
         ["Meta tags", "XML sitemaps", "Open Graph", "Schema markup"], "ignore"),
        (["contact form", "gravity form", "ninja form", "wpforms", "form builder", "web form"],
         "Contact forms / Form builder",
         ["Drag-drop form builder", "Email notifications", "Submission storage"], "rebuild"),
        (["wordfence", "itheme", "security", "firewall", "malware", "brute force", "captcha"],
         "Security / Firewall",
         ["Login protection", "Malware scanning", "IP blocking", "2FA"], "ignore"),
        (["w3 total", "wp super cache", "litespeed", "cache", "performance", "minif", "speed"],
         "Performance / Caching",
         ["Page caching", "Asset minification", "CDN integration"], "ignore"),
        (["google analytics", "gtm", "tag manager", "pixel", "tracking", "analytics", "stats"],
         "Analytics and tracking",
         ["Page view tracking", "User behaviour", "Conversion tracking"], "integrate"),
        (["gallery", "nextgen", "envira", "slider", "carousel", "lightbox"],
         "Media gallery / Slideshow",
         ["Image galleries", "Lightbox overlay", "Responsive slideshows"], "rebuild"),
        (["social", "share", "addthis", "shareaholic", "twitter", "facebook"],
         "Social media integration",
         ["Share buttons", "Social feeds", "Social login"], "integrate"),
        (["mailchimp", "mailpoet", "newsletter", "campaign", "subscriber", "email marketing"],
         "Email marketing / Newsletter",
         ["Subscriber lists", "Email campaigns", "Opt-in forms"], "integrate"),
        (["memberpress", "membership", "learndash", "restrict", "paywall", "subscription", "edd"],
         "Membership / Access control",
         ["User roles", "Content restriction", "Subscription billing"], "rebuild"),
        (["wpml", "polylang", "weglot", "multilingual", "translation", "language"],
         "Multilingual / Translation",
         ["Content translation", "Language switcher", "RTL support"], "rebuild"),
        (["elementor", "divi", "beaver", "visual composer", "page builder", "vc_row"],
         "Page builder / Visual editor",
         ["Drag-and-drop layout", "Custom blocks", "Pre-built templates"], "ignore"),
        (["updraft", "duplicator", "akeeba", "backup", "migration", "clone"],
         "Backup and migration",
         ["Database backup", "File backup", "One-click restore"], "ignore"),
        (["tablepress", "ninja table", "spreadsheet", "data table"],
         "Data tables",
         ["Table display", "CSV import", "Responsive tables"], "rebuild"),
        (["booking", "appointment", "schedule", "reservation", "calendar", "event espresso"],
         "Booking / Scheduling",
         ["Calendar", "Reservations", "Automated reminders"], "rebuild"),
        (["jetpack", "akismet"],
         "Automattic platform service",
         ["CDN", "Stats", "Spam filtering", "Security"], "ignore"),
    ]

    for keywords, purpose, features, action in _rules:
        if any(k in corpus for k in keywords):
            return {"purpose": purpose, "features": features,
                    "complexity": complexity, "recommended_action": action}

    return {
        "purpose": desc[:120] if desc else "General WordPress plugin",
        "features": list(tags.keys())[:5] if isinstance(tags, dict) else [],
        "complexity": complexity,
        "recommended_action": "rebuild",
    }


@router.post("/plugins/analyze")
async def analyze_plugins(req: PluginAnalyzeRequest, _: str = Depends(require_super_admin)) -> dict:
    """Lookup each plugin on WordPress.org and classify it for the decision interface."""
    results: list[dict] = []

    async with httpx.AsyncClient() as client:
        for plugin in req.plugins:
            name   = plugin.get("name", "")
            status = plugin.get("status", "")
            slug   = plugin.get("slug") or _wp_slug(name)

            wp_data = await _lookup_wp_org(slug, client)

            desc     = wp_data.get("short_description", "")
            tags     = wp_data.get("tags", {})
            installs = wp_data.get("active_installs", 0)

            classification = _classify_plugin(name, tags, desc, installs)

            results.append({
                "plugin":          name,
                "slug":            slug,
                "status":          status,
                "wp_org_found":    bool(wp_data),
                "description":     desc or "Not found on WordPress.org",
                "active_installs": installs,
                "tags":            list(tags.keys())[:8] if isinstance(tags, dict) else [],
                **classification,
                "decision":        classification["recommended_action"],  # editable by user in MC3
            })

    return {"plugins": results, "total": len(results)}


# ---------------------------------------------------------------------------
# VALIDATION — post-migration report
# ---------------------------------------------------------------------------

class ValidateRequest(BaseModel):
    target_site: str
    plan: dict
    source_url: str = ""


@router.post("/validate")
async def validate_migration(req: ValidateRequest, _: str = Depends(require_super_admin)) -> dict:
    """Check migrated content for missing media, broken WP references, and count mismatches."""
    import os, subprocess, tempfile, pathlib

    site = req.target_site
    plan = req.plan
    analysis = plan.get("analysis", {})

    issues: list[dict] = []
    stats:  dict = {}

    # Load media mapping
    media_mapping: dict = {}
    try:
        p = pathlib.Path(f"/tmp/wpmedia_mapping_{site}.json")
        if p.exists():
            media_mapping = json.loads(p.read_text())
    except Exception:
        pass

    # 1. Count records in Frappe + scan for lingering WP references
    code = textwrap.dedent("""
import frappe, json

counts = {}
for dt in ['Blog Post', 'Blog Category', 'Web Page']:
    try:
        counts[dt] = frappe.db.count(dt)
    except Exception:
        counts[dt] = -1

broken = []
for dt, field in [('Blog Post', 'content'), ('Web Page', 'main_section_html'), ('Web Page', 'main_section')]:
    try:
        recs = frappe.db.get_all(dt, fields=['name', field])
        for rec in recs:
            body = rec.get(field) or ''
            if 'wp-content/uploads' in body or 'wp-includes' in body:
                broken.append({'doctype': dt, 'name': rec['name']})
    except Exception:
        pass

print(json.dumps({'counts': counts, 'broken': broken}))
""").strip()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
        f.write(code)
        tmp = f.name
    try:
        cmd = ["sudo", "-u", "frappe", "/usr/local/bin/frothiq-bench",
               "--site", site, "execute", f"exec(open('{tmp}').read())"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd="/tmp")
        for line in (r.stdout + r.stderr).splitlines():
            try:
                data = json.loads(line)
                counts = data.get("counts", {})
                stats["frappe_counts"] = counts

                # Count mismatch vs plan
                plan_counts = {s["doctype"]: s["count"]
                               for s in plan.get("steps", []) if s.get("doctype")}
                for dt, expected in plan_counts.items():
                    actual = counts.get(dt, 0)
                    if actual < expected:
                        issues.append({
                            "severity": "warning",
                            "type": "count_mismatch",
                            "message": f"{dt}: plan expected {expected}, Frappe has {actual}",
                            "doctype": dt,
                        })

                # Lingering WP URL references
                for ref in data.get("broken", []):
                    issues.append({
                        "severity": "high",
                        "type": "broken_wp_reference",
                        "message": f"WordPress URL still present in {ref['doctype']} '{ref['name']}'",
                        "doctype": ref["doctype"],
                        "name": ref["name"],
                    })
                break
            except Exception:
                continue
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    # 2. Media coverage
    source_media = analysis.get("media", [])
    if source_media:
        total = len(source_media)
        migrated = len(media_mapping)
        stats["media_total"]    = total
        stats["media_migrated"] = migrated
        if migrated < total:
            issues.append({
                "severity": "high",
                "type": "missing_media",
                "message": f"{total - migrated} of {total} media files not yet in Frappe — run Media Migrate step",
            })
        # Per-file missing list (cap at 20 for brevity)
        for m in source_media:
            src = m.get("url", "")
            if src and src not in media_mapping:
                issues.append({
                    "severity": "high",
                    "type": "media_not_migrated",
                    "message": f"Not migrated: {m.get('title') or src}",
                    "source_url": src,
                })
            if len([i for i in issues if i["type"] == "media_not_migrated"]) >= 20:
                break
    elif not media_mapping:
        issues.append({
            "severity": "info",
            "type": "media_skipped",
            "message": "Media migration was not run. Use the Media step before Execute for full content fidelity.",
        })

    high  = sum(1 for i in issues if i["severity"] == "high")
    warns = sum(1 for i in issues if i["severity"] == "warning")
    info  = sum(1 for i in issues if i["severity"] == "info")

    return {
        "ok":          high == 0,
        "target_site": site,
        "stats":       stats,
        "issues":      issues,
        "summary":     {"high": high, "warnings": warns, "info": info, "total": len(issues)},
    }
