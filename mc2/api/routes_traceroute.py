"""
FrothIQ traceroute attacker analysis.

Closes TASK-2026-00231.

The WordPress FrothIQ plugin runs traceroute on suspicious source IPs and
POSTs the raw output (or a structured hop list) here. MC² enriches each
hop with PTR lookups, classifies hosting providers / known networks from
PTR patterns, and returns a plain-English summary suitable for inclusion
in the attack report shown to the operator.

No third-party APIs are called — everything runs locally on wh1:
  - dig/host for reverse DNS (offline-tolerant; missing PTR → "unknown")
  - hostname/PTR pattern matching for cloud and bad-network classification
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from mc2.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/traceroute", tags=["traceroute"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ─────────────────────────────────────────────────────────────────────────────
# Hosting-provider / bad-network classification by PTR pattern
# ─────────────────────────────────────────────────────────────────────────────

CLOUD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS",            re.compile(r"\.(?:amazonaws|amazon|aws)\.com$", re.I)),
    ("Google Cloud",   re.compile(r"\.(?:googleusercontent|google|googlecloud|1e100)\.(?:com|net)$", re.I)),
    ("Cloudflare",     re.compile(r"\.cloudflare(?:-dns)?\.(?:com|net)$", re.I)),
    ("Microsoft Azure", re.compile(r"\.(?:azure|microsoft|azureedge|azurewebsites)\.(?:com|net)$", re.I)),
    ("DigitalOcean",   re.compile(r"\.digitalocean\.com$", re.I)),
    ("Linode",         re.compile(r"\.(?:linode|linodeusercontent)\.com$", re.I)),
    ("Vultr",          re.compile(r"\.vultr\.com$", re.I)),
    ("OVH",            re.compile(r"\.ovh\.(?:com|net|ca)$", re.I)),
    ("Hetzner",        re.compile(r"\.hetzner\.(?:com|de|cloud)$", re.I)),
    ("Akamai",         re.compile(r"\.akamai(?:edge|technologies)?\.net$", re.I)),
    ("Fastly",         re.compile(r"\.fastly\.net$", re.I)),
    ("M247 / Leaseweb", re.compile(r"\.(?:m247|leaseweb|liteserver)\.(?:com|net)$", re.I)),
]

# Networks frequently abused or that operate as residential / mobile proxies.
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("Tor exit relay",     re.compile(r"(?:^|\.)tor(?:exit)?\.", re.I), "high"),
    ("VPN / proxy network", re.compile(r"\.(?:nordvpn|expressvpn|protonvpn|surfshark|mullvad)\.com$", re.I), "high"),
    ("Russian ISP",        re.compile(r"\.ru$", re.I), "medium"),
    ("Iranian ISP",        re.compile(r"\.ir$", re.I), "medium"),
    ("North Korean ISP",   re.compile(r"\.kp$", re.I), "high"),
    ("Chinese telecom",    re.compile(r"\.(?:chinatelecom|chinanet|cnc-noc|cnc|cncgroup)\.(?:com\.cn|net)$", re.I), "medium"),
    ("Sketchy bulletproof hosting", re.compile(r"\.(?:bulletproof|offshore-?host)", re.I), "high"),
]


def _reverse_dns(ip: str, timeout: float = 1.5) -> str | None:
    """Best-effort reverse DNS. Returns None if no PTR or query fails."""
    try:
        socket.setdefaulttimeout(timeout)
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _classify_ptr(ptr: str | None) -> dict:
    if not ptr:
        return {"hosting_provider": None, "suspicious": None, "severity": None}
    for name, pat in CLOUD_PATTERNS:
        if pat.search(ptr):
            return {"hosting_provider": name, "suspicious": None, "severity": None}
    for label, pat, sev in SUSPICIOUS_PATTERNS:
        if pat.search(ptr):
            return {"hosting_provider": None, "suspicious": label, "severity": sev}
    return {"hosting_provider": None, "suspicious": None, "severity": None}


def _ip_kind(ip: str) -> str:
    """Categorize the IP: private, loopback, multicast, public, or invalid."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if obj.is_loopback:
        return "loopback"
    if obj.is_private:
        return "private"
    if obj.is_multicast:
        return "multicast"
    if obj.is_link_local:
        return "link_local"
    if obj.is_unspecified:
        return "unspecified"
    return "public"


# ─────────────────────────────────────────────────────────────────────────────
# Traceroute output parser
# ─────────────────────────────────────────────────────────────────────────────

# Matches: " 5  198.51.100.1 (some.host.example.com)  12.345 ms  …"
# Or:      " 5  198.51.100.1  12.345 ms"
# Or:      " 6  * * *"
_HOP_LINE_RE = re.compile(
    r"^\s*(\d+)\s+"                           # hop #
    r"(?:(\*)\s*\*\s*\*"                      # all stars (timeout)
    r"|"
    r"(?:([^\s(]+)\s*"                         # host or IP
    r"(?:\(([^)]+)\)\s*)?"                     # optional (resolved-IP)
    r"(.*))"                                   # timing rest
    r")\s*$"
)


def parse_traceroute(raw: str) -> list[dict]:
    """Parse raw `traceroute` output into structured hops."""
    hops: list[dict] = []
    for line in raw.splitlines():
        m = _HOP_LINE_RE.match(line)
        if not m:
            continue
        hop_no = int(m.group(1))
        if m.group(2):
            hops.append({"hop": hop_no, "ip": None, "host": None, "timeout": True})
            continue
        first = m.group(3) or ""
        paren = m.group(4) or ""
        # If first looks like a hostname and paren has an IP, use paren as IP
        if paren and re.match(r"^\d+\.\d+\.\d+\.\d+$", paren):
            ip = paren
            host = first
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", first):
            ip = first
            # If paren contains a non-IP token, treat it as the resolved hostname
            host = paren if paren and not re.match(r"^\d+\.\d+\.\d+\.\d+$", paren) else None
        else:
            ip = None
            host = first
        hops.append({"hop": hop_no, "ip": ip, "host": host, "timeout": False})
    return hops


def enrich_hop(hop: dict) -> dict:
    out = dict(hop)
    ip = hop.get("ip")
    out["kind"] = _ip_kind(ip) if ip else "unknown"
    ptr = hop.get("host")
    if ip and not ptr and out["kind"] == "public":
        ptr = _reverse_dns(ip)
        out["host"] = ptr
    out.update(_classify_ptr(ptr))
    return out


def summarize(enriched: list[dict], attacker_ip: str | None) -> dict:
    """Build a plain-English summary plus structured signals."""
    public_hops = [h for h in enriched if h["kind"] == "public"]
    providers = [h["hosting_provider"] for h in public_hops if h["hosting_provider"]]
    suspicious = [(h["hop"], h["suspicious"], h["severity"]) for h in public_hops if h["suspicious"]]
    timeouts = sum(1 for h in enriched if h["timeout"])

    # Verdict
    verdict = "low"
    if any(s == "high" for _, _, s in suspicious):
        verdict = "high"
    elif any(s == "medium" for _, _, s in suspicious):
        verdict = "medium"
    elif timeouts > len(enriched) * 0.5 and len(enriched) > 3:
        verdict = "medium"  # Heavy timeout pattern (possible evasion)

    # Origin assessment from the last public hop
    origin = None
    if public_hops:
        last = public_hops[-1]
        if last.get("hosting_provider"):
            origin = f"{last['hosting_provider']} ({last.get('host') or last.get('ip')})"
        elif last.get("host"):
            origin = last["host"]
        elif last.get("ip"):
            origin = last["ip"]

    # English summary
    parts: list[str] = []
    if attacker_ip:
        parts.append(f"Traceroute to attacker {attacker_ip}.")
    parts.append(f"{len(enriched)} hops total, {timeouts} timed out.")
    if origin:
        parts.append(f"Final origin appears to be {origin}.")
    if providers:
        uniq = sorted(set(providers))
        parts.append(f"Path traverses: {', '.join(uniq)}.")
    if suspicious:
        labels = sorted({label for _, label, _ in suspicious})
        parts.append(f"⚠ Suspicious hops detected: {', '.join(labels)}.")

    return {
        "verdict": verdict,
        "origin": origin,
        "providers_in_path": sorted(set(providers)),
        "suspicious_hops": [{"hop": h, "label": l, "severity": s} for h, l, s in suspicious],
        "timeout_count": timeouts,
        "narrative": " ".join(parts),
    }


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────

class TracerouteInput(BaseModel):
    raw: str | None = None
    hops: list[dict] | None = None
    attacker_ip: str | None = Field(default=None, max_length=45)


@router.post("/analyze")
def analyze(body: TracerouteInput, _: Auth):
    """Enrich a traceroute (raw text or pre-parsed hops) and return an
    attacker-origin summary suitable for the FrothIQ attack report."""
    if not body.raw and not body.hops:
        return {"error": "either 'raw' or 'hops' is required", "hops": [], "summary": None}

    hops = body.hops if body.hops else parse_traceroute(body.raw or "")
    enriched = [enrich_hop(h) for h in hops]
    summary = summarize(enriched, body.attacker_ip)
    return {"hops": enriched, "summary": summary}


@router.post("/run")
def run(body: TracerouteInput, _: Auth):
    """Run traceroute against attacker_ip on wh1 and return enriched analysis.

    Requires the `traceroute` binary; falls back gracefully if absent."""
    if not body.attacker_ip:
        return {"error": "attacker_ip is required", "hops": [], "summary": None}
    try:
        ipaddress.ip_address(body.attacker_ip)
    except ValueError:
        return {"error": "invalid attacker_ip", "hops": [], "summary": None}

    try:
        r = subprocess.run(
            ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", body.attacker_ip],
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        return {"error": "traceroute binary not installed on host", "hops": [], "summary": None}
    except subprocess.TimeoutExpired:
        return {"error": "traceroute timed out", "hops": [], "summary": None}

    hops = parse_traceroute(r.stdout)
    enriched = [enrich_hop(h) for h in hops]
    summary = summarize(enriched, body.attacker_ip)
    return {
        "raw": r.stdout,
        "hops": enriched,
        "summary": summary,
        "stderr": r.stderr[:500] if r.returncode != 0 else None,
    }
