"""
Mail infrastructure — autodiscover configuration reader.

Reads Postfix and Dovecot settings to produce structured mail client
configuration (IMAP / SMTP) for use in new-user onboarding workflows.
"""

from __future__ import annotations

import asyncio
import re
import subprocess

from fastapi import APIRouter, Depends

from frothiq_control_center.auth import TokenPayload, require_super_admin

router = APIRouter(prefix="/sysinfo/mail", tags=["mail"])


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _postconf(key: str) -> str:
    out = _run(["postconf", "-h", key])
    return out.strip()


def _doveconf_value(key: str) -> str:
    out = _run(["sudo", "doveconf", key])
    # output format: "key = value"
    if "=" in out:
        return out.split("=", 1)[1].strip()
    return out.strip()


def _doveconf_listener_port(service: str, listener: str) -> int | None:
    """Extract port for a named Dovecot inet_listener."""
    out = _run(["sudo", "doveconf", "-a"], timeout=15)
    # Find the service block, then the named listener block, then port
    pattern = re.compile(
        r"service\s+" + re.escape(service) + r"\s*\{.*?inet_listener\s+"
        + re.escape(listener) + r"\s*\{(.*?)\}",
        re.DOTALL | re.IGNORECASE,
    )
    m = pattern.search(out)
    if not m:
        return None
    block = m.group(1)
    pm = re.search(r"port\s*=\s*(\d+)", block)
    if pm and pm.group(1) != "0":
        return int(pm.group(1))
    return None


def _build_autodiscover() -> dict:
    # --- Server hostname ---
    hostname = _postconf("myhostname") or "mail.example.com"

    # --- SMTP ---
    # Prefer submission (587) or smtps (465); fall back to 25
    smtp_port = 587
    smtp_ssl = "STARTTLS"
    # Check if submission listener is enabled in Postfix master.cf
    master_out = _run(["postconf", "-M"])
    if "submission/inet" in master_out:
        smtp_port = 587
        smtp_ssl = "STARTTLS"
    elif "smtps/inet" in master_out:
        smtp_port = 465
        smtp_ssl = "SSL/TLS"

    # --- IMAP ---
    # Prefer imaps (993); fall back to imap (143) with STARTTLS
    imaps_port = _doveconf_listener_port("imap", "imaps")
    imap_port = _doveconf_listener_port("imap", "imap")

    if imaps_port and imaps_port > 0:
        imap_config = {"port": imaps_port, "ssl": "SSL/TLS"}
    elif imap_port and imap_port > 0:
        imap_config = {"port": imap_port, "ssl": "STARTTLS"}
    else:
        imap_config = {"port": 993, "ssl": "SSL/TLS"}  # sensible default

    # --- Authentication ---
    auth_mechanisms = _doveconf_value("auth_mechanisms") or "plain login"
    smtp_auth = "LOGIN" if "login" in auth_mechanisms.lower() else "PLAIN"

    return {
        "hostname": hostname,
        "imap": {
            "host": hostname,
            "port": imap_config["port"],
            "ssl": imap_config["ssl"],
            "username_format": "{email}",
        },
        "smtp": {
            "host": hostname,
            "port": smtp_port,
            "ssl": smtp_ssl,
            "auth": smtp_auth,
            "username_format": "{email}",
        },
        "webmail_hint": f"https://{hostname}/webmail",
        "autoconfig_url": "https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml",
    }


@router.get("/autodiscover")
async def get_autodiscover(_: TokenPayload = Depends(require_super_admin)):
    """
    Return mail client autodiscover settings derived from live Postfix and
    Dovecot configuration. Used by the new-user onboarding wizard.
    """
    config = await asyncio.to_thread(_build_autodiscover)
    return config
