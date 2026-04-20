"""
FrothIQ NFT service — service control, nftables viewer, IP/port management,
LFD settings, validation status, decommission orchestration.

All system changes go through this service layer — never direct rule editing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from frothiq_control_center.models.defense_settings import (
    FrothiqIPEntry,
    FrothiqNftAudit,
    FrothiqNftSetting,
    FrothiqPortRule,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings default dicts — mirrors CSF/LFD config keys 1:1
# ---------------------------------------------------------------------------

PORT_DEFAULTS: dict[str, str] = {
    "TCP_IN":    "20,21,25,53,853,80,110,143,443,465,587,993,995,3000,3112,8782,8780,10000,20000",
    "TCP_OUT":   "20,21,25,53,853,80,110,113,443,587,993,995,3000,3112,8782,8780,10000,20000",
    "UDP_IN":    "20,21,53,853,80,443",
    "UDP_OUT":   "20,21,53,853,113,123",
    "TCP6_IN":   "20,21,25,53,853,80,110,143,443,465,587,993,995,3112,8782,8780",
    "TCP6_OUT":  "20,21,25,53,853,80,110,113,443,587,993,995,3112,8782,8780",
    "UDP6_IN":   "20,21,53,853,80,443",
    "UDP6_OUT":  "20,21,53,853,113,123",
    "DROP_NOLOG":"23,67,68,111,113,135:139,445,500,513,520",
}

LFD_DEFAULTS: dict[str, str] = {
    "LF_SSHD": "5",     "LF_SSHD_PERM": "1",
    "LF_FTPD": "5",     "LF_FTPD_PERM": "1",
    "LF_SMTPAUTH": "3", "LF_SMTPAUTH_PERM": "1",
    "LF_POP3D": "5",    "LF_POP3D_PERM": "1",
    "LF_IMAPD": "5",    "LF_IMAPD_PERM": "1",
    "LF_HTACCESS": "5", "LF_HTACCESS_PERM": "1",
    "LF_MODSEC": "5",   "LF_MODSEC_PERM": "1",
    "LF_WEBMIN": "1",   "LF_WEBMIN_PERM": "0",
}

BLOCKING_DEFAULTS: dict[str, str] = {
    "SYNFLOOD": "0", "SYNFLOOD_RATE": "100/s", "SYNFLOOD_BURST": "150",
    "CONNLIMIT": "25;20,465;20,587;20",
    "PORTFLOOD": "143;tcp;20;5,993;tcp;20;5,110;tcp;20;5,995;tcp;20;5",
    "LF_PERMBLOCK": "1", "LF_PERMBLOCK_INTERVAL": "86400", "LF_PERMBLOCK_COUNT": "4",
    "LF_NETBLOCK": "1", "LF_NETBLOCK_INTERVAL": "86400",
    "LF_NETBLOCK_COUNT": "4", "LF_NETBLOCK_CLASS": "C",
    "CC_DENY": "CN,RU,IN,BR,VN,TW,IR,KP,RO,UA,MD,PH",
    "CC_ALLOW": "",
}

ALERT_DEFAULTS: dict[str, str] = {
    "LF_ALERT_TO": "adrianguerraii@gmail.com",
    "LF_ALERT_FROM": "", "LF_ALERT_SMTP": "",
    "LF_EMAIL_ALERT": "1", "LF_TEMP_EMAIL_ALERT": "1",
    "LF_SSH_EMAIL_ALERT": "1", "LF_SU_EMAIL_ALERT": "1",
    "LF_WEBMIN_EMAIL_ALERT": "1", "LF_CONSOLE_EMAIL_ALERT": "1",
    "LF_PERMBLOCK_ALERT": "1", "LF_NETBLOCK_ALERT": "1",
}

# ---------------------------------------------------------------------------

VALIDATION_DIR = "/var/lib/frothiq-validation"
DECOMMISSION_LOG = f"{VALIDATION_DIR}/decommission-cron.log"
DECOMMISSION_FLAG = f"{VALIDATION_DIR}/DECOMMISSION_COMPLETE"
READY_FLAG = f"{VALIDATION_DIR}/DECOMMISSION_READY"
PASSES_FILE = f"{VALIDATION_DIR}/clean_passes"
LAST_CLEAN_FILE = f"{VALIDATION_DIR}/last_clean"

MANAGED_SERVICES = ["frothiq-nft", "frothiq-lfd", "csf", "lfd"]

# Default LFD settings seeded on first access
LFD_DEFAULTS = {
    "block_threshold": "5",
    "block_duration_minutes": "30",
    "permanent_block": "false",
    "email_alerts": "true",
    "alert_email": "adrianguerraii@gmail.com",
}

VALIDATION_DEFAULTS = {
    "interval_minutes": "60",
    "passes_required": "2",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run(cmd: list[str], sudo: bool = True) -> tuple[int, str, str]:
    """Run a shell command, optionally with sudo. Returns (returncode, stdout, stderr)."""
    if sudo:
        cmd = ["sudo"] + cmd
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        return 1, "", "Command timed out"
    except Exception as exc:
        return 1, "", str(exc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _audit(
    session: AsyncSession,
    user_email: str,
    action: str,
    category: str,
    detail: str | None = None,
    ip_address: str | None = None,
) -> None:
    session.add(FrothiqNftAudit(
        id=str(uuid.uuid4()),
        user_email=user_email,
        action=action,
        category=category,
        detail=detail,
        ip_address=ip_address,
        created_at=_utcnow(),
    ))
    await session.commit()


async def _get_setting(session: AsyncSession, category: str, key: str, default: str = "") -> str:
    row = await session.scalar(
        select(FrothiqNftSetting).where(
            FrothiqNftSetting.category == category,
            FrothiqNftSetting.key == key,
        )
    )
    return row.value if row else default


async def _set_setting(
    session: AsyncSession, category: str, key: str, value: str, updated_by: str
) -> None:
    existing = await session.scalar(
        select(FrothiqNftSetting).where(
            FrothiqNftSetting.category == category,
            FrothiqNftSetting.key == key,
        )
    )
    if existing:
        existing.value = value
        existing.updated_by = updated_by
        existing.updated_at = _utcnow()
    else:
        session.add(FrothiqNftSetting(
            id=str(uuid.uuid4()),
            category=category,
            key=key,
            value=value,
            updated_by=updated_by,
            updated_at=_utcnow(),
        ))
    await session.commit()


# ---------------------------------------------------------------------------
# Service Status
# ---------------------------------------------------------------------------

async def get_service_status() -> dict[str, Any]:
    """Return live systemctl status for all managed FrothIQ services."""
    results = {}
    for svc in MANAGED_SERVICES:
        rc, stdout, _ = await _run(["systemctl", "is-active", svc])
        state = stdout.strip() or ("active" if rc == 0 else "inactive")
        rc2, out2, _ = await _run(["systemctl", "show", svc, "--property=ActiveEnterTimestamp,ExecMainPID"])
        props: dict[str, str] = {}
        for line in out2.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k] = v
        results[svc] = {
            "service": svc,
            "state": state,
            "is_active": state == "active",
            "pid": props.get("ExecMainPID", ""),
            "since": props.get("ActiveEnterTimestamp", ""),
        }
    return {"services": results, "checked_at": _utcnow().isoformat()}


# ---------------------------------------------------------------------------
# Service Control
# ---------------------------------------------------------------------------

async def control_service(
    session: AsyncSession,
    service: str,
    action: str,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    """Start, stop, or restart a managed service."""
    if service not in MANAGED_SERVICES:
        return {"success": False, "error": f"Unknown service: {service}"}
    if action not in ("start", "stop", "restart"):
        return {"success": False, "error": f"Invalid action: {action}"}

    rc, stdout, stderr = await _run(["systemctl", action, service])
    success = rc == 0

    await _audit(
        session, user_email,
        f"{action.upper()} {service}",
        "service_control",
        f"rc={rc} {stderr[:200] if not success else 'ok'}",
        ip_address,
    )

    await asyncio.sleep(0.5)
    _, state_out, _ = await _run(["systemctl", "is-active", service])
    return {
        "success": success,
        "service": service,
        "action": action,
        "new_state": state_out.strip(),
        "error": stderr.strip() if not success else None,
    }


# ---------------------------------------------------------------------------
# nftables Viewer (read-only)
# ---------------------------------------------------------------------------

async def get_nft_view() -> dict[str, Any]:
    """
    Return a structured view of the active nftables ruleset.
    Read-only — no modifications made here.
    """
    rc, stdout, stderr = await _run(["nft", "-j", "list", "ruleset"])
    if rc != 0:
        # Fall back to text output
        rc2, txt, _ = await _run(["nft", "list", "ruleset"])
        return {
            "success": rc2 == 0,
            "format": "text",
            "raw": txt,
            "error": stderr.strip() if rc != 0 else None,
        }

    try:
        data = json.loads(stdout)
        nftables = data.get("nftables", [])
        tables: list[dict] = []
        chains: list[dict] = []
        sets: list[dict] = []
        rules: list[dict] = []

        for entry in nftables:
            if "table" in entry:
                tables.append(entry["table"])
            elif "chain" in entry:
                chains.append(entry["chain"])
            elif "set" in entry:
                sets.append(entry["set"])
            elif "rule" in entry:
                r = entry["rule"]
                rules.append({
                    "family": r.get("family"),
                    "table": r.get("table"),
                    "chain": r.get("chain"),
                    "handle": r.get("handle"),
                    "comment": r.get("comment"),
                    "expr": r.get("expr", []),
                })

        return {
            "success": True,
            "format": "structured",
            "tables": tables,
            "chains": chains,
            "sets": sets,
            "rules": rules,
            "rule_count": len(rules),
            "refreshed_at": _utcnow().isoformat(),
        }
    except json.JSONDecodeError:
        return {"success": True, "format": "text", "raw": stdout}


# ---------------------------------------------------------------------------
# IP List (shared whitelist / blacklist)
# ---------------------------------------------------------------------------

async def list_ip_entries(session: AsyncSession) -> list[dict[str, Any]]:
    rows = await session.scalars(select(FrothiqIPEntry).order_by(FrothiqIPEntry.created_at.desc()))
    return [
        {
            "id": r.id, "ip": r.ip, "label": r.label,
            "list_type": r.list_type, "notes": r.notes,
            "created_at": r.created_at.isoformat(), "created_by": r.created_by,
        }
        for r in rows
    ]


async def add_ip_entry(
    session: AsyncSession,
    ip: str,
    label: str,
    list_type: str,
    notes: str | None,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    if list_type not in ("whitelist", "blacklist"):
        return {"success": False, "error": "list_type must be whitelist or blacklist"}

    entry = FrothiqIPEntry(
        id=str(uuid.uuid4()),
        ip=ip.strip(),
        label=label.strip(),
        list_type=list_type,
        notes=notes,
        created_at=_utcnow(),
        created_by=user_email,
    )
    session.add(entry)
    await session.commit()

    await _audit(session, user_email, f"ADD_IP_{list_type.upper()}", "ip_list", f"{ip} — {label}", ip_address)
    return {"success": True, "id": entry.id}


async def remove_ip_entry(
    session: AsyncSession,
    entry_id: str,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    row = await session.get(FrothiqIPEntry, entry_id)
    if not row:
        return {"success": False, "error": "Entry not found"}

    detail = f"{row.ip} ({row.label}, {row.list_type})"
    await session.delete(row)
    await session.commit()
    await _audit(session, user_email, "REMOVE_IP", "ip_list", detail, ip_address)
    return {"success": True}


# ---------------------------------------------------------------------------
# Port Rules
# ---------------------------------------------------------------------------

async def list_port_rules(session: AsyncSession) -> list[dict[str, Any]]:
    rows = await session.scalars(select(FrothiqPortRule).order_by(FrothiqPortRule.port))
    return [
        {
            "id": r.id, "port": r.port, "protocol": r.protocol,
            "action": r.action, "description": r.description,
            "created_at": r.created_at.isoformat(), "created_by": r.created_by,
        }
        for r in rows
    ]


async def add_port_rule(
    session: AsyncSession,
    port: int,
    protocol: str,
    action: str,
    description: str,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    if not (1 <= port <= 65535):
        return {"success": False, "error": "Port must be 1–65535"}
    if protocol not in ("tcp", "udp", "both"):
        return {"success": False, "error": "protocol must be tcp, udp, or both"}
    if action not in ("accept", "drop"):
        return {"success": False, "error": "action must be accept or drop"}

    rule = FrothiqPortRule(
        id=str(uuid.uuid4()),
        port=port,
        protocol=protocol,
        action=action,
        description=description.strip(),
        created_at=_utcnow(),
        created_by=user_email,
    )
    session.add(rule)
    await session.commit()
    await _audit(session, user_email, "ADD_PORT_RULE", "port_rules", f"{port}/{protocol} → {action}", ip_address)
    return {"success": True, "id": rule.id}


async def remove_port_rule(
    session: AsyncSession,
    rule_id: str,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    row = await session.get(FrothiqPortRule, rule_id)
    if not row:
        return {"success": False, "error": "Rule not found"}

    detail = f"{row.port}/{row.protocol} → {row.action} ({row.description})"
    await session.delete(row)
    await session.commit()
    await _audit(session, user_email, "REMOVE_PORT_RULE", "port_rules", detail, ip_address)
    return {"success": True}


# ---------------------------------------------------------------------------
# Generic category settings (get/update) used by ports, lfd, blocking, alerts
# ---------------------------------------------------------------------------

async def get_category_settings(
    session: AsyncSession, category: str, defaults: dict[str, str]
) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, default in defaults.items():
        out[key] = await _get_setting(session, category, key, default)
    return out


async def update_category_settings(
    session: AsyncSession,
    category: str,
    settings: dict[str, Any],
    allowed_keys: Any,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    allowed = set(allowed_keys)
    for key, value in settings.items():
        if key not in allowed:
            continue
        await _set_setting(session, category, key, str(value), user_email)
    await _audit(session, user_email, f"UPDATE_{category.upper()}_SETTINGS", category,
                 json.dumps({k: v for k, v in settings.items() if k in allowed}), ip_address)
    return {"success": True}


# ---------------------------------------------------------------------------
# LFD Settings
# ---------------------------------------------------------------------------

async def get_lfd_settings(session: AsyncSession) -> dict[str, Any]:
    out: dict[str, str] = {}
    for key, default in LFD_DEFAULTS.items():
        out[key] = await _get_setting(session, "lfd", key, default)
    return out


async def update_lfd_settings(
    session: AsyncSession,
    settings: dict[str, str],
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    allowed = set(LFD_DEFAULTS.keys())
    for key, value in settings.items():
        if key not in allowed:
            continue
        await _set_setting(session, "lfd", key, str(value), user_email)

    await _audit(session, user_email, "UPDATE_LFD_SETTINGS", "lfd", json.dumps(settings), ip_address)
    return {"success": True}


# ---------------------------------------------------------------------------
# Validation Status
# ---------------------------------------------------------------------------

async def get_validation_status(session: AsyncSession) -> dict[str, Any]:
    """Read validation state from filesystem + settings from DB."""
    gate_open = os.path.exists(READY_FLAG)
    decommission_done = os.path.exists(DECOMMISSION_FLAG)

    clean_passes = 0
    try:
        with open(PASSES_FILE) as f:
            clean_passes = int(f.read().strip())
    except Exception:
        pass

    last_clean: str | None = None
    try:
        with open(LAST_CLEAN_FILE) as f:
            last_clean = f.read().strip()
    except Exception:
        pass

    interval = await _get_setting(session, "validation", "interval_minutes", VALIDATION_DEFAULTS["interval_minutes"])
    passes_req = await _get_setting(session, "validation", "passes_required", VALIDATION_DEFAULTS["passes_required"])

    # Check timer status
    rc, timer_out, _ = await _run(["systemctl", "show", "frothiq-validate.timer", "--property=ActiveState,NextElapseUSecRealtime"])
    timer_props: dict[str, str] = {}
    for line in timer_out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            timer_props[k] = v

    return {
        "gate_open": gate_open,
        "decommission_complete": decommission_done,
        "clean_passes": clean_passes,
        "passes_required": int(passes_req),
        "last_clean": last_clean,
        "interval_minutes": int(interval),
        "timer_active": timer_props.get("ActiveState") == "active",
        "timer_next": timer_props.get("NextElapseUSecRealtime", ""),
    }


async def update_validation_settings(
    session: AsyncSession,
    settings: dict[str, str],
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    allowed = set(VALIDATION_DEFAULTS.keys())
    for key, value in settings.items():
        if key not in allowed:
            continue
        await _set_setting(session, "validation", key, str(value), user_email)

    await _audit(session, user_email, "UPDATE_VALIDATION_SETTINGS", "validation", json.dumps(settings), ip_address)
    return {"success": True}


# ---------------------------------------------------------------------------
# Decommission
# ---------------------------------------------------------------------------

DECOMMISSION_SCRIPT = "/usr/local/bin/frothiq-decommission.sh"

async def get_decommission_status(session: AsyncSession) -> dict[str, Any]:
    """Check all 6 safety gates and overall decommission state."""
    done = os.path.exists(DECOMMISSION_FLAG)
    gate_open = os.path.exists(READY_FLAG)

    # Gate 1: DECOMMISSION_READY flag
    gate1 = gate_open

    # Gate 2: inet frothiq table active
    rc2, out2, _ = await _run(["nft", "list", "table", "inet", "frothiq"])
    gate2 = rc2 == 0

    # Gate 3: ≥2 drop rules present
    drop_count = out2.lower().count("drop")
    gate3 = drop_count >= 2

    # Gate 4: critical IPs whitelisted
    critical_ips = ["144.202.77.105", "144.202.64.118", "69.174.173.110"]
    gate4 = all(ip in out2 for ip in critical_ips)

    # Gate 5: frothiq-lfd active
    rc5, state5, _ = await _run(["systemctl", "is-active", "frothiq-lfd"])
    gate5 = state5.strip() == "active"

    # Gate 6: last clean < 90 min
    gate6 = False
    try:
        with open(LAST_CLEAN_FILE) as f:
            ts = float(f.read().strip())
        import time
        gate6 = (time.time() - ts) < 5400
    except Exception:
        pass

    # Read decommission log tail
    log_tail = ""
    try:
        with open(DECOMMISSION_LOG) as f:
            lines = f.readlines()
            log_tail = "".join(lines[-50:])
    except Exception:
        pass

    # Determine status
    if done:
        status = "completed"
    elif not gate_open:
        status = "not_started"
    else:
        status = "ready"

    return {
        "status": status,
        "decommission_complete": done,
        "gates": {
            "gate1_ready_flag": gate1,
            "gate2_nft_table_active": gate2,
            "gate3_drop_rules": gate3,
            "gate4_critical_ips": gate4,
            "gate5_lfd_active": gate5,
            "gate6_recent_validation": gate6,
        },
        "gates_passed": sum([gate1, gate2, gate3, gate4, gate5, gate6]),
        "gates_total": 6,
        "all_gates_passed": all([gate1, gate2, gate3, gate4, gate5, gate6]),
        "log_tail": log_tail,
    }


async def run_decommission(
    session: AsyncSession,
    user_email: str,
    ip_address: str | None,
) -> dict[str, Any]:
    """Trigger the decommission script. Re-triggerable — not one-time."""
    await _audit(session, user_email, "DECOMMISSION_TRIGGERED", "decommission", "Manual trigger via UI", ip_address)

    rc, stdout, stderr = await _run([DECOMMISSION_SCRIPT])
    success = rc == 0

    await _audit(
        session, user_email,
        "DECOMMISSION_COMPLETE" if success else "DECOMMISSION_FAILED",
        "decommission",
        f"rc={rc} {(stdout + stderr)[:500]}",
        ip_address,
    )

    return {
        "success": success,
        "return_code": rc,
        "stdout": stdout[-2000:],
        "stderr": stderr[-500:],
    }


# ---------------------------------------------------------------------------
# Defense Audit Log
# ---------------------------------------------------------------------------

async def get_defense_audit(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    category: str | None = None,
) -> dict[str, Any]:
    q = select(FrothiqNftAudit).order_by(FrothiqNftAudit.created_at.desc()).limit(limit).offset(offset)
    if category:
        q = q.where(FrothiqNftAudit.category == category)

    rows = await session.scalars(q)
    return {
        "entries": [
            {
                "id": r.id,
                "user_email": r.user_email,
                "action": r.action,
                "category": r.category,
                "detail": r.detail,
                "ip_address": r.ip_address,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
    }
