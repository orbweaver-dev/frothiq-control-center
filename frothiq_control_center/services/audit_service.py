"""
Audit logging service — records every admin action with full context.

All mutating admin actions must call log_action() before returning.
Read-only views log at DEBUG level only.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Redis key for real-time audit stream
_AUDIT_STREAM_KEY = "cc:audit:stream"
_AUDIT_STREAM_MAX_LEN = 10_000


async def log_action(
    action: str,
    user_id: str | None,
    user_email: str | None,
    resource: str | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
    status: str = "success",
    db=None,
    redis=None,
) -> None:
    """
    Log an admin action to:
      - PostgreSQL audit table (if db session provided)
      - Redis audit stream (if redis client provided)
      - Python logger (always)

    Args:
        action: Machine-readable action name, e.g. "license.revoke"
        user_id: ID of the acting admin user
        user_email: Email of the acting admin user
        resource: The affected resource identifier
        detail: Human-readable detail string
        ip_address: Client IP address
        status: "success" | "failure" | "denied"
        db: AsyncSession (optional)
        redis: Redis client (optional)
    """
    entry = {
        "user_id": user_id,
        "user_email": user_email,
        "action": action,
        "resource": resource,
        "detail": detail,
        "ip_address": ip_address,
        "status": status,
        "created_at": datetime.now(UTC).isoformat(),
    }

    # Always log to Python logger
    log_msg = (
        f"AUDIT | action={action} user={user_email or user_id or 'anonymous'} "
        f"resource={resource or '-'} status={status}"
    )
    if status == "success":
        logger.info(log_msg)
    else:
        logger.warning(log_msg)

    # Write to database
    if db is not None:
        try:
            from frothiq_control_center.models.user import AuditLog
            log_row = AuditLog(**entry)
            db.add(log_row)
            await db.commit()
        except Exception as exc:
            logger.error("Failed to write audit log to DB: %s", exc)

    # Write to Redis stream (for real-time WebSocket broadcast)
    if redis is not None:
        try:
            await redis.xadd(
                _AUDIT_STREAM_KEY,
                {k: json.dumps(v) if not isinstance(v, str) else v for k, v in entry.items() if v is not None},
                maxlen=_AUDIT_STREAM_MAX_LEN,
                approximate=True,
            )
        except Exception as exc:
            logger.error("Failed to write audit log to Redis stream: %s", exc)


async def get_recent_audit_log(
    db,
    page: int = 1,
    page_size: int = 50,
    action_filter: str | None = None,
    user_filter: str | None = None,
) -> dict[str, Any]:
    """
    Fetch paginated audit log entries from PostgreSQL.
    """
    from sqlalchemy import desc, select
    from frothiq_control_center.models.user import AuditLog

    offset = (page - 1) * page_size
    q = select(AuditLog).order_by(desc(AuditLog.created_at)).offset(offset).limit(page_size)

    if action_filter:
        q = q.where(AuditLog.action.ilike(f"%{action_filter}%"))
    if user_filter:
        q = q.where(AuditLog.user_email.ilike(f"%{user_filter}%"))

    try:
        result = await db.execute(q)
        rows = result.scalars().all()

        # Count query
        from sqlalchemy import func
        count_q = select(func.count()).select_from(AuditLog)
        if action_filter:
            count_q = count_q.where(AuditLog.action.ilike(f"%{action_filter}%"))
        if user_filter:
            count_q = count_q.where(AuditLog.user_email.ilike(f"%{user_filter}%"))
        total = (await db.execute(count_q)).scalar() or 0

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "entries": [
                {
                    "id": r.id,
                    "user_id": r.user_id,
                    "user_email": r.user_email,
                    "action": r.action,
                    "resource": r.resource,
                    "detail": r.detail,
                    "ip_address": r.ip_address,
                    "status": r.status,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ],
        }
    except Exception as exc:
        logger.error("Audit log query failed: %s", exc)
        return {"total": 0, "page": page, "page_size": page_size, "entries": []}
