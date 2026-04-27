"""
Dev Reports API — stores Claude Code session task-completion reports.

  GET  /api/v1/cc/dev/reports          — list all reports (paginated)
  GET  /api/v1/cc/dev/reports/{id}     — single report
  POST /api/v1/cc/dev/reports          — create a new report (super_admin only)
  DELETE /api/v1/cc/dev/reports/{id}   — delete a report (super_admin only)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text

from frothiq_control_center.auth.jwt_handler import TokenPayload, get_current_user, require_role
from frothiq_control_center.integrations.database import get_session_factory

router = APIRouter(prefix="/dev/reports", tags=["dev-reports"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CreateReportRequest(BaseModel):
    task_ref: str = ""
    title: str
    content: str
    status: str = "completed"
    tags: list[str] = []
    github_commit: str = ""
    github_issue: str = ""
    files_changed: list[str] = []


# ─────────────────────────────────────────────────────────────────────────────

@router.get("")
async def list_reports(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    current_user: TokenPayload = Depends(get_current_user),
):
    factory = get_session_factory()
    async with factory() as session:
        where = "1=1"
        params: dict = {"limit": min(limit, 200), "offset": offset}
        if status:
            where += " AND status = :status"
            params["status"] = status

        total = (await session.execute(
            text(f"SELECT COUNT(*) FROM dev_reports WHERE {where}"), params
        )).scalar_one()

        rows = (await session.execute(
            text(
                f"SELECT id, created_at, task_ref, title, status, tags, "
                f"github_commit, github_issue, files_changed, "
                f"LEFT(content, 300) AS preview "
                f"FROM dev_reports WHERE {where} "
                f"ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            ),
            params,
        )).all()

    return {
        "total": total,
        "reports": [
            {
                "id":             r.id,
                "created_at":     r.created_at.isoformat(),
                "task_ref":       r.task_ref,
                "title":          r.title,
                "status":         r.status,
                "tags":           json.loads(r.tags or "[]"),
                "github_commit":  r.github_commit,
                "github_issue":   r.github_issue,
                "files_changed":  json.loads(r.files_changed or "[]"),
                "preview":        r.preview,
            }
            for r in rows
        ],
    }


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
):
    factory = get_session_factory()
    async with factory() as session:
        row = (await session.execute(
            text("SELECT * FROM dev_reports WHERE id = :id"),
            {"id": report_id},
        )).one_or_none()

    if row is None:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id":             row.id,
        "created_at":     row.created_at.isoformat(),
        "task_ref":       row.task_ref,
        "title":          row.title,
        "content":        row.content,
        "status":         row.status,
        "tags":           json.loads(row.tags or "[]"),
        "github_commit":  row.github_commit,
        "github_issue":   row.github_issue,
        "files_changed":  json.loads(row.files_changed or "[]"),
    }


@router.post("")
async def create_report(
    body: CreateReportRequest,
    request: Request,
    current_user: TokenPayload = Depends(require_role("super_admin")),
):
    report_id = str(uuid.uuid4())
    factory = get_session_factory()
    async with factory() as session:
        await session.execute(
            text(
                "INSERT INTO dev_reports "
                "(id, created_at, task_ref, title, content, status, tags, "
                "github_commit, github_issue, files_changed) "
                "VALUES (:id, :ts, :task_ref, :title, :content, :status, :tags, "
                ":commit, :issue, :files)"
            ),
            {
                "id":       report_id,
                "ts":       _utcnow(),
                "task_ref": body.task_ref,
                "title":    body.title,
                "content":  body.content,
                "status":   body.status,
                "tags":     json.dumps(body.tags),
                "commit":   body.github_commit,
                "issue":    body.github_issue,
                "files":    json.dumps(body.files_changed),
            },
        )
        await session.commit()

    return {"id": report_id, "status": "created"}


@router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    request: Request,
    current_user: TokenPayload = Depends(require_role("super_admin")),
):
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            text("DELETE FROM dev_reports WHERE id = :id"),
            {"id": report_id},
        )
        await session.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Report not found")

    return {"status": "deleted"}
