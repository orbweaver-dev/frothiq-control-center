"""
MC² Theme System — operator-editable named themes.

Closes TASK-2026-00242.

Themes are CSS-variable bundles (colors / typography / spacing / radius).
Stored in MariaDB; one is marked active. Frontend reads the active theme
once on load and applies the variables to :root via inline style. Editing
happens server-side so changes survive bench restarts and roll out to
all operators.

The DDL is created lazily on first request (idempotent) so this module
doesn't need to touch shared database.py.
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from mc2.auth import TokenPayload, require_super_admin
from mc2.integrations.database import get_engine


router = APIRouter(prefix="/themes", tags=["themes"])

Auth = Annotated[TokenPayload, Depends(require_super_admin)]


# ─────────────────────────────────────────────────────────────────────────────
# Defaults — must match the variables actually referenced in mc2-ui CSS.
# These are exported as a "Default" theme on first DDL run.
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_THEME_VARS = {
    # Brand palette
    "--brand-primary":    "#3b82f6",
    "--brand-secondary":  "#10b981",
    "--brand-accent":     "#f59e0b",
    "--brand-danger":     "#ef4444",
    # Surface palette
    "--bg-base":          "#0a0e1a",
    "--bg-surface":       "#0d1526",
    "--bg-elevated":      "#1e2d4a",
    # Text
    "--text-primary":     "#e2e8f0",
    "--text-secondary":   "#94a3b8",
    "--text-muted":       "#64748b",
    # Typography
    "--font-sans":        '"Inter", system-ui, sans-serif',
    "--font-mono":        '"JetBrains Mono", ui-monospace, monospace',
    "--font-size-base":   "14px",
    # Shape
    "--radius-sm":        "4px",
    "--radius-md":        "8px",
    "--radius-lg":        "16px",
    # Spacing scale base
    "--spacing-base":     "4px",
}


_ddl_done = False


async def _ensure_table() -> None:
    """Idempotent table creation on first request."""
    global _ddl_done
    if _ddl_done:
        return
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS cc_themes ("
            "  id          VARCHAR(36) PRIMARY KEY,"
            "  name        VARCHAR(64) NOT NULL UNIQUE,"
            "  vars        JSON NOT NULL,"
            "  is_active   BOOLEAN NOT NULL DEFAULT FALSE,"
            "  is_builtin  BOOLEAN NOT NULL DEFAULT FALSE,"
            "  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP "
            "                 ON UPDATE CURRENT_TIMESTAMP,"
            "  KEY idx_themes_active (is_active)"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        ))
        # Seed Default theme if no rows exist
        result = await conn.execute(text("SELECT COUNT(*) FROM cc_themes"))
        count = result.scalar()
        if count == 0:
            await conn.execute(
                text(
                    "INSERT INTO cc_themes (id, name, vars, is_active, is_builtin) "
                    "VALUES (:id, :name, :vars, TRUE, TRUE)"
                ),
                {
                    "id":   str(uuid.uuid4()),
                    "name": "Default",
                    "vars": json.dumps(DEFAULT_THEME_VARS),
                },
            )
    _ddl_done = True


async def _row_to_dict(row) -> dict:
    """SQLAlchemy Row → JSON-safe dict. vars is a JSON column."""
    raw_vars = row.vars
    if isinstance(raw_vars, (bytes, bytearray)):
        raw_vars = raw_vars.decode("utf-8")
    if isinstance(raw_vars, str):
        try: raw_vars = json.loads(raw_vars)
        except Exception: raw_vars = {}
    return {
        "id":         row.id,
        "name":       row.name,
        "vars":       raw_vars or {},
        "is_active":  bool(row.is_active),
        "is_builtin": bool(row.is_builtin),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("")
async def list_themes(_: Auth):
    await _ensure_table()
    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(text(
            "SELECT id, name, vars, is_active, is_builtin, created_at, updated_at "
            "FROM cc_themes ORDER BY is_builtin DESC, name ASC"
        ))
        rows = [await _row_to_dict(r) for r in result.mappings().all()]
    return {"themes": rows, "count": len(rows)}


@router.get("/active")
async def active_theme(_: Auth):
    """Convenience endpoint for the UI bootstrap — fetch only the active theme."""
    await _ensure_table()
    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(text(
            "SELECT id, name, vars, is_active, is_builtin, created_at, updated_at "
            "FROM cc_themes WHERE is_active = TRUE LIMIT 1"
        ))
        row = result.mappings().first()
    if not row:
        return {"theme": None, "vars": DEFAULT_THEME_VARS}
    d = await _row_to_dict(row)
    return {"theme": d, "vars": d["vars"]}


class ThemeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    vars: dict[str, str] = Field(default_factory=dict)
    seed_from_default: bool = False


@router.post("")
async def create_theme(body: ThemeCreate, _: Auth):
    await _ensure_table()
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    merged = dict(DEFAULT_THEME_VARS) if body.seed_from_default else {}
    merged.update(body.vars or {})
    new_id = str(uuid.uuid4())
    engine = get_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO cc_themes (id, name, vars, is_active, is_builtin) "
                    "VALUES (:id, :name, :vars, FALSE, FALSE)"
                ),
                {"id": new_id, "name": body.name.strip(), "vars": json.dumps(merged)},
            )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"insert failed: {str(e)[:200]}")
    return {"id": new_id, "name": body.name, "created": True}


class ThemeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    vars: dict[str, str] | None = None


@router.put("/{theme_id}")
async def update_theme(theme_id: str, body: ThemeUpdate, _: Auth):
    await _ensure_table()
    engine = get_engine()
    async with engine.connect() as conn:
        existing = (await conn.execute(
            text("SELECT id, name, vars, is_builtin FROM cc_themes WHERE id = :id"),
            {"id": theme_id},
        )).mappings().first()
    if not existing:
        raise HTTPException(status_code=404, detail="theme not found")
    if existing["is_builtin"] and body.name:
        raise HTTPException(status_code=400, detail="cannot rename a built-in theme")

    new_name = (body.name or existing["name"]).strip()
    raw = existing["vars"]
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    current_vars = json.loads(raw) if isinstance(raw, str) else (raw or {})
    if body.vars is not None:
        current_vars = {**current_vars, **body.vars}

    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE cc_themes SET name = :name, vars = :vars WHERE id = :id"),
            {"id": theme_id, "name": new_name, "vars": json.dumps(current_vars)},
        )
    return {"id": theme_id, "name": new_name, "updated": True}


@router.delete("/{theme_id}")
async def delete_theme(theme_id: str, _: Auth):
    await _ensure_table()
    engine = get_engine()
    async with engine.connect() as conn:
        existing = (await conn.execute(
            text("SELECT id, is_active, is_builtin FROM cc_themes WHERE id = :id"),
            {"id": theme_id},
        )).mappings().first()
    if not existing:
        raise HTTPException(status_code=404, detail="theme not found")
    if existing["is_builtin"]:
        raise HTTPException(status_code=400, detail="cannot delete a built-in theme")
    if existing["is_active"]:
        raise HTTPException(status_code=400, detail="cannot delete the active theme; switch active first")
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM cc_themes WHERE id = :id"), {"id": theme_id})
    return {"id": theme_id, "deleted": True}


@router.post("/{theme_id}/activate")
async def activate_theme(theme_id: str, _: Auth):
    await _ensure_table()
    engine = get_engine()
    async with engine.connect() as conn:
        existing = (await conn.execute(
            text("SELECT id FROM cc_themes WHERE id = :id"),
            {"id": theme_id},
        )).mappings().first()
    if not existing:
        raise HTTPException(status_code=404, detail="theme not found")
    async with engine.begin() as conn:
        # Flip everything off, then set just this one active.
        await conn.execute(text("UPDATE cc_themes SET is_active = FALSE"))
        await conn.execute(
            text("UPDATE cc_themes SET is_active = TRUE WHERE id = :id"),
            {"id": theme_id},
        )
    return {"id": theme_id, "activated": True}


@router.get("/{theme_id}/export")
async def export_theme(theme_id: str, _: Auth):
    """Return a self-contained JSON object suitable for the import endpoint."""
    await _ensure_table()
    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT id, name, vars, is_active, is_builtin FROM cc_themes "
                "WHERE id = :id"
            ),
            {"id": theme_id},
        )
        row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="theme not found")
    d = await _row_to_dict(row)
    return {
        "schema":  "mc2.theme/v1",
        "name":    d["name"],
        "vars":    d["vars"],
    }


class ThemeImport(BaseModel):
    schema_: str = Field(alias="schema", default="mc2.theme/v1")
    name: str
    vars: dict[str, str]
    overwrite: bool = False


@router.post("/import")
async def import_theme(body: ThemeImport, _: Auth):
    await _ensure_table()
    if body.schema_ != "mc2.theme/v1":
        raise HTTPException(status_code=400, detail=f"unsupported schema: {body.schema_}")
    engine = get_engine()
    async with engine.connect() as conn:
        existing = (await conn.execute(
            text("SELECT id, is_builtin FROM cc_themes WHERE name = :name"),
            {"name": body.name},
        )).mappings().first()
    if existing and not body.overwrite:
        raise HTTPException(status_code=409, detail=f"theme '{body.name}' already exists; pass overwrite=true to replace")
    if existing and existing["is_builtin"]:
        raise HTTPException(status_code=400, detail="cannot overwrite a built-in theme")

    if existing:
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE cc_themes SET vars = :vars WHERE id = :id"),
                {"id": existing["id"], "vars": json.dumps(body.vars)},
            )
        return {"id": existing["id"], "name": body.name, "updated": True}

    new_id = str(uuid.uuid4())
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO cc_themes (id, name, vars, is_active, is_builtin) "
                "VALUES (:id, :name, :vars, FALSE, FALSE)"
            ),
            {"id": new_id, "name": body.name, "vars": json.dumps(body.vars)},
        )
    return {"id": new_id, "name": body.name, "created": True}
