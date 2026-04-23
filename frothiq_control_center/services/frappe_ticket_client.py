"""
Frappe / ERPNext ticket integration.

Creates, queries, amends, and resolves Issues in orbweaver.dev's ERPNext instance.

Deduplication pattern:
  1. find_open_issue(ref_tag)  → existing name, or None
  2a. None     → create_issue()      (new failure)
  2b. existing → append_to_issue()   (recurring failure — amend, don't duplicate)
  3. On recovery → resolve_issue()
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

# Tag embedded in every Issue subject so we can look it up later
_SUBJECT_PREFIX = "[FrothIQ]"


def _headers() -> dict:
    s = get_settings()
    return {
        "Authorization": f"token {s.frappe_api_key}:{s.frappe_api_secret}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _base() -> str:
    return get_settings().frappe_site_url.rstrip("/")


def _enabled() -> bool:
    s = get_settings()
    return bool(s.frappe_site_url and s.frappe_api_key and s.frappe_api_secret)


async def find_open_issue(ref_tag: str) -> Optional[str]:
    """
    Search for an open Frappe Issue whose subject contains ref_tag.
    Returns the Issue name (e.g. "ISS-2026-00042") or None.
    ref_tag should be a unique identifier embedded in the subject, e.g. edge_id.
    """
    if not _enabled():
        return None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{_base()}/api/resource/Issue",
                params={
                    "filters": f'[["subject","like","%{ref_tag}%"],["status","in","Open,Replied"]]',
                    "fields": '["name","subject","status"]',
                    "limit_page_length": 5,
                },
                headers=_headers(),
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            if data:
                return data[0]["name"]
    except Exception as exc:
        logger.warning("frappe_ticket: find_open_issue failed: %s", exc)
    return None


async def create_issue(
    subject: str,
    description: str,
    raised_by: str = "frothiq-system@orbweaver.dev",
    priority: str = "High",
) -> Optional[str]:
    """
    Create a new ERPNext Issue.
    Returns the Issue name on success, None on failure.
    Subject is automatically prefixed with [FrothIQ] for later lookup.
    """
    if not _enabled():
        return None
    s = get_settings()
    full_subject = f"{_SUBJECT_PREFIX} {subject}"
    payload = {
        "subject": full_subject[:140],
        "raised_by": raised_by,
        "status": "Open",
        "priority": priority,
        "description": description,
    }
    if s.frappe_issue_type:
        payload["issue_type"] = s.frappe_issue_type
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{_base()}/api/resource/Issue",
                json=payload,
                headers=_headers(),
            )
            resp.raise_for_status()
            name = resp.json().get("data", {}).get("name")
            logger.info("frappe_ticket: created Issue %s — %s", name, full_subject[:80])
            return name
    except Exception as exc:
        logger.error("frappe_ticket: create_issue failed: %s", exc)
    return None


async def append_to_issue(issue_name: str, note: str) -> bool:
    """
    Add a Comment to an existing ERPNext Issue with updated failure information.
    Called when find_open_issue() returns an existing ticket so each new
    occurrence of the failure is recorded without creating a duplicate ticket.
    Returns True on success.
    """
    if not _enabled() or not issue_name:
        return False
    payload = {
        "comment_type": "Comment",
        "reference_doctype": "Issue",
        "reference_name": issue_name,
        "content": note[:2000],
        "comment_by": "frothiq-system@orbweaver.dev",
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{_base()}/api/resource/Comment",
                json=payload,
                headers=_headers(),
            )
            resp.raise_for_status()
            logger.info("frappe_ticket: appended comment to Issue %s", issue_name)
            return True
    except Exception as exc:
        logger.error("frappe_ticket: append_to_issue %s failed: %s", issue_name, exc)
    return False


async def resolve_issue(issue_name: str, resolution_note: str = "") -> bool:
    """
    Mark an existing ERPNext Issue as Resolved and add a resolution note.
    Returns True on success.
    """
    if not _enabled() or not issue_name:
        return False
    payload: dict = {"status": "Resolved"}
    if resolution_note:
        payload["resolution_details"] = resolution_note[:1000]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.put(
                f"{_base()}/api/resource/Issue/{issue_name}",
                json=payload,
                headers=_headers(),
            )
            resp.raise_for_status()
            logger.info("frappe_ticket: resolved Issue %s", issue_name)
            return True
    except Exception as exc:
        logger.error("frappe_ticket: resolve_issue %s failed: %s", issue_name, exc)
    return False


async def get_issues_for_edge(edge_id: str, limit: int = 10) -> list[dict]:
    """
    Return recent Issues whose subject contains the edge_id.
    Used by the plugin ticket proxy endpoint.
    """
    if not _enabled():
        return []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{_base()}/api/resource/Issue",
                params={
                    "filters": f'[["subject","like","%{edge_id}%"]]',
                    "fields": '["name","subject","status","priority","creation","modified"]',
                    "limit_page_length": limit,
                    "order_by": "creation desc",
                },
                headers=_headers(),
            )
            resp.raise_for_status()
            return resp.json().get("data", [])
    except Exception as exc:
        logger.warning("frappe_ticket: get_issues_for_edge failed: %s", exc)
    return []
