"""
Frappe / ERPNext billing integration — tenant accounting on registration.

GAAP compliance (ASC 606 — Revenue from Contracts with Customers):
  • Every new tenant gets a Customer record and a Subscription in ERPNext,
    regardless of plan tier.
  • Free plan ($0): No revenue journal entry — nothing is exchanged, so nothing
    is recognised. The Subscription documents the $0 performance obligation.
  • Paid monthly plan: ERPNext Subscription auto-generates a Sales Invoice at
    the start of each billing period. Dr Accounts Receivable / Cr Service Revenue.
  • Paid annual plan: Upfront invoice flows through Deferred Subscription Revenue
    (Current Liability). Each month: Dr Deferred Sub Revenue / Cr Service Revenue
    (1/12 amortisation). ERPNext Subscription handles this automatically when
    the Item has a deferred_revenue_account set.

ERPNext objects created per tenant:
  1. Customer  — one per domain, Customer Group "FrothIQ"
  2. Subscription — one per Customer, Subscription Plan = plan tier

Called fire-and-forget (asyncio.create_task) from register_edge_node() so the
HTTP registration response is never delayed by ERPNext latency.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date
from typing import Any

import httpx

from frothiq_control_center.config import get_settings

logger = logging.getLogger(__name__)

# ERPNext Subscription Plan names — must match what was created in Frappe
_PLAN_MAP: dict[str, str] = {
    "free":       "FrothIQ Free",
    "pro":        "FrothIQ Pro",
    "enterprise": "FrothIQ Enterprise",
}

_CUSTOMER_GROUP = "FrothIQ"
_TERRITORY      = "All Territories"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _headers() -> dict[str, str]:
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


# ─────────────────────────────────────────────────────────────────────────────
# Customer
# ─────────────────────────────────────────────────────────────────────────────

async def get_or_create_customer(
    tenant_id: str,
    domain: str,
    contact_email: str | None,
    plan: str,
) -> str | None:
    """
    Idempotent: finds an existing Customer by name (= domain) or creates one.
    Returns the ERPNext Customer document name, or None on error.

    Customer name = domain so the record is human-readable in ERPNext and
    can be looked up without a custom field query.
    """
    if not _enabled():
        return None

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            # Check if customer already exists
            resp = await client.get(
                f"{_base()}/api/resource/Customer/{domain}",
                headers=_headers(),
            )
            if resp.status_code == 200:
                logger.info("frappe_billing: customer '%s' already exists", domain)
                return domain

            payload: dict[str, Any] = {
                "customer_name":  domain,
                "customer_type":  "Company",
                "customer_group": _CUSTOMER_GROUP,
                "territory":      _TERRITORY,
                # Embed tenant_id + plan in the customer notes for traceability
                "customer_details": (
                    f"FrothIQ MC3 tenant\n"
                    f"tenant_id: {tenant_id}\n"
                    f"plan: {plan}"
                ),
            }
            if contact_email:
                payload["email_id"] = contact_email

            resp = await client.post(
                f"{_base()}/api/resource/Customer",
                json=payload,
                headers=_headers(),
            )
            resp.raise_for_status()
            name = resp.json().get("data", {}).get("name", domain)
            logger.info(
                "frappe_billing: created Customer '%s' tenant=%s plan=%s",
                name, tenant_id[:8], plan,
            )
            return name

    except Exception as exc:
        logger.error("frappe_billing: get_or_create_customer failed for '%s': %s", domain, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Subscription
# ─────────────────────────────────────────────────────────────────────────────

async def get_or_create_subscription(
    customer_name: str,
    plan: str,
    tenant_id: str,
) -> str | None:
    """
    Idempotent: finds an Active/Trialling Subscription for this customer or creates one.
    Returns the ERPNext Subscription document name, or None on error.

    GAAP note: For free ($0) plan, ERPNext generates a $0 Sales Invoice each
    billing period documenting the fulfilled performance obligation. No cash or
    revenue movement occurs — the invoice closes immediately at zero.
    For paid plans, the Sales Invoice creates Dr AR / Cr Service Revenue.
    Annual pre-paid plans flow through Deferred Subscription Revenue.
    """
    if not _enabled():
        return None

    plan_name = _PLAN_MAP.get(plan, "FrothIQ Free")

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            # Check for existing active subscription
            resp = await client.get(
                f"{_base()}/api/resource/Subscription",
                params={
                    "filters": f'[["party","=","{customer_name}"],["status","in","Active,Trialling"]]',
                    "fields":  '["name","status"]',
                    "limit_page_length": 1,
                },
                headers=_headers(),
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    logger.info(
                        "frappe_billing: subscription '%s' already exists for '%s'",
                        data[0]["name"], customer_name,
                    )
                    return data[0]["name"]

            today = date.today().isoformat()
            payload: dict[str, Any] = {
                "party_type": "Customer",
                "party":      customer_name,
                "start":      today,
                "plans": [{"plan": plan_name, "qty": 1}],
                # Generate invoice at the beginning of each period (standard SaaS)
                "generate_invoice_at": "Beginning of the current subscription period",
                "submit_invoice": 1,
            }

            resp = await client.post(
                f"{_base()}/api/resource/Subscription",
                json=payload,
                headers=_headers(),
            )
            resp.raise_for_status()
            name = resp.json().get("data", {}).get("name")
            logger.info(
                "frappe_billing: created Subscription '%s' for '%s' plan='%s'",
                name, customer_name, plan_name,
            )
            return name

    except Exception as exc:
        logger.error(
            "frappe_billing: get_or_create_subscription failed for '%s': %s",
            customer_name, exc,
        )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator — called from register_edge_node via asyncio.create_task
# ─────────────────────────────────────────────────────────────────────────────

async def sync_new_tenant(
    tenant_id: str,
    domain: str,
    contact_email: str | None,
    plan: str,
) -> dict[str, Any]:
    """
    Creates ERPNext Customer + Subscription for a brand-new tenant.
    Writes the ERPNext document names back to EdgeTenant for bidirectional linkage.

    Always fire-and-forget — never awaited in the registration hot path.
    Failures are logged but do not affect edge node registration.
    """
    logger.info("frappe_billing: syncing new tenant %s (%s) plan=%s", tenant_id[:8], domain, plan)

    customer = await get_or_create_customer(tenant_id, domain, contact_email, plan)
    if not customer:
        logger.error("frappe_billing: aborting sync for %s — customer creation failed", domain)
        return {"ok": False, "error": "customer_creation_failed", "domain": domain}

    subscription = await get_or_create_subscription(customer, plan, tenant_id)

    # Write ERPNext refs back to EdgeTenant row
    await _store_erpnext_refs(tenant_id, customer, subscription)

    result = {
        "ok": True,
        "tenant_id":    tenant_id,
        "domain":       domain,
        "plan":         plan,
        "customer":     customer,
        "subscription": subscription,
    }
    logger.info("frappe_billing: sync complete %s", result)
    return result


async def _store_erpnext_refs(
    tenant_id: str,
    customer: str | None,
    subscription: str | None,
) -> None:
    """Persist ERPNext Customer/Subscription names back to EdgeTenant."""
    if not customer and not subscription:
        return
    try:
        from frothiq_control_center.integrations.database import get_session_factory
        from frothiq_control_center.models.edge import EdgeTenant
        from sqlalchemy import select

        factory = get_session_factory()
        async with factory() as session:
            result = await session.execute(
                select(EdgeTenant).where(EdgeTenant.tenant_id == tenant_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant:
                if customer:
                    tenant.erpnext_customer = customer
                if subscription:
                    tenant.erpnext_subscription = subscription
                await session.commit()
                logger.info(
                    "frappe_billing: EdgeTenant %s updated — customer=%s subscription=%s",
                    tenant_id[:8], customer, subscription,
                )
    except Exception as exc:
        logger.error("frappe_billing: failed to store ERPNext refs for %s: %s", tenant_id[:8], exc)
