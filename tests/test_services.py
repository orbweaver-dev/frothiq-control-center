"""
Unit tests for all service modules.
Tests business logic, failover, and data transformation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from frothiq_control_center.services.core_client import CoreClientError
from frothiq_control_center.services import (
    defense_service,
    envelope_service,
    flywheel_service,
    license_service,
    monetization_service,
    policy_service,
    simulation_service,
)
from frothiq_control_center.services.monetization_service import (
    _compute_rpi,
    _estimate_paywall_hits,
    _estimate_upgrade_signals,
    _next_plan,
)
from frothiq_control_center.services.defense_service import _severity_to_priority
from frothiq_control_center.services.envelope_service import (
    _compute_diff,
    _verify_envelope_signature,
)
from frothiq_control_center.services.license_service import (
    _derive_license_status,
    _is_sync_healthy,
)


# ---------------------------------------------------------------------------
# Defense service
# ---------------------------------------------------------------------------

class TestDefenseService:
    @pytest.mark.asyncio
    async def test_get_all_clusters_success(self, mock_core_client):
        mock_core_client.get.return_value = {"clusters": [{"severity": "high"}], "total": 1}
        with patch("frothiq_control_center.services.defense_service.core_client", mock_core_client):
            result = await defense_service.get_all_clusters()
        assert result["success"] is True
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_all_clusters_core_offline(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Core offline")
        with patch("frothiq_control_center.services.defense_service.core_client", mock_core_client):
            result = await defense_service.get_all_clusters()
        assert result["success"] is False
        assert result["engine_healthy"] is False

    @pytest.mark.asyncio
    async def test_suggested_actions_sorted_by_priority(self, mock_core_client):
        mock_core_client.get.return_value = {
            "clusters": [
                {"cluster_id": "c1", "severity": "low", "action": "monitor", "auto_apply_eligible": True, "campaign_ids": []},
                {"cluster_id": "c2", "severity": "critical", "action": "block_asn", "auto_apply_eligible": True, "campaign_ids": ["a", "b"]},
                {"cluster_id": "c3", "severity": "medium", "action": "rate_limit", "auto_apply_eligible": True, "campaign_ids": ["x"]},
            ]
        }
        with patch("frothiq_control_center.services.defense_service.core_client", mock_core_client):
            actions = await defense_service.get_suggested_actions()
        assert actions[0]["severity"] == "critical"
        assert actions[-1]["severity"] == "low"

    @pytest.mark.asyncio
    async def test_suggested_actions_excludes_non_eligible(self, mock_core_client):
        mock_core_client.get.return_value = {
            "clusters": [
                {"cluster_id": "c1", "severity": "high", "action": "block", "auto_apply_eligible": False, "campaign_ids": []},
            ]
        }
        with patch("frothiq_control_center.services.defense_service.core_client", mock_core_client):
            actions = await defense_service.get_suggested_actions()
        assert len(actions) == 0

    @pytest.mark.asyncio
    async def test_propagation_graph_structure(self, mock_core_client):
        mock_core_client.get.return_value = {
            "clusters": [
                {"cluster_id": "cluster-1", "campaign_ids": ["camp-a", "camp-b"], "severity": "high"},
            ]
        }
        with patch("frothiq_control_center.services.defense_service.core_client", mock_core_client):
            graph = await defense_service.get_propagation_graph()
        assert len(graph["nodes"]) == 1
        assert len(graph["edges"]) == 2

    def test_severity_to_priority(self):
        assert _severity_to_priority("critical") == 4
        assert _severity_to_priority("high") == 3
        assert _severity_to_priority("medium") == 2
        assert _severity_to_priority("low") == 1
        assert _severity_to_priority("unknown") == 0


# ---------------------------------------------------------------------------
# License service
# ---------------------------------------------------------------------------

class TestLicenseService:
    @pytest.mark.asyncio
    async def test_get_all_license_states_success(self, mock_core_client):
        mock_core_client.get.return_value = {
            "tenants": [
                {"tenant_id": "t1", "plan": "pro", "max_sites": 10, "active_sites": 5},
            ]
        }
        with patch("frothiq_control_center.services.license_service.core_client", mock_core_client):
            result = await license_service.get_all_license_states()
        assert result["success"] is True
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_all_license_states_core_failure(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("frothiq_control_center.services.license_service.core_client", mock_core_client):
            result = await license_service.get_all_license_states()
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_revoke_license_calls_core(self, mock_core_client):
        mock_core_client.post.return_value = {"revoked": True}
        with patch("frothiq_control_center.services.license_service.core_client", mock_core_client):
            result = await license_service.revoke_license("t1", "Non-payment", "admin@cc.io")
        assert result["success"] is True
        mock_core_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_license_core_failure(self, mock_core_client):
        mock_core_client.post.side_effect = CoreClientError(500, "Error")
        with patch("frothiq_control_center.services.license_service.core_client", mock_core_client):
            result = await license_service.revoke_license("t1", "test", "admin")
        assert result["success"] is False
        assert "error" in result

    def test_derive_license_status_suspended(self):
        assert _derive_license_status({"suspended": True}) == "suspended"

    def test_derive_license_status_expired(self):
        assert _derive_license_status({"expired": True}) == "expired"

    def test_derive_license_status_trial(self):
        assert _derive_license_status({"plan": "trial"}) == "trial"

    def test_derive_license_status_active(self):
        assert _derive_license_status({"plan": "pro"}) == "active"

    def test_sync_healthy_recent_sync(self):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert _is_sync_healthy({"last_sync": recent}) is True

    def test_sync_unhealthy_old_sync(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
        assert _is_sync_healthy({"last_sync": old}) is False

    def test_sync_unhealthy_no_sync(self):
        assert _is_sync_healthy({"last_sync": None}) is False

    @pytest.mark.asyncio
    async def test_sync_health_returns_pct(self, mock_core_client):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        mock_core_client.get.return_value = {
            "tenants": [
                {"tenant_id": "t1", "plan": "pro", "max_sites": 10, "active_sites": 5, "last_sync": recent},
                {"tenant_id": "t2", "plan": "free", "max_sites": 1, "active_sites": 0, "last_sync": None},
            ],
            "total": 2,
        }
        with patch("frothiq_control_center.services.license_service.core_client", mock_core_client):
            result = await license_service.get_sync_health()
        assert result["health_pct"] == 50.0


# ---------------------------------------------------------------------------
# Envelope service
# ---------------------------------------------------------------------------

class TestEnvelopeService:
    def test_verify_envelope_with_signature(self):
        env = {"signature": "sha256:validhash12345678"}
        assert _verify_envelope_signature(env) is True

    def test_verify_envelope_without_signature_permissive(self):
        env = {"version": "v1", "sections": {}}
        assert _verify_envelope_signature(env) is True

    def test_compute_diff_added_key(self):
        old = {"a": 1}
        new = {"a": 1, "b": 2}
        changes = _compute_diff(old, new)
        assert any(c["op"] == "add" and c["path"] == "b" for c in changes)

    def test_compute_diff_removed_key(self):
        old = {"a": 1, "b": 2}
        new = {"a": 1}
        changes = _compute_diff(old, new)
        assert any(c["op"] == "remove" and c["path"] == "b" for c in changes)

    def test_compute_diff_changed_value(self):
        old = {"score": 80}
        new = {"score": 100}
        changes = _compute_diff(old, new)
        assert any(c["op"] == "change" and c["path"] == "score" for c in changes)

    def test_compute_diff_nested(self):
        old = {"rules": {"block_score": 80}}
        new = {"rules": {"block_score": 90}}
        changes = _compute_diff(old, new)
        assert any(c["path"] == "rules.block_score" for c in changes)

    def test_compute_diff_no_changes(self):
        d = {"a": 1, "b": {"c": 2}}
        changes = _compute_diff(d, d.copy())
        assert len(changes) == 0

    @pytest.mark.asyncio
    async def test_get_tenant_envelope_success(self, mock_core_client):
        mock_core_client.get.return_value = {
            "version": "v1.0", "signature": "sha256:abc123", "sections": {}
        }
        with patch("frothiq_control_center.services.envelope_service.core_client", mock_core_client):
            result = await envelope_service.get_tenant_envelope("t1")
        assert result["success"] is True
        assert result["envelope_version"] == "v1.0"

    @pytest.mark.asyncio
    async def test_get_tenant_envelope_core_failure(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("frothiq_control_center.services.envelope_service.core_client", mock_core_client):
            result = await envelope_service.get_tenant_envelope("t1")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_verify_all_envelopes_batch(self, mock_core_client):
        mock_core_client.get.return_value = {"version": "v1", "signature": "abc123456789"}
        with patch("frothiq_control_center.services.envelope_service.core_client", mock_core_client):
            result = await envelope_service.verify_all_envelopes(["t1", "t2", "t3"])
        assert result["summary"]["total"] == 3


# ---------------------------------------------------------------------------
# Monetization service
# ---------------------------------------------------------------------------

class TestMonetizationService:
    def test_compute_rpi_all_free(self):
        assert _compute_rpi({"free": 10}) == 1.0

    def test_compute_rpi_all_enterprise(self):
        assert _compute_rpi({"enterprise": 5}) == 0.0

    def test_compute_rpi_mixed(self):
        rpi = _compute_rpi({"free": 1, "pro": 2, "enterprise": 1})
        assert abs(rpi - 0.25) < 0.01

    def test_compute_rpi_empty(self):
        assert _compute_rpi({}) == 0.0

    def test_next_plan_free_to_pro(self):
        assert _next_plan("free") == "pro"

    def test_next_plan_pro_to_enterprise(self):
        assert _next_plan("pro") == "enterprise"

    def test_next_plan_enterprise_stays(self):
        assert _next_plan("enterprise") == "enterprise"

    def test_estimate_upgrade_signals(self):
        tenants = [
            {"plan": "free", "max_sites": 1, "active_sites": 1},  # at limit
            {"plan": "pro", "max_sites": 10, "active_sites": 9},  # near limit
            {"plan": "enterprise", "max_sites": 100, "active_sites": 90},  # enterprise excluded
            {"plan": "free", "max_sites": 1, "active_sites": 0},  # comfortable
        ]
        assert _estimate_upgrade_signals(tenants) == 2

    def test_estimate_paywall_hits(self):
        tenants = [
            {"max_sites": 1, "active_sites": 1},  # at limit
            {"max_sites": 1, "active_sites": 2},  # over limit
            {"max_sites": 10, "active_sites": 5},  # fine
        ]
        assert _estimate_paywall_hits(tenants) == 2

    @pytest.mark.asyncio
    async def test_monetization_overview_structure(self, mock_core_client):
        mock_core_client.get.return_value = {
            "tenants": [
                {"tenant_id": "t1", "plan": "free", "max_sites": 1, "active_sites": 1},
                {"tenant_id": "t2", "plan": "pro", "max_sites": 10, "active_sites": 2},
            ]
        }
        with patch("frothiq_control_center.services.monetization_service.core_client", mock_core_client):
            result = await monetization_service.get_monetization_overview()
        assert "plan_breakdown" in result
        assert "revenue_pressure_index" in result
        assert "top_upgrade_candidates" in result

    @pytest.mark.asyncio
    async def test_upgrade_candidates_sorted_by_utilization(self, mock_core_client):
        mock_core_client.get.return_value = {
            "tenants": [
                {"tenant_id": "t1", "plan": "free", "max_sites": 1, "active_sites": 1},
                {"tenant_id": "t2", "plan": "pro", "max_sites": 10, "active_sites": 9},
            ]
        }
        with patch("frothiq_control_center.services.monetization_service.core_client", mock_core_client):
            result = await monetization_service.get_monetization_overview()
        candidates = result["top_upgrade_candidates"]
        if len(candidates) >= 2:
            assert candidates[0]["utilization"] >= candidates[1]["utilization"]


# ---------------------------------------------------------------------------
# Simulation service
# ---------------------------------------------------------------------------

class TestSimulationService:
    @pytest.mark.asyncio
    async def test_get_scenarios_list(self, mock_core_client):
        mock_core_client.get.return_value = {"scenarios": [{"id": "s1"}, {"id": "s2"}]}
        with patch("frothiq_control_center.services.simulation_service.core_client", mock_core_client):
            scenarios = await simulation_service.get_scenarios()
        assert len(scenarios) == 2

    @pytest.mark.asyncio
    async def test_run_scenario_success(self, mock_core_client):
        mock_core_client.post.return_value = {"sim_id": "sim-001", "status": "started"}
        with patch("frothiq_control_center.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.run_scenario("s1", "t1", {}, "admin")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_scenario_core_failure(self, mock_core_client):
        mock_core_client.post.side_effect = CoreClientError(500, "Error")
        with patch("frothiq_control_center.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.run_scenario("s1", "t1", {}, "admin")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_get_metrics_returns_all_scores(self, mock_core_client):
        mock_core_client.get.return_value = {
            "das_avg": 0.7, "dei_avg": 0.6, "pps_avg": 0.8,
            "das_trend": [0.5, 0.7], "dei_trend": [], "pps_trend": [],
        }
        with patch("frothiq_control_center.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.get_metrics(period_days=7)
        assert result["das_avg"] == 0.7
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_metrics_core_offline_graceful(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("frothiq_control_center.services.simulation_service.core_client", mock_core_client):
            result = await simulation_service.get_metrics()
        assert result["success"] is False
        assert result["das_avg"] == 0.0


# ---------------------------------------------------------------------------
# Flywheel service
# ---------------------------------------------------------------------------

class TestFlywheelService:
    @pytest.mark.asyncio
    async def test_get_flywheel_state_success(self, mock_core_client):
        mock_core_client.get.return_value = {"phase": "reinforcement", "velocity": 0.87}
        with patch("frothiq_control_center.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_flywheel_state()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_correlation_heatmap_fallback_on_error(self, mock_core_client):
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("frothiq_control_center.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_correlation_heatmap()
        assert result["success"] is False
        assert len(result["matrix"]) == len(result["dimensions"])
        # Matrix should be all zeros
        assert all(v == 0.0 for row in result["matrix"] for v in row)

    @pytest.mark.asyncio
    async def test_flywheel_dashboard_aggregates_all(self, mock_core_client):
        mock_core_client.get.return_value = {}
        with patch("frothiq_control_center.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_flywheel_dashboard()
        assert "state" in result
        assert "correlation_heatmap" in result
        assert "reinforcement_vectors" in result
        assert "optimization_suggestions" in result

    @pytest.mark.asyncio
    async def test_flywheel_dashboard_handles_partial_failure(self, mock_core_client):
        """Flywheel dashboard should not crash if some sub-calls fail."""
        mock_core_client.get.side_effect = CoreClientError(503, "Offline")
        with patch("frothiq_control_center.services.flywheel_service.core_client", mock_core_client):
            result = await flywheel_service.get_flywheel_dashboard()
        # Should return something, not raise
        assert isinstance(result, dict)
