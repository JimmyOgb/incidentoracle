"""Test suite for AutonomousIncidentOracle and incident_comparator.

Covers:
- Strict boolean parity, case-insensitive severity, and 900s fuzzy timestamp window
- Hardened comparator edge cases (unicode whitespace, extreme epochs, NaN/Inf, empty inputs)
- Anti-spam & DoS cooldown logic
- Web render & LLM execution graceful degradation
- Deposit accounting, partial penalties, terminal slashing, top-ups, and timelocked withdrawals
"""

import datetime
import json
import math
import sys
import types
from unittest.mock import MagicMock
import pytest

# Ensure genlayer and genlayer.gl stubs are registered if not in GenVM environment
if "genlayer.gl" not in sys.modules:
    genlayer_mod = sys.modules.setdefault("genlayer", types.ModuleType("genlayer"))
    gl_mod = types.ModuleType("genlayer.gl")

    class Address(str):
        """Address stub for tests."""
        pass

    class TreeMap(dict):
        def __class_getitem__(cls, item):
            return cls

    class DynArray(list):
        def __class_getitem__(cls, item):
            return cls

    class Contract:
        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)

    class _Message:
        def __init__(self):
            self.sender = "0x1111111111111111111111111111111111111111"
            self.sender_address = self.sender
            self.value = 1000000000000000000  # 1 ETH in wei
            self.contract_address = "0x0000000000000000000000000000000000000001"
            self.origin_address = self.sender

    class _Write:
        def __call__(self, fn):
            fn.__gl_public__ = True
            fn.__gl_write__ = True
            return fn

        def payable(self, fn):
            fn.__gl_public__ = True
            fn.__gl_write__ = True
            fn.__gl_payable__ = True
            return fn

    class _Public:
        write = _Write()

        @staticmethod
        def view(fn):
            fn.__gl_public__ = True
            fn.__gl_view__ = True
            return fn

    gl_mod.Address = Address
    gl_mod.TreeMap = TreeMap
    gl_mod.DynArray = DynArray
    gl_mod.Contract = Contract
    gl_mod.message = _Message()
    gl_mod.public = _Public()
    gl_mod.nondet = MagicMock()
    gl_mod.vm = MagicMock()
    gl_mod.vm.run_nondet_unsafe = lambda leader_fn, validator_fn: leader_fn()
    gl_mod.transfer = MagicMock()

    def _eq_principle_stub(comparator, fn):
        return fn()

    gl_mod.eq_principle = _eq_principle_stub

    genlayer_mod.Address = Address
    genlayer_mod.TreeMap = TreeMap
    genlayer_mod.DynArray = DynArray
    genlayer_mod.Contract = Contract
    genlayer_mod.gl = gl_mod

    sys.modules["genlayer"] = genlayer_mod
    sys.modules["genlayer.gl"] = gl_mod

from contracts.autonomous_incident_oracle import (
    AutonomousIncidentOracle,
    incident_comparator,
    _gl_transfer,
)
import genlayer.gl as gl

if not hasattr(gl, "transfer") or not callable(getattr(gl, "transfer")):
    gl.transfer = MagicMock()


@pytest.fixture(autouse=True)
def reset_gl_transfer():
    if hasattr(gl, "transfer") and hasattr(gl.transfer, "reset_mock"):
        gl.transfer.reset_mock()
    else:
        gl.transfer = MagicMock()
    yield


class TestIncidentComparatorIdenticalInputs:
    """Requirement 1: Test incident_comparator with identical inputs returning True."""

    def test_identical_major_outage(self):
        payload = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Core API database connection failure",
        })
        assert incident_comparator(payload, payload) is True

    def test_identical_no_outage(self):
        payload = json.dumps({
            "is_outage": False,
            "severity": "NONE",
            "timestamp_epoch": 1710000000,
            "reason": "All systems operational",
        })
        assert incident_comparator(payload, payload) is True

    def test_identical_partial_outage(self):
        payload = json.dumps({
            "is_outage": True,
            "severity": "PARTIAL",
            "timestamp_epoch": 1710005000,
            "reason": "Elevated latency on search endpoints",
        })
        assert incident_comparator(payload, payload) is True

    def test_identical_keys_different_ordering_and_whitespace(self):
        payload_a = '{"is_outage": true, "severity": "MAJOR", "timestamp_epoch": 1710000000, "reason": "Outage"}'
        payload_b = '{\n  "reason": "Outage",\n  "timestamp_epoch": 1710000000,\n  "severity": "MAJOR",\n  "is_outage": true\n}'
        assert incident_comparator(payload_a, payload_b) is True


class TestIncidentComparatorTimestampWindow:
    """Requirement 2: Test varying timestamps within the 900-second window returning True."""

    def test_timestamp_delta_within_window(self):
        base_ts = 1710000000
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts,
            "reason": "DNS resolution error",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts + 300,
            "reason": "DNS timeout error",
        })
        assert incident_comparator(payload_a, payload_b) is True

    def test_timestamp_exact_boundary_positive_900s(self):
        base_ts = 1710000000
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts,
            "reason": "Primary gateway unreachable",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts + 900,
            "reason": "Primary gateway unreachable",
        })
        assert incident_comparator(payload_a, payload_b) is True

    def test_timestamp_exact_boundary_negative_900s(self):
        base_ts = 1710000000
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "PARTIAL",
            "timestamp_epoch": base_ts,
            "reason": "Degraded performance",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "PARTIAL",
            "timestamp_epoch": base_ts - 900,
            "reason": "Degraded performance",
        })
        assert incident_comparator(payload_a, payload_b) is True

    def test_timestamp_899s_delta(self):
        base_ts = 1710000000
        payload_a = json.dumps({
            "is_outage": False,
            "severity": "NONE",
            "timestamp_epoch": base_ts,
            "reason": "OK",
        })
        payload_b = json.dumps({
            "is_outage": False,
            "severity": "NONE",
            "timestamp_epoch": base_ts + 899,
            "reason": "OK",
        })
        assert incident_comparator(payload_a, payload_b) is True


class TestIncidentComparatorDivergentSeverity:
    """Requirement 3: Test divergent severity values returning False."""

    def test_major_vs_partial(self):
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Service unreachable",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "PARTIAL",
            "timestamp_epoch": 1710000000,
            "reason": "Some nodes degraded",
        })
        assert incident_comparator(payload_a, payload_b) is False

    def test_major_vs_none(self):
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Down",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "NONE",
            "timestamp_epoch": 1710000000,
            "reason": "Recovered",
        })
        assert incident_comparator(payload_a, payload_b) is False

    def test_case_insensitive_severity_matches(self):
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "major",
            "timestamp_epoch": 1710000000,
            "reason": "Down",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Down",
        })
        assert incident_comparator(payload_a, payload_b) is True

    def test_invalid_severity_string(self):
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "CRITICAL",
            "timestamp_epoch": 1710000000,
            "reason": "Down",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "CRITICAL",
            "timestamp_epoch": 1710000000,
            "reason": "Down",
        })
        assert incident_comparator(payload_a, payload_b) is False


class TestIncidentComparatorTimestampDivergence:
    """Requirement 4: Test timestamp divergence exceeding 900 seconds returning False."""

    def test_timestamp_delta_901s(self):
        base_ts = 1710000000
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts,
            "reason": "Database crash",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts + 901,
            "reason": "Database crash",
        })
        assert incident_comparator(payload_a, payload_b) is False

    def test_timestamp_negative_delta_901s(self):
        base_ts = 1710000000
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts,
            "reason": "Database crash",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": base_ts - 901,
            "reason": "Database crash",
        })
        assert incident_comparator(payload_a, payload_b) is False

    def test_large_timestamp_delta(self):
        payload_a = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Crash",
        })
        payload_b = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710086400,
            "reason": "Crash",
        })
        assert incident_comparator(payload_a, payload_b) is False


class TestIncidentComparatorInvalidJSONAndHardening:
    """Requirement 5 & Audit Target 4: Hardened comparator edge cases."""

    def test_malformed_json_syntax(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        assert incident_comparator("{bad_json: true", valid) is False
        assert incident_comparator(valid, "{\"unclosed: 1") is False

    def test_non_json_string(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        assert incident_comparator("hello world", valid) is False
        assert incident_comparator("", valid) is False
        assert incident_comparator("", "") is False
        assert incident_comparator("   ", "   ") is False

    def test_unicode_whitespace_handling(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        # Non-breaking spaces and zero-width spaces
        assert incident_comparator("\u00a0\u200b\n", valid) is False
        # Severity with unicode whitespace should be safely stripped and compared
        with_unicode_ws = json.dumps({
            "is_outage": True,
            "severity": " MAJOR\u00a0",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        assert incident_comparator(valid, with_unicode_ws) is True

    def test_non_string_types(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        assert incident_comparator(None, valid) is False
        assert incident_comparator(valid, None) is False
        assert incident_comparator(12345, valid) is False
        assert incident_comparator({"is_outage": True}, valid) is False

    def test_json_primitive_or_array_instead_of_object(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        assert incident_comparator("[1, 2, 3]", valid) is False
        assert incident_comparator("123", valid) is False
        assert incident_comparator("true", valid) is False

    def test_missing_required_keys(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Valid",
        })
        assert incident_comparator(json.dumps({"severity": "MAJOR", "timestamp_epoch": 1710000000}), valid) is False
        assert incident_comparator(json.dumps({"is_outage": True, "timestamp_epoch": 1710000000}), valid) is False
        assert incident_comparator(json.dumps({"is_outage": True, "severity": "MAJOR"}), valid) is False

    def test_is_outage_type_and_parity(self):
        valid_true = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
        })
        valid_false = json.dumps({
            "is_outage": False,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
        })
        assert incident_comparator(valid_true, valid_false) is False

        non_bool = json.dumps({
            "is_outage": 1,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
        })
        assert incident_comparator(non_bool, valid_true) is False

    def test_extreme_and_invalid_timestamps(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
        })
        # Negative epoch
        neg_ts = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": -100,
        })
        assert incident_comparator(neg_ts, valid) is False

        # Unreasonably huge epoch (overflow protection)
        huge_ts = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 10**16,
        })
        assert incident_comparator(huge_ts, valid) is False

        # String timestamp
        str_ts = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": "not-a-number",
        })
        assert incident_comparator(str_ts, valid) is False

        # Boolean timestamp
        bool_ts = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": True,
        })
        assert incident_comparator(bool_ts, valid) is False

    def test_non_string_severity(self):
        valid = json.dumps({
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
        })
        num_sev = json.dumps({
            "is_outage": True,
            "severity": 3,
            "timestamp_epoch": 1710000000,
        })
        assert incident_comparator(num_sev, valid) is False


class TestAutonomousIncidentOracleContract:
    """Test suite for AutonomousIncidentOracle contract methods and audit upgrades."""

    def test_contract_initialization(self):
        oracle = AutonomousIncidentOracle()
        assert oracle.owner == gl.message.sender
        assert oracle.treasury == gl.message.sender
        assert oracle.services == {}
        assert oracle.incident_logs == {}

    def test_set_treasury(self):
        oracle = AutonomousIncidentOracle()
        assert oracle.treasury == gl.message.sender
        new_treasury = "0x2222222222222222222222222222222222222222"
        oracle.set_treasury(new_treasury)
        assert oracle.treasury == new_treasury

        # Non-owner caller fails assert
        prev_sender = gl.message.sender
        gl.message.sender = "0x9999999999999999999999999999999999999999"
        with pytest.raises(AssertionError):
            oracle.set_treasury("0x3333333333333333333333333333333333333333")
        gl.message.sender = prev_sender

    def test_register_service_success(self):
        oracle = AutonomousIncidentOracle()
        service_id = "payment-gateway"
        status_url = "https://status.paymentgateway.com"

        oracle.register_service(service_id, status_url)

        service = oracle.get_service(service_id)
        assert service["status_url"] == status_url
        assert service["deposit"] == gl.message.value
        assert service["is_slashed"] is False
        assert service["total_incidents"] == 0
        assert service["registered_by"] == str(gl.message.sender)
        assert service["last_audit_timestamp"] == 0
        assert service["last_incident_timestamp"] == 0
        assert oracle.get_incidents(service_id) == []

    def test_register_service_validation(self):
        oracle = AutonomousIncidentOracle()

        with pytest.raises(ValueError, match="service_id must be a non-empty string"):
            oracle.register_service("", "https://status.example.com")

        with pytest.raises(ValueError, match="status_url must be a valid HTTPS URL"):
            oracle.register_service("service-1", "http://insecure.example.com")

        oracle.register_service("service-1", "https://status.example.com")
        with pytest.raises(ValueError, match="already registered"):
            oracle.register_service("service-1", "https://status.example.com")

    def test_get_service_not_found(self):
        oracle = AutonomousIncidentOracle()
        with pytest.raises(ValueError, match="not found"):
            oracle.get_service("non-existent")

    def test_get_incidents_not_found(self):
        oracle = AutonomousIncidentOracle()
        with pytest.raises(ValueError, match="not found"):
            oracle.get_incidents("non-existent")

    def test_report_incident_validation(self):
        oracle = AutonomousIncidentOracle()

        with pytest.raises(ValueError, match="not found"):
            oracle.report_incident("unknown-svc")

        oracle.register_service("svc-slashed", "https://status.slashed.com")
        svc_data = oracle.get_service("svc-slashed")
        svc_data["is_slashed"] = True
        oracle.services["svc-slashed"] = json.dumps(svc_data)
        with pytest.raises(ValueError, match="already slashed"):
            oracle.report_incident("svc-slashed")

    def test_report_incident_anti_spam_cooldown(self, monkeypatch):
        """Audit Target 1: Anti-Spam & DoS cooldown enforcement."""
        oracle = AutonomousIncidentOracle()
        service_id = "api-service"
        oracle.register_service(service_id, "https://status.api.com")

        llm_response = {
            "is_outage": False,
            "severity": "NONE",
            "timestamp_epoch": 1710000000,
            "reason": "Healthy",
        }
        monkeypatch.setattr(gl.nondet.web, "render", lambda url: "All OK")
        monkeypatch.setattr(gl.nondet, "exec_prompt", lambda prompt, response_format=None: llm_response)

        # First report succeeds
        output_1 = oracle.report_incident(service_id)
        assert json.loads(output_1)["is_outage"] is False

        # Immediate second report fails due to MIN_AUDIT_INTERVAL cooldown
        with pytest.raises(ValueError, match="Audit cooldown active"):
            oracle.report_incident(service_id)

        # Fast forward time by 301 seconds past cooldown
        service = oracle.get_service(service_id)
        service["last_audit_timestamp"] -= 301
        oracle.services[service_id] = json.dumps(service)

        # Second report now succeeds
        output_2 = oracle.report_incident(service_id)
        assert json.loads(output_2)["is_outage"] is False

    def test_report_incident_web_failure_graceful_degradation(self, monkeypatch):
        """Audit Target 2: Web fetch failure & graceful degradation."""
        oracle = AutonomousIncidentOracle()
        service_id = "failing-web-svc"
        oracle.register_service(service_id, "https://status.broken.com")

        # Simulate web.render raising an error (e.g. timeout / connection refused)
        def mock_render_fail(url):
            raise ConnectionError("502 Bad Gateway from cloudflare")

        monkeypatch.setattr(gl.nondet.web, "render", mock_render_fail)

        def mock_exec_prompt(prompt, response_format=None):
            assert "FETCH_ERROR" in prompt
            return {
                "is_outage": True,
                "severity": "MAJOR",
                "timestamp_epoch": 1710000000,
                "reason": "Status page unreachable due to 502 Bad Gateway",
            }

        monkeypatch.setattr(gl.nondet, "exec_prompt", mock_exec_prompt)

        output = oracle.report_incident(service_id)
        res = json.loads(output)
        assert res["is_outage"] is True
        assert res["severity"] == "MAJOR"

        service = oracle.get_service(service_id)
        assert service["is_slashed"] is True
        assert service["deposit"] == 0

    def test_report_incident_llm_failure_graceful_degradation(self, monkeypatch):
        """Audit Target 2: LLM failure fallback."""
        oracle = AutonomousIncidentOracle()
        service_id = "failing-llm-svc"
        oracle.register_service(service_id, "https://status.llm-broken.com")

        def mock_render(url):
            return "500 Internal Error"

        def mock_exec_prompt_fail(prompt, response_format=None):
            raise RuntimeError("LLM inference service unavailable")

        monkeypatch.setattr(gl.nondet.web, "render", mock_render)
        monkeypatch.setattr(gl.nondet, "exec_prompt", mock_exec_prompt_fail)

        # Does not crash: falls back cleanly
        output = oracle.report_incident(service_id)
        res = json.loads(output)
        assert "is_outage" in res
        assert "Execution fallback" in res["reason"]

    def test_report_incident_partial_outage_deducts_penalty(self, monkeypatch):
        """Audit Target 3: Slashing & Deposit Accounting for PARTIAL outage."""
        oracle = AutonomousIncidentOracle()
        service_id = "partial-svc"
        initial_deposit = 1000
        gl.message.value = initial_deposit
        oracle.register_service(service_id, "https://status.partial.com")

        llm_response = {
            "is_outage": True,
            "severity": "PARTIAL",
            "timestamp_epoch": 1710000000,
            "reason": "Search endpoint degraded",
        }
        monkeypatch.setattr(gl.nondet.web, "render", lambda url: "Degraded")
        monkeypatch.setattr(gl.nondet, "exec_prompt", lambda prompt, response_format=None: llm_response)

        oracle.report_incident(service_id)
        service = oracle.get_service(service_id)

        # 25% penalty deducted: 1000 - 250 = 750
        assert service["deposit"] == 750
        assert service["total_incidents"] == 1
        assert service["is_slashed"] is False

        incidents = oracle.get_incidents(service_id)
        assert len(incidents) == 1
        assert incidents[0]["deposit_after_incident"] == 750

        # Verify 50/50 slashing disposal: 250 slashed -> 125 bounty, 125 treasury
        assert gl.transfer.call_count == 2
        gl.transfer.assert_any_call(gl.message.sender, 125)
        gl.transfer.assert_any_call(oracle.treasury, 125)

    def test_deposit_top_up_and_recovery(self):
        """Audit Target 3: Top-up deposit functionality."""
        oracle = AutonomousIncidentOracle()
        service_id = "topup-svc"
        gl.message.value = 500
        oracle.register_service(service_id, "https://status.topup.com")

        # Top up with 500
        gl.message.value = 500
        new_deposit = oracle.top_up_deposit(service_id)
        assert new_deposit == 1000
        assert oracle.get_service(service_id)["deposit"] == 1000

        # Invalid top up
        gl.message.value = 0
        with pytest.raises(ValueError, match="greater than 0"):
            oracle.top_up_deposit(service_id)

    def test_deposit_withdrawal_lock_period(self):
        """Audit Target 3: Withdrawal with incident-free lock period."""
        oracle = AutonomousIncidentOracle()
        service_id = "withdraw-svc"
        gl.message.value = 1000
        oracle.register_service(service_id, "https://status.withdraw.com")

        # Attempt immediate withdrawal: blocked by WITHDRAWAL_LOCK_PERIOD
        with pytest.raises(ValueError, match="Withdrawal lock active"):
            oracle.withdraw_deposit(service_id, 200)

        # Fast forward time past 24 hours (86400s)
        service = oracle.get_service(service_id)
        service["created_at"] -= 86401
        oracle.services[service_id] = json.dumps(service)

        # Unauthorized caller
        prev_sender = gl.message.sender
        gl.message.sender = "0x9999999999999999999999999999999999999999"
        with pytest.raises(ValueError, match="Only service registrant or contract owner"):
            oracle.withdraw_deposit(service_id, 200)

        gl.message.sender = prev_sender

        # Successful withdrawal
        remaining = oracle.withdraw_deposit(service_id, 400)
        assert remaining == 600
        assert oracle.get_service(service_id)["deposit"] == 600
        gl.transfer.assert_called_with(gl.message.sender, 400)

        # Over-withdrawal rejected
        with pytest.raises(ValueError, match="Insufficient deposit"):
            oracle.withdraw_deposit(service_id, 700)

    def test_slashing_disposal_major_outage(self, monkeypatch):
        """Verify 50/50 distribution between reporter bounty and treasury on MAJOR outage."""
        oracle = AutonomousIncidentOracle()
        service_id = "major-outage-svc"
        deposit = 2000
        gl.message.value = deposit
        oracle.register_service(service_id, "https://status.major.com")

        custom_treasury = "0x8888888888888888888888888888888888888888"
        oracle.set_treasury(custom_treasury)

        llm_response = {
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Complete database cluster outage",
        }
        monkeypatch.setattr(gl.nondet.web, "render", lambda url: "Outage detected")
        monkeypatch.setattr(gl.nondet, "exec_prompt", lambda prompt, response_format=None: llm_response)

        # Reporter triggers report_incident
        reporter = "0x7777777777777777777777777777777777777777"
        prev_sender = gl.message.sender
        gl.message.sender = reporter

        gl.transfer.reset_mock()
        oracle.report_incident(service_id)

        # 100% of 2000 is slashed: 1000 to reporter, 1000 to treasury
        assert gl.transfer.call_count == 2
        gl.transfer.assert_any_call(reporter, 1000)
        gl.transfer.assert_any_call(custom_treasury, 1000)

        service = oracle.get_service(service_id)
        assert service["deposit"] == 0
        assert service["is_slashed"] is True

        gl.message.sender = prev_sender


class TestFundFlowTransferImplementation:
    """Validate fund-flow native transfer implementation resolving reviewer Joaquin's rejection."""

    def test_gl_transfer_fallback_uses_get_contract_at_emit_transfer(self, monkeypatch):
        """Verify _gl_transfer invokes get_contract_at(Address(to)).emit_transfer(value=val)."""
        mock_contract = MagicMock()
        mock_get_contract_at = MagicMock(return_value=mock_contract)
        monkeypatch.setattr(gl, "get_contract_at", mock_get_contract_at, raising=False)

        target = "0x9876543210987654321098765432109876543210"
        _gl_transfer(target, 500)

        mock_get_contract_at.assert_called_once()
        called_addr = mock_get_contract_at.call_args[0][0]
        assert str(called_addr) == target
        mock_contract.emit_transfer.assert_called_once_with(value=500)

    def test_gl_transfer_fallback_propagates_exceptions_without_suppression(self, monkeypatch):
        """Verify _gl_transfer does not swallow errors when emit_transfer fails."""
        mock_contract = MagicMock()
        mock_contract.emit_transfer.side_effect = RuntimeError("EVM VM revert during native transfer")
        monkeypatch.setattr(gl, "get_contract_at", lambda addr: mock_contract, raising=False)

        with pytest.raises(RuntimeError, match="EVM VM revert during native transfer"):
            _gl_transfer("0x1111111111111111111111111111111111111111", 100)

    def test_gl_transfer_zero_amount_noop(self, monkeypatch):
        """Verify _gl_transfer does not invoke emit_transfer when amount <= 0."""
        mock_get_contract_at = MagicMock()
        monkeypatch.setattr(gl, "get_contract_at", mock_get_contract_at, raising=False)

        _gl_transfer("0x1111111111111111111111111111111111111111", 0)
        _gl_transfer("0x1111111111111111111111111111111111111111", -50)
        mock_get_contract_at.assert_not_called()

    def test_withdraw_deposit_propagates_transfer_failure(self, monkeypatch):
        """Verify withdrawal fails and is not confirmed if transfer raises."""
        oracle = AutonomousIncidentOracle()
        service_id = "revert-withdraw-svc"
        gl.message.value = 1000
        oracle.register_service(service_id, "https://status.withdraw-fail.com")

        # Age past lock
        service = oracle.get_service(service_id)
        service["created_at"] -= 86401
        oracle.services[service_id] = json.dumps(service)

        # Force gl.transfer to fail
        monkeypatch.setattr(gl, "transfer", MagicMock(side_effect=RuntimeError("Insufficient gas for transfer")))

        with pytest.raises(RuntimeError, match="Insufficient gas for transfer"):
            oracle.withdraw_deposit(service_id, 300)

    def test_report_incident_slashing_propagates_transfer_failure(self, monkeypatch):
        """Verify slashing does not swallow transfer failures during bounty/treasury payout."""
        oracle = AutonomousIncidentOracle()
        service_id = "revert-slash-svc"
        gl.message.value = 1000
        oracle.register_service(service_id, "https://status.slash-fail.com")

        llm_response = {
            "is_outage": True,
            "severity": "MAJOR",
            "timestamp_epoch": 1710000000,
            "reason": "Complete power outage",
        }
        monkeypatch.setattr(gl.nondet.web, "render", lambda url: "Outage")
        monkeypatch.setattr(gl.nondet, "exec_prompt", lambda prompt, response_format=None: llm_response)

        # Force gl.transfer to fail
        monkeypatch.setattr(gl, "transfer", MagicMock(side_effect=RuntimeError("Transfer to treasury failed")))

        with pytest.raises(RuntimeError, match="Transfer to treasury failed"):
            oracle.report_incident(service_id)
