from __future__ import annotations

import hashlib
import hmac
import asyncio
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import AsyncMock, patch

from constraints import canonical_signature_payload, validate_command
from store import AdaptiveStore, now_iso
from service import SERVICE


class DummyAdapter:
    name = "DUMMY"

    async def execute(self, device, action, params):
        return {"success": True, "adapter": self.name, "response": {"action": action, "params": params}}


class AutonomousControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._original_devices = dict(SERVICE.store.devices)
        self._original_actions = list(SERVICE.store.actions)
        self._original_overrides = dict(SERVICE.store.overrides)
        self._original_tasks = dict(SERVICE.store.override_tasks)
        SERVICE.store.devices = dict(self._original_devices)
        SERVICE.store.actions = []
        SERVICE.store.overrides = {}
        SERVICE.store.override_tasks = {}

    async def asyncTearDown(self) -> None:
        for task in SERVICE.store.override_tasks.values():
            task.cancel()
        SERVICE.store.devices = self._original_devices
        SERVICE.store.actions = self._original_actions
        SERVICE.store.overrides = self._original_overrides
        SERVICE.store.override_tasks = self._original_tasks

    async def test_validation_requires_incident(self) -> None:
        result = validate_command(
            action_key="elevator_hold",
            device={"type": "smart_elevator"},
            requestor={"approval_level": "supervisor"},
            incident_id=None,
            approved_by="user_1",
        )
        self.assertFalse(result["valid"])
        self.assertIn("incident", result["reason"].lower())

    def _sign(self, payload: dict[str, object], secret: str = "test-secret") -> str:
        digest = hmac.new(
            secret.encode("utf-8"),
            canonical_signature_payload(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        SERVICE.approval_signature_secret = secret
        SERVICE.playbook_signature_secret = secret
        return digest

    async def test_mode_zero_blocks_execution(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-mode0",
            "org_id": "org_abc123",
            "automation_mode": 0,
            "action": {
                "action_key": "get_status",
                "device_id": "GATE-001",
                "parameters": {},
            },
            "authorisation": {
                "approved_by": "user_supervisor_001",
                "approval_timestamp": "2026-07-19T00:00:00Z",
                "approval_level": "supervisor",
                "incident_id": "INC-2024-001",
            },
        }

        result = await SERVICE.execute(payload, client_ip="127.0.0.1")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["data"]["policy_decision"], "advisory_only")

    async def test_safety_override_blocks_emergency_exit_lock(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-safe",
            "org_id": "org_abc123",
            "automation_mode": 2,
            "action": {
                "action_key": "lock",
                "device_id": "GATE-001",
                "parameters": {
                    "reason": "Lock emergency exit route",
                    "route_ids": ["EXIT-ROUTE-1"],
                },
            },
            "authorisation": {
                "approved_by": "user_manager_001",
                "approval_timestamp": "2026-07-19T00:00:00Z",
                "approval_level": "manager",
                "incident_id": "INC-2024-001",
                "approval_signature": "ignored",
            },
        }

        result = await SERVICE.execute(payload, client_ip="127.0.0.1")
        self.assertEqual(result["status"], "blocked")
        self.assertIn("safety override", result["error"].lower())

    async def test_mode_one_human_signature_executes(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-mode1",
            "org_id": "org_abc123",
            "automation_mode": 1,
            "action": {
                "action_key": "open",
                "device_id": "GATE-001",
                "parameters": {"duration_seconds": 2},
            },
            "authorisation": {
                "approved_by": "user_supervisor_001",
                "approval_timestamp": "2026-07-19T00:00:00Z",
                "approval_level": "supervisor",
                "incident_id": "INC-2024-001",
            },
        }
        payload["authorisation"]["approval_signature"] = self._sign(
            {
                "request_id": payload["request_id"],
                "org_id": payload["org_id"],
                "action_key": payload["action"]["action_key"],
                "device_id": payload["action"]["device_id"],
                "parameters": payload["action"]["parameters"],
                "approved_by": payload["authorisation"]["approved_by"],
                "approval_timestamp": payload["authorisation"]["approval_timestamp"],
                "automation_mode": payload["automation_mode"],
            }
        )

        dummy = DummyAdapter()
        with patch.dict("adapters.ADAPTERS", {"MQTT": dummy, "REST_API": dummy, "HARDWARE_BRIDGE": dummy}):
            result = await SERVICE.execute(payload, client_ip="127.0.0.1")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"]["automation_mode"], 1)

    async def test_mode_three_preapproved_playbook_executes(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-mode3",
            "org_id": "org_abc123",
            "automation_mode": 3,
            "action": {
                "action_key": "get_status",
                "device_id": "GATE-001",
                "parameters": {},
            },
            "manifest": {
                "preapproved": True,
                "playbook_id": "status-check",
                "steps": [
                    {
                        "action_key": "get_status",
                        "device_id": "GATE-001",
                        "parameters": {},
                    }
                ],
            },
            "authorisation": {
                "approved_by": "system_playbook",
                "approval_timestamp": "2026-07-19T00:00:00Z",
                "approval_level": "manager",
                "incident_id": "INC-2024-001",
            },
        }

        dummy = DummyAdapter()
        with patch.dict("adapters.ADAPTERS", {"MQTT": dummy, "REST_API": dummy, "HARDWARE_BRIDGE": dummy}):
            result = await SERVICE.execute(payload, client_ip="127.0.0.1")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"]["policy_decision"], "playbook_executed")
        self.assertEqual(len(result["data"]["playbook_results"]), 1)

    async def test_execute_success_schedules_override(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-001",
            "org_id": "org_abc123",
            "automation_mode": 1,
            "action": {
                "action_key": "open",
                "device_id": "GATE-001",
                "parameters": {"duration_seconds": 2},
            },
            "authorisation": {
                "approved_by": "user_supervisor_001",
                "approval_timestamp": "2026-06-17T00:00:00Z",
                "approval_level": "supervisor",
                "incident_id": "INC-2024-001",
            },
        }
        payload["authorisation"]["approval_signature"] = self._sign(
            {
                "request_id": payload["request_id"],
                "org_id": payload["org_id"],
                "action_key": payload["action"]["action_key"],
                "device_id": payload["action"]["device_id"],
                "parameters": payload["action"]["parameters"],
                "approved_by": payload["authorisation"]["approved_by"],
                "approval_timestamp": payload["authorisation"]["approval_timestamp"],
                "automation_mode": payload["automation_mode"],
            }
        )

        dummy = DummyAdapter()
        with patch.dict("adapters.ADAPTERS", {"MQTT": dummy, "REST_API": dummy, "HARDWARE_BRIDGE": dummy}):
            result = await SERVICE.execute(payload, client_ip="127.0.0.1")

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["data"]["auto_revert_scheduled"])
        self.assertIsNotNone(result["data"]["active_override_id"])
        self.assertEqual(SERVICE.store.actions[-1]["requested_from_ip"], "127.0.0.1")

    async def test_unsupported_action_rejected(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-002",
            "org_id": "org_abc123",
            "action": {
                "action_key": "deploy",
                "device_id": "GATE-001",
                "parameters": {},
            },
            "authorisation": {
                "approved_by": "user_manager_001",
                "approval_timestamp": "2026-06-17T00:00:00Z",
                "approval_level": "manager",
                "incident_id": "INC-2024-001",
            },
        }

        result = await SERVICE.execute(payload, client_ip="127.0.0.1")
        self.assertEqual(result["status"], "failed")
        self.assertIn("not supported", result["error"].lower())

    async def test_bridge_queue_prunes_expired_commands(self) -> None:
        store = AdaptiveStore()
        await store.queue_bridge_command(
            {
                "id": "cmd-1",
                "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                "status": "queued",
            }
        )
        expired = await store.prune_expired_bridge_commands()
        self.assertEqual(len(expired), 1)
        queue = await store.list_bridge_queue()
        self.assertEqual(queue, [])

    async def test_hardware_bridge_crud_and_health(self) -> None:
        created = await SERVICE.register_hardware_bridge(
            {
                "org_id": "org_abc123",
                "name": "Bridge A",
                "location": "HQ",
                "gateway_key": "bridge-key-1",
                "status": "offline",
            }
        )
        self.assertEqual(created["name"], "Bridge A")
        fetched = await SERVICE.get_hardware_bridge(created["id"])
        self.assertEqual(fetched["gateway_key"], "bridge-key-1")
        updated = await SERVICE.update_hardware_bridge(created["id"], {"status": "online"})
        self.assertEqual(updated["status"], "online")
        health = await SERVICE.health()
        self.assertIn("REST_API", health["adapters"])

    async def test_get_action_status_returns_override_state(self) -> None:
        payload = {
            "request_type": "execute_action",
            "request_id": "req-003",
            "org_id": "org_abc123",
            "automation_mode": 1,
            "action": {
                "action_key": "open",
                "device_id": "GATE-001",
                "parameters": {"duration_seconds": 2},
            },
            "authorisation": {
                "approved_by": "user_supervisor_001",
                "approval_timestamp": "2026-06-17T00:00:00Z",
                "approval_level": "supervisor",
                "incident_id": "INC-2024-001",
            },
        }
        payload["authorisation"]["approval_signature"] = self._sign(
            {
                "request_id": payload["request_id"],
                "org_id": payload["org_id"],
                "action_key": payload["action"]["action_key"],
                "device_id": payload["action"]["device_id"],
                "parameters": payload["action"]["parameters"],
                "approved_by": payload["authorisation"]["approved_by"],
                "approval_timestamp": payload["authorisation"]["approval_timestamp"],
                "automation_mode": payload["automation_mode"],
            }
        )

        dummy = DummyAdapter()
        with patch.dict("adapters.ADAPTERS", {"MQTT": dummy, "REST_API": dummy, "HARDWARE_BRIDGE": dummy}):
            result = await SERVICE.execute(payload, client_ip="127.0.0.1")

        action_log_id = result["data"]["action_log_id"]
        status = await SERVICE.get_action_status(action_log_id)
        self.assertEqual(status["identifier"], action_log_id)
        self.assertIsNotNone(status["action"])


if __name__ == "__main__":
    unittest.main()
