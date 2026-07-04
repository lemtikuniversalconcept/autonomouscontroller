from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from adapters import ADAPTERS, AdapterError
from constraints import CONSTRAINT_RULES, resolve_action_key, validate_command
from crypto import decrypt_text, encrypt_text, redact_secret
from store import STORE, now_iso, parse_iso


class AutonomousControlService:
    def __init__(self) -> None:
        self.store = STORE
        self.scheduler = None
        self.encryption_key = os.getenv("DEVICE_CREDENTIALS_ENCRYPTION_KEY")
        self.max_traffic_preemption_seconds = int(os.getenv("MAX_TRAFFIC_PREEMPTION_SECONDS", "600"))
        self.max_lockdown_seconds = int(os.getenv("MAX_LOCKDOWN_SECONDS", "1800"))
        self.max_elevator_hold_seconds = int(os.getenv("MAX_ELEVATOR_HOLD_SECONDS", "600"))
        self.revert_retry_count = int(os.getenv("REVERT_RETRY_COUNT", "3"))
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        if self.store.devices:
            return
        defaults = [
            {
                "id": "ELEV-EKO-002",
                "org_id": "org_abc123",
                "building_id": "BLD-001",
                "name": "Main Elevator Block B",
                "type": "smart_elevator",
                "manufacturer": "Generic",
                "model": "DCS",
                "floor": 0,
                "zone": "Core",
                "area": "Lobby",
                "connection_type": "REST_API",
                "connection_config": {
                    "base_url": "https://example.invalid/api/elevator",
                    "auth_type": "bearer_token",
                    "credentials": {"token": "redacted"},
                    "action_paths": {
                        "release": "/release",
                        "hold_at_floor": "/hold",
                    },
                },
                "supported_actions": ["hold_at_floor", "release", "get_status"],
            },
            {
                "id": "GATE-001",
                "org_id": "org_abc123",
                "building_id": "BLD-001",
                "name": "Perimeter Gate 1",
                "type": "smart_gate",
                "manufacturer": "Generic",
                "model": "GateCtrl",
                "connection_type": "MQTT",
                "connection_config": {
                    "broker_url": os.getenv("EMQX_BROKER_URL", ""),
                    "topic_prefix": "lemtik",
                    "credentials": {"username": os.getenv("EMQX_USERNAME", ""), "password": os.getenv("EMQX_PASSWORD", "")},
                },
                "supported_actions": ["open", "close", "lock", "unlock", "get_status"],
            },
            {
                "id": "TL-LEKKI-042",
                "org_id": "org_abc123",
                "building_id": "BLD-001",
                "name": "Lekki Intersection 42",
                "type": "traffic_light",
                "manufacturer": "Generic",
                "model": "CTMS Bridge",
                "connection_type": "HARDWARE_BRIDGE",
                "connection_config": {
                    "gateway_id": "gw-001",
                    "gateway_websocket_url": "ws://localhost:9000/bridge",
                    "local_device_id": "TL-42",
                    "bridge_key": "redacted",
                },
                "supported_actions": ["green_corridor", "single_preempt", "release_all", "release_intersection", "get_status"],
            },
        ]
        for device in defaults:
            record = {
                **device,
                "status": "online",
                "created_at": now_iso(),
                "updated_at": now_iso(),
                "last_seen": now_iso(),
                "last_command_at": None,
                "last_command_result": None,
            }
            if self.encryption_key and record.get("connection_config"):
                record["connection_config_encrypted"] = encrypt_text(
                    json.dumps(record["connection_config"]),
                    self.encryption_key,
                )
                record["connection_config"] = {}
            self.store.devices[device["id"]] = record

    async def register_device(self, payload: dict[str, Any]) -> dict[str, Any]:
        device = {
            **payload,
            "connection_config": payload.get("connection_config", {}),
            "supported_actions": payload.get("supported_actions", []),
        }
        if self.encryption_key and device["connection_config"]:
            device["connection_config_encrypted"] = encrypt_text(
                json.dumps(device["connection_config"]),
                self.encryption_key,
            )
            device["connection_config"] = {}
        stored = await self.store.upsert_device(device)
        return self._redact_device(stored) or stored

    async def update_device(self, device_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        existing = await self.store.get_device(device_id)
        if not existing:
            return None
        updated = {**existing, **payload}
        if "connection_config" in payload and self.encryption_key:
            updated["connection_config_encrypted"] = encrypt_text(
                json.dumps(payload["connection_config"]),
                self.encryption_key,
            )
            updated["connection_config"] = {}
        stored = await self.store.upsert_device(updated)
        return self._redact_device(stored) or stored

    async def list_devices(self) -> list[dict[str, Any]]:
        return [self._redact_device(device) for device in await self.store.list_devices()]

    async def get_device(self, device_id: str) -> dict[str, Any] | None:
        device = await self.store.get_device(device_id)
        return self._redact_device(device) if device else None

    async def execute(self, request: dict[str, Any], client_ip: str | None = None) -> dict[str, Any]:
        action = request["action"]
        device_id = action["device_id"]
        device = await self.store.get_device(device_id)
        if not device:
            return self._failure(request["request_id"], f"Unknown device: {device_id}")
        device = self._materialize_device(device)
        action_key = resolve_action_key(device.get("type"), action["action_key"])
        supported_actions = device.get("supported_actions") or []
        if supported_actions and action["action_key"] not in supported_actions and action_key not in supported_actions:
            return self._failure(
                request["request_id"],
                f"Action not supported by device: {action['action_key']}",
            )

        auth = request.get("authorisation", {})
        incident_id = auth.get("incident_id")
        approval_level = auth.get("approval_level")
        approved_by = auth.get("approved_by")

        validation = validate_command(
            action_key=action_key,
            device=device,
            requestor={"approval_level": approval_level, "approved_by": approved_by},
            incident_id=incident_id,
            approved_by=approved_by,
        )
        if not validation["valid"]:
            return self._failure(request["request_id"], validation["reason"], validation)

        adapter = ADAPTERS.get(device["connection_type"])
        if not adapter:
            return self._failure(request["request_id"], f"Unsupported connection type: {device['connection_type']}")

        payload = {
            **action.get("parameters", {}),
            "incident_id": incident_id,
        }
        try:
            result = await adapter.execute(device, action_key, payload)
        except AdapterError as exc:
            result = {"success": False, "error": str(exc), "adapter": adapter.name}

        execution_result = "success" if result.get("success") else "failed"
        if not result.get("confirmed", True) and device["connection_type"] in {"MQTT", "HARDWARE_BRIDGE"}:
            execution_result = "unconfirmed"
        elif device["connection_type"] == "MQTT" and result.get("success") and not result.get("confirmed", True):
            execution_result = "unconfirmed"

        log_entry = await self.store.append_action(
            {
                "id": str(uuid.uuid4()),
                "device_id": device_id,
                "org_id": request["org_id"],
                "incident_id": incident_id,
                "action_key": action_key,
                "parameters": action.get("parameters", {}),
                "requested_by": auth.get("requested_by"),
                "requested_from_ip": client_ip,
                "approved_by": approved_by,
                "approval_level": approval_level,
                "approval_timestamp": auth.get("approval_timestamp"),
                "executed_at": now_iso(),
                "execution_result": execution_result,
                "adapter_used": adapter.name,
                "response_data": result,
                "error_message": result.get("error"),
                "auto_revert_scheduled_at": None,
                "reverted_at": None,
                "revert_result": None,
                "log_level": validation["log_level"],
                "life_safety_risk": bool(validation["warnings"]),
                "created_at": now_iso(),
            }
        )

        await self._update_device_after_command(device_id, execution_result)

        if not result.get("success"):
            return self._failure(request["request_id"], result.get("error", "Execution failed"), {
                "action_log_id": log_entry["id"],
                "warnings": validation["warnings"],
            })

        active_override_id = None
        revert_at = None
        if validation["auto_revert"] and validation["revert_action"]:
            active_override_id = str(uuid.uuid4())
            duration_seconds = self._cap_duration(action_key, action.get("parameters", {}), validation["max_duration_seconds"])
            revert_at = (datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)).isoformat()
            await self.store.create_override(
                {
                    "id": active_override_id,
                    "device_id": device_id,
                    "org_id": request["org_id"],
                    "incident_id": incident_id,
                    "action_key": action_key,
                    "action_log_id": log_entry["id"],
                    "status": "active",
                    "started_at": now_iso(),
                    "expires_at": revert_at,
                    "revert_action": validation["revert_action"],
                }
            )
            await self.store.update_override(active_override_id, status="active")
            await self.store.update_action_log(
                log_entry["id"],
                auto_revert_scheduled_at=revert_at,
            )
            await self._schedule_revert(
                override_id=active_override_id,
                device_id=device_id,
                revert_action=validation["revert_action"],
                duration_seconds=duration_seconds,
                incident_id=incident_id,
            )
            await self.store.update_override(active_override_id, auto_revert=True)

        response = {
            "request_id": request["request_id"],
            "status": "success",
            "data": {
                "action_log_id": log_entry["id"],
                "device_id": device_id,
                "device_name": device["name"],
                "action_key": action_key,
                "execution_result": execution_result,
                "adapter_used": adapter.name,
                "executed_at": log_entry["executed_at"],
                "confirmed": result.get("success", False),
                "auto_revert_scheduled": bool(active_override_id),
                "revert_at": revert_at,
                "revert_action": validation["revert_action"],
                "warnings": validation["warnings"],
                "active_override_id": active_override_id,
            },
        }
        return response

    async def revert(self, override_id: str, manual: bool = True) -> dict[str, Any]:
        override = await self.store.get_override(override_id)
        if not override:
            return self._failure(override_id, f"Unknown override: {override_id}")
        if override.get("status") not in {"active", "unconfirmed"}:
            return self._failure(override_id, f"Override is not active: {override['status']}")

        device = await self.store.get_device(override["device_id"])
        if not device:
            return self._failure(override_id, f"Unknown device: {override['device_id']}")
        adapter = ADAPTERS.get(device["connection_type"])
        if not adapter:
            return self._failure(override_id, f"Unsupported connection type: {device['connection_type']}")

        payload = {"source": "manual_revert" if manual else "auto_revert", "override_id": override_id}
        last_result: dict[str, Any] | None = None
        for attempt in range(self.revert_retry_count):
            last_result = await adapter.execute(device, override["revert_action"], payload)
            if last_result.get("success"):
                break
            await asyncio.sleep(2**attempt)

        if not last_result or not last_result.get("success"):
            await self.store.update_override(override_id, status="revert_failed")
            return self._failure(override_id, "Revert command failed", last_result or {})

        await self.store.update_override(
            override_id,
            status="reverted",
            reverted_at=now_iso(),
            revert_result="success",
        )
        task = self.store.override_tasks.pop(override_id, None)
        if task:
            task.cancel()
        return {
            "override_id": override_id,
            "status": "success",
            "data": last_result,
        }

    async def active_overrides(self, org_id: str | None = None) -> list[dict[str, Any]]:
        return await self.store.list_active_overrides(org_id)

    async def log_query(self) -> list[dict[str, Any]]:
        return await self.store.list_actions()

    async def get_action_status(self, identifier: str) -> dict[str, Any]:
        actions = await self.store.list_actions()
        action = next(
            (
                entry
                for entry in reversed(actions)
                if entry.get("id") == identifier
                or entry.get("device_id") == identifier
                or entry.get("action_key") == identifier
            ),
            None,
        )
        override = await self.store.get_override(identifier)
        if not override and action:
            override = next(
                (
                    item
                    for item in (await self.store.list_active_overrides())
                    if item.get("action_log_id") == action.get("id")
                ),
                None,
            )
        return {
            "identifier": identifier,
            "action": action,
            "override": override,
            "status": override.get("status") if override else (action.get("execution_result") if action else "unknown"),
        }

    async def incident_resolved(self, incident_id: str) -> dict[str, Any]:
        overrides = await self.store.list_overrides_for_incident(incident_id)
        results = []
        for override in overrides:
            results.append(await self.revert(override["id"], manual=False))
        return {"incident_id": incident_id, "reverted_overrides": results}

    async def health(self) -> dict[str, Any]:
        devices = await self.store.list_devices()
        adapters = await self._adapter_health(devices)
        return {
            "status": "ok",
            "environment": os.getenv("ENVIRONMENT", "production"),
            "devices": len(devices),
            "adapters": adapters,
        }

    async def health_bridges(self) -> dict[str, Any]:
        expired = await self.store.prune_expired_bridge_commands()
        return {
            "status": "ok",
            "bridges": list(self.store.hardware_bridges.values()),
            "queued_commands": await self.store.list_bridge_queue(),
            "expired_commands": expired,
            "replayable_commands": await self.replay_bridge_queue(),
        }

    async def _revert_after_delay(
        self,
        override_id: str,
        device_id: str,
        revert_action: str,
        duration_seconds: int,
        incident_id: str | None,
    ) -> None:
        await asyncio.sleep(duration_seconds)
        override = await self.store.get_override(override_id)
        if not override or override.get("status") != "active":
            return
        await self.revert(override_id, manual=False)

    def set_scheduler(self, scheduler: Any) -> None:
        self.scheduler = scheduler

    async def reschedule_active_overrides(self) -> None:
        for override in await self.store.list_active_overrides():
            expires_at = parse_iso(override.get("expires_at"))
            if not expires_at:
                continue
            delay = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
            device_id = override["device_id"]
            revert_action = override.get("revert_action")
            if revert_action:
                await self._schedule_revert(
                    override_id=override["id"],
                    device_id=device_id,
                    revert_action=revert_action,
                    duration_seconds=delay,
                    incident_id=override.get("incident_id"),
                )

    async def replay_bridge_queue(self) -> dict[str, Any]:
        try:
            import websockets
        except ModuleNotFoundError:
            return {"attempted": 0, "replayed": 0, "remaining": len(await self.store.list_bridge_queue())}

        queued = await self.store.list_bridge_queue()
        replayed = 0
        for command in queued:
            gateway_ws_url = command.get("gateway_websocket_url")
            bridge_key = command.get("bridge_key")
            local_device_id = command.get("local_device_id")
            if not (gateway_ws_url and bridge_key and local_device_id):
                continue
            payload = {
                "type": command.get("type", "execute_action"),
                "device_local_id": local_device_id,
                "action": command.get("action"),
                "parameters": command.get("parameters", {}),
                "correlation_id": command.get("correlation_id"),
                "expires_at": command.get("expires_at"),
            }
            try:
                async with websockets.connect(gateway_ws_url, extra_headers={"X-Bridge-Key": bridge_key}) as ws:
                    await ws.send(json.dumps(payload))
                    await asyncio.wait_for(ws.recv(), timeout=15.0)
                await self.store.remove_bridge_command(command["id"])
                replayed += 1
            except Exception:
                continue
        remaining = len(await self.store.list_bridge_queue())
        return {"attempted": len(queued), "replayed": replayed, "remaining": remaining}

    async def _schedule_revert(
        self,
        override_id: str,
        device_id: str,
        revert_action: str,
        duration_seconds: int,
        incident_id: str | None,
    ) -> None:
        if self.scheduler is not None:
            run_date = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
            self.scheduler.add_job(
                self._revert_after_delay,
                trigger="date",
                run_date=run_date,
                id=override_id,
                replace_existing=True,
                kwargs={
                    "override_id": override_id,
                    "device_id": device_id,
                    "revert_action": revert_action,
                    "duration_seconds": duration_seconds,
                    "incident_id": incident_id,
                },
            )
        else:
            self.store.override_tasks[override_id] = asyncio.create_task(
                self._revert_after_delay(
                    override_id=override_id,
                    device_id=device_id,
                    revert_action=revert_action,
                    duration_seconds=duration_seconds,
                    incident_id=incident_id,
                )
            )

    async def reconcile_overrides(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        expired = []
        for override in await self.store.list_active_overrides():
            expires_at = parse_iso(override.get("expires_at"))
            if expires_at and expires_at <= now:
                expired.append(override["id"])
        results = []
        for override_id in expired:
            results.append(await self.revert(override_id, manual=False))
        bridge_expired = await self.store.prune_expired_bridge_commands()
        bridge_replay = await self.replay_bridge_queue()
        return {
            "expired_overrides": expired,
            "results": results,
            "expired_bridge_commands": bridge_expired,
            "bridge_replay": bridge_replay,
        }

    async def _update_device_after_command(self, device_id: str, result: str) -> None:
        device = await self.store.get_device(device_id)
        if not device:
            return
        device["last_command_at"] = now_iso()
        device["last_command_result"] = result
        await self.store.upsert_device(device)

    async def _adapter_health(self, devices: list[dict[str, Any]]) -> dict[str, Any]:
        health: dict[str, Any] = {}
        by_type: dict[str, dict[str, Any]] = {}
        for device in devices:
            by_type.setdefault(device.get("connection_type"), device)
        for adapter_name, adapter in ADAPTERS.items():
            device = by_type.get(adapter_name)
            probe = await adapter.check_connectivity(device)
            probe["configured"] = probe.get("configured", bool(device))
            probe["stored_status"] = self.store.adapter_status.get(adapter_name, {}).get("status", "unknown")
            health[adapter_name] = probe
        return health

    async def register_hardware_bridge(self, payload: dict[str, Any]) -> dict[str, Any]:
        record = {
            "id": payload.get("id", str(uuid.uuid4())),
            "org_id": payload["org_id"],
            "name": payload["name"],
            "location": payload.get("location"),
            "gateway_key": payload["gateway_key"],
            "status": payload.get("status", "offline"),
            "last_connected": payload.get("last_connected"),
            "firmware_version": payload.get("firmware_version"),
            "ip_address": payload.get("ip_address"),
            "created_at": payload.get("created_at", now_iso()),
        }
        return await self.store.upsert_hardware_bridge(record)

    async def list_hardware_bridges(self) -> list[dict[str, Any]]:
        return await self.store.list_hardware_bridges()

    async def get_hardware_bridge(self, bridge_id: str) -> dict[str, Any] | None:
        return self.store.hardware_bridges.get(bridge_id)

    async def update_hardware_bridge(self, bridge_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.store.hardware_bridges.get(bridge_id)
        if not existing:
            return None
        updated = {**existing, **payload, "id": bridge_id}
        return await self.store.upsert_hardware_bridge(updated)

    def _cap_duration(self, action_key: str, parameters: dict[str, Any], default_max: int) -> int:
        requested = int(parameters.get("duration_seconds", default_max))
        ceiling = default_max
        if action_key.startswith("traffic_"):
            ceiling = min(ceiling, self.max_traffic_preemption_seconds)
        if action_key.startswith("door_") or action_key.startswith("gate_") or action_key.startswith("lock_"):
            ceiling = min(ceiling, self.max_lockdown_seconds)
        if action_key.startswith("elevator_"):
            ceiling = min(ceiling, self.max_elevator_hold_seconds)
        return max(1, min(requested, ceiling))

    def _redact_device(self, device: dict[str, Any] | None) -> dict[str, Any] | None:
        if not device:
            return None
        cloned = dict(device)
        if "connection_config" in cloned:
            cloned["connection_config"] = self._redact_connection_config(cloned["connection_config"])
        if "connection_config_encrypted" in cloned:
            cloned["connection_config_encrypted"] = redact_secret(cloned["connection_config_encrypted"])
        return cloned

    def _redact_connection_config(self, config: Any) -> Any:
        if not isinstance(config, dict):
            return config
        redacted = dict(config)
        credentials = redacted.get("credentials")
        if isinstance(credentials, dict):
            redacted["credentials"] = {key: redact_secret(value) if isinstance(value, str) else value for key, value in credentials.items()}
        return redacted

    def _materialize_device(self, device: dict[str, Any]) -> dict[str, Any]:
        materialized = dict(device)
        encrypted = materialized.get("connection_config_encrypted")
        if encrypted and self.encryption_key:
            try:
                materialized["connection_config"] = json.loads(decrypt_text(encrypted, self.encryption_key))
            except Exception:
                materialized["connection_config"] = {}
        return materialized

    def _failure(self, request_id: str, reason: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "request_id": request_id,
            "status": "failed",
            "error": reason,
        }
        if extra:
            payload["data"] = extra
        return payload


SERVICE = AutonomousControlService()
