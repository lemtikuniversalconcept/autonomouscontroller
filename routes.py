from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from security import enforce_source_ip, require_internal_api_key
from service import SERVICE


router = APIRouter(dependencies=[Depends(require_internal_api_key)])


class ExecuteActionModel(BaseModel):
    request_type: str
    request_id: str
    org_id: str
    action: dict[str, Any]
    authorisation: dict[str, Any]
    automation_mode: int | None = None
    manifest: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)


class AutonomousActionModel(BaseModel):
    request_type: str = "autonomous_action"
    request_id: str
    action: dict[str, Any]
    authorisation: dict[str, Any]
    automation_mode: int | None = None
    manifest: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)


class DeviceModel(BaseModel):
    id: str
    org_id: str
    name: str
    type: str
    connection_type: str
    connection_config: dict[str, Any] = Field(default_factory=dict)
    supported_actions: list[str] = Field(default_factory=list)
    building_id: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    lat: float | None = None
    lng: float | None = None
    floor: int | None = None
    zone: str | None = None
    area: str | None = None
    status: str | None = "online"


class HardwareBridgeModel(BaseModel):
    id: str | None = None
    org_id: str
    name: str
    location: str | None = None
    gateway_key: str
    status: str | None = "offline"
    last_connected: str | None = None
    firmware_version: str | None = None
    ip_address: str | None = None


def _effective_org_id(payload_org_id: str | None, header_org_id: str | None, authorisation: dict[str, Any]) -> str:
    return payload_org_id or header_org_id or authorisation.get("org_id") or "unknown"


@router.post("/execute")
async def execute_action(
    payload: ExecuteActionModel,
    request: Request,
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    enforce_source_ip(request)
    request_payload = payload.model_dump()
    request_payload["org_id"] = _effective_org_id(request_payload.get("org_id"), x_org_id, request_payload.get("authorisation", {}))
    return await SERVICE.execute(request_payload, client_ip=request.client.host if request.client else None)


@router.post("/api/v1/execute")
async def execute_action_v1(
    payload: ExecuteActionModel,
    request: Request,
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    enforce_source_ip(request)
    request_payload = payload.model_dump()
    request_payload["org_id"] = _effective_org_id(request_payload.get("org_id"), x_org_id, request_payload.get("authorisation", {}))
    return await SERVICE.execute(request_payload, client_ip=request.client.host if request.client else None)


@router.post("/api/v1/autonomous/action")
async def autonomous_action(
    payload: AutonomousActionModel,
    request: Request,
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    enforce_source_ip(request)
    action = payload.action
    request_payload = {
        "request_type": payload.request_type,
        "request_id": payload.request_id,
        "org_id": _effective_org_id(action.get("org_id"), x_org_id, payload.authorisation),
        "action": {
            "action_key": action.get("command") or action.get("action_key"),
            "device_id": action.get("target_id") or action.get("device_id"),
            "parameters": {
                **{k: v for k, v in action.items() if k not in {"type", "target_id", "device_id", "command", "route_ids"}},
                "route_ids": action.get("route_ids", []),
                "duration_seconds": action.get("duration_seconds"),
                "reason": action.get("reason"),
                "incident_id": action.get("incident_id") or payload.authorisation.get("incident_id"),
            },
        },
        "authorisation": payload.authorisation,
    }
    return await SERVICE.execute(request_payload, client_ip=request.client.host if request.client else None)


@router.post("/revert/{override_id}")
async def revert_override(override_id: str) -> dict[str, Any]:
    return await SERVICE.revert(override_id, manual=True)


@router.post("/api/v1/autonomous/revert/{override_id}")
async def revert_override_v1(override_id: str) -> dict[str, Any]:
    return await SERVICE.revert(override_id, manual=True)


@router.get("/overrides/active")
async def active_overrides(org_id: str | None = None) -> list[dict[str, Any]]:
    return await SERVICE.active_overrides(org_id)


@router.get("/api/v1/overrides/active")
async def active_overrides_v1(org_id: str | None = None) -> list[dict[str, Any]]:
    return await SERVICE.active_overrides(org_id)


@router.get("/api/v1/autonomous/active")
async def autonomous_active(org_id: str | None = None) -> list[dict[str, Any]]:
    return await SERVICE.active_overrides(org_id)


@router.get("/api/v1/autonomous/status/{identifier}")
async def autonomous_status(identifier: str) -> dict[str, Any]:
    return await SERVICE.get_action_status(identifier)


@router.get("/devices")
async def list_devices() -> list[dict[str, Any]]:
    return await SERVICE.list_devices()


@router.get("/devices/{device_id}")
async def get_device(device_id: str) -> dict[str, Any] | None:
    return await SERVICE.get_device(device_id)


@router.post("/devices")
async def register_device(payload: DeviceModel) -> dict[str, Any]:
    return await SERVICE.register_device(payload.model_dump())


@router.put("/devices/{device_id}")
async def update_device(device_id: str, payload: DeviceModel) -> dict[str, Any] | None:
    return await SERVICE.update_device(device_id, payload.model_dump())


@router.get("/devices/{device_id}/status")
async def device_status(device_id: str) -> dict[str, Any]:
    device = await SERVICE.get_device(device_id)
    return {"device_id": device_id, "status": device.get("status") if device else "unknown", "device": device}


@router.get("/log")
async def action_log() -> list[dict[str, Any]]:
    return await SERVICE.log_query()


@router.post("/incident/resolved")
async def incident_resolved(payload: dict[str, Any]) -> dict[str, Any]:
    incident_id = payload.get("incident_id")
    return await SERVICE.incident_resolved(incident_id)


@router.get("/health")
async def health() -> dict[str, Any]:
    return await SERVICE.health()


@router.get("/health/bridges")
async def health_bridges() -> dict[str, Any]:
    return await SERVICE.health_bridges()


@router.get("/bridges")
async def list_bridges() -> list[dict[str, Any]]:
    return await SERVICE.list_hardware_bridges()


@router.post("/bridges")
async def register_bridge(payload: HardwareBridgeModel) -> dict[str, Any]:
    return await SERVICE.register_hardware_bridge(payload.model_dump())


@router.get("/bridges/{bridge_id}")
async def get_bridge(bridge_id: str) -> dict[str, Any] | None:
    return await SERVICE.get_hardware_bridge(bridge_id)


@router.put("/bridges/{bridge_id}")
async def update_bridge(bridge_id: str, payload: HardwareBridgeModel) -> dict[str, Any] | None:
    return await SERVICE.update_hardware_bridge(bridge_id, payload.model_dump())
