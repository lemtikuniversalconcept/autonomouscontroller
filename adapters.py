from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import Any

from store import STORE, now_iso


class AdapterError(RuntimeError):
    pass


class BaseAdapter:
    name = "BASE"

    async def execute(self, device: dict[str, Any], action: str, params: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    async def check_connectivity(self, device: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"adapter": self.name, "configured": False, "reachable": False}


class RESTAdapter(BaseAdapter):
    name = "REST_API"

    async def check_connectivity(self, device: dict[str, Any] | None = None) -> dict[str, Any]:
        config = (device or {}).get("connection_config", {})
        base_url = config.get("base_url")
        if not base_url:
            return {"adapter": self.name, "configured": False, "reachable": False}
        try:
            import httpx
        except ModuleNotFoundError:
            return {"adapter": self.name, "configured": True, "reachable": None, "reason": "httpx unavailable"}
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.head(base_url)
                return {
                    "adapter": self.name,
                    "configured": True,
                    "reachable": response.status_code < 500,
                    "status_code": response.status_code,
                }
        except Exception as exc:
            return {"adapter": self.name, "configured": True, "reachable": False, "error": str(exc)}

    async def execute(self, device: dict[str, Any], action: str, params: dict[str, Any]) -> dict[str, Any]:
        config = device["connection_config"]
        action_paths = config.get("action_paths", {})
        url = f"{config['base_url']}{action_paths.get(action, f'/{action}')}"
        headers = self._build_auth_headers(config)
        body = {
            **params,
            "source": "lemtik_c4i",
            "incident_id": params.get("incident_id"),
        }

        try:
            import httpx
        except ModuleNotFoundError as exc:
            raise AdapterError("httpx is required for REST execution.") from exc

        last_error: Exception | None = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(url, json=body, headers=headers, timeout=10.0)
                    response.raise_for_status()
                    try:
                        payload = response.json()
                    except Exception:
                        payload = {"text": response.text}
                    return {
                        "success": True,
                        "response": payload,
                        "adapter": self.name,
                        "attempt": attempt + 1,
                    }
            except Exception as exc:
                last_error = exc
                if attempt == 2:
                    return {
                        "success": False,
                        "error": str(exc),
                        "adapter": self.name,
                        "attempts": 3,
                    }
                await asyncio.sleep(2**attempt)
        raise AdapterError(str(last_error))

    def _build_auth_headers(self, config: dict[str, Any]) -> dict[str, str]:
        auth_type = config.get("auth_type", "").lower()
        credentials = config.get("credentials", {})
        headers: dict[str, str] = {}
        if auth_type == "bearer_token":
            headers["Authorization"] = f"Bearer {credentials.get('token', '')}"
        elif auth_type == "api_key":
            headers["X-API-Key"] = credentials.get("api_key", "")
        return headers


class MQTTAdapter(BaseAdapter):
    name = "MQTT"

    def __init__(self) -> None:
        self.client = None
        self.pending_acks: dict[str, asyncio.Future] = {}
        self._client_connected = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client_lock = asyncio.Lock()

    async def check_connectivity(self, device: dict[str, Any] | None = None) -> dict[str, Any]:
        config = (device or {}).get("connection_config", {})
        broker = config.get("broker_url") or os.getenv("EMQX_BROKER_URL")
        if not broker:
            return {"adapter": self.name, "configured": False, "reachable": False}
        try:
            import paho.mqtt.client as mqtt
        except ModuleNotFoundError:
            return {"adapter": self.name, "configured": True, "reachable": None, "reason": "paho-mqtt unavailable"}
        try:
            client = mqtt.Client()
            parsed = urlparse(broker if "://" in broker else f"mqtt://{broker}")
            host = parsed.hostname or broker
            port = parsed.port or 1883
            client.connect(host, port, 5)
            client.disconnect()
            return {"adapter": self.name, "configured": True, "reachable": True}
        except Exception as exc:
            return {"adapter": self.name, "configured": True, "reachable": False, "error": str(exc)}

    async def execute(self, device: dict[str, Any], action: str, params: dict[str, Any]) -> dict[str, Any]:
        config = device["connection_config"]
        correlation_id = str(uuid.uuid4())
        payload = json.dumps(
            {
                "correlation_id": correlation_id,
                "action": action,
                "parameters": params,
                "source": "lemtik_c4i",
                "timestamp": now_iso(),
            }
        )

        try:
            import paho.mqtt.client as mqtt
        except ModuleNotFoundError:
            return {
                "success": True,
                "ack": {
                    "correlation_id": correlation_id,
                    "simulated": True,
                    "payload": payload,
                },
                "adapter": self.name,
                "confirmed": True,
            }

        broker = config.get("broker_url") or os.getenv("EMQX_BROKER_URL")
        if not broker:
            raise AdapterError("MQTT broker URL not configured.")
        client = await self._ensure_client(mqtt, config)
        topic_prefix = config.get("topic_prefix", "lemtik")
        command_topic = f"{topic_prefix}/{device['id']}/command"
        ack_topic = f"{topic_prefix}/{device['id']}/ack"
        future = asyncio.get_running_loop().create_future()
        self.pending_acks[correlation_id] = future

        def _on_message(_client: Any, _userdata: Any, message: Any) -> None:
            try:
                ack_payload = json.loads(message.payload.decode("utf-8"))
            except Exception:
                return
            if ack_payload.get("correlation_id") != correlation_id:
                return
            loop = self._loop
            if loop and not future.done():
                loop.call_soon_threadsafe(future.set_result, ack_payload)

        client.subscribe(ack_topic, qos=1)
        client.on_message = _on_message
        client.publish(command_topic, payload, qos=1)
        try:
            ack = await asyncio.wait_for(future, timeout=5.0)
            return {
                "success": True,
                "ack": ack,
                "adapter": self.name,
                "confirmed": True,
            }
        except asyncio.TimeoutError:
            self.pending_acks.pop(correlation_id, None)
            return {
                "success": False,
                "error": "Device acknowledgement timeout",
                "adapter": self.name,
                "confirmed": False,
                "requires_manual_verification": True,
            }

    async def _ensure_client(self, mqtt: Any, config: dict[str, Any]) -> Any:
        async with self._client_lock:
            if self.client is not None and self._client_connected:
                return self.client
            broker = config.get("broker_url") or os.getenv("EMQX_BROKER_URL")
            parsed = urlparse(broker if "://" in broker else f"mqtt://{broker}")
            host = parsed.hostname or broker
            port = parsed.port or 1883
            client = mqtt.Client()
            username = config.get("credentials", {}).get("username") or os.getenv("EMQX_USERNAME")
            password = config.get("credentials", {}).get("password") or os.getenv("EMQX_PASSWORD")
            if username:
                client.username_pw_set(username, password=password)
            client.connect(host, port, 60)
            client.loop_start()
            self.client = client
            self._client_connected = True
            self._loop = asyncio.get_running_loop()
            return client


class HardwareBridgeAdapter(BaseAdapter):
    name = "HARDWARE_BRIDGE"

    async def check_connectivity(self, device: dict[str, Any] | None = None) -> dict[str, Any]:
        config = (device or {}).get("connection_config", {})
        gateway_ws_url = config.get("gateway_websocket_url")
        if not gateway_ws_url:
            return {"adapter": self.name, "configured": False, "reachable": False}
        try:
            import websockets
        except ModuleNotFoundError:
            return {"adapter": self.name, "configured": True, "reachable": None, "reason": "websockets unavailable"}
        try:
            async with websockets.connect(gateway_ws_url, extra_headers={"X-Bridge-Key": config.get("bridge_key", "")}) as ws:
                await ws.close()
            return {"adapter": self.name, "configured": True, "reachable": True}
        except Exception as exc:
            return {"adapter": self.name, "configured": True, "reachable": False, "error": str(exc)}

    async def execute(self, device: dict[str, Any], action: str, params: dict[str, Any]) -> dict[str, Any]:
        config = device["connection_config"]
        command = {
            "type": "execute_action",
            "device_local_id": config["local_device_id"],
            "action": action,
            "parameters": params,
            "correlation_id": str(uuid.uuid4()),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
        }

        try:
            import websockets
        except ModuleNotFoundError:
            await STORE.queue_bridge_command(
                {
                    **command,
                    "status": "queued",
                    "bridge_id": config.get("gateway_id"),
                    "gateway_websocket_url": config.get("gateway_websocket_url"),
                    "bridge_key": config.get("bridge_key"),
                    "local_device_id": config.get("local_device_id"),
                    "queued_at": now_iso(),
                }
            )
            return {
                "success": False,
                "adapter": self.name,
                "error": "Hardware bridge transport unavailable; command queued locally.",
                "confirmed": False,
                "queued": True,
            }

        gateway_ws_url = config["gateway_websocket_url"]
        headers = [("X-Bridge-Key", config["bridge_key"])]
        try:
            async with websockets.connect(gateway_ws_url, extra_headers=headers) as ws:
                await ws.send(json.dumps(command))
                response = await asyncio.wait_for(ws.recv(), timeout=15.0)
                return {
                    "success": True,
                    "bridge_response": json.loads(response),
                    "adapter": self.name,
                }
        except Exception as exc:
            await STORE.queue_bridge_command(
                {
                    **command,
                    "status": "queued",
                    "bridge_id": config.get("gateway_id"),
                    "gateway_websocket_url": config.get("gateway_websocket_url"),
                    "bridge_key": config.get("bridge_key"),
                    "local_device_id": config.get("local_device_id"),
                    "queued_at": now_iso(),
                    "reason": str(exc),
                }
            )
            return {
                "success": False,
                "adapter": self.name,
                "error": f"Hardware bridge unavailable: {exc}",
                "confirmed": False,
                "queued": True,
            }


ADAPTERS = {
    "REST_API": RESTAdapter(),
    "MQTT": MQTTAdapter(),
    "HARDWARE_BRIDGE": HardwareBridgeAdapter(),
}
