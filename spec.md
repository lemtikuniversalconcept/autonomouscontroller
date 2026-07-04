# Lemtik Security — Autonomous Control Layer Specification
### Service 4 of 6 — Protocol-Agnostic Smart Infrastructure Control
**Classification:** Internal Engineering — Restricted
**Version:** 1.0
**Status:** Build-Ready

---

## 1. What This Service Is

The Autonomous Control Layer is the service that translates
approved AI decisions into physical actions in the real world.

When the Master Agent recommends clearing a traffic corridor,
holding an elevator, locking a perimeter gate, or activating
CCTV tracking — and a human supervisor approves — this service
executes that command against the actual hardware, regardless
of how that hardware is connected, who manufactured it, or
what protocol it speaks.

It does four things:

1. **Maintains** a registry of every smart device connected
   to the platform and how to communicate with each one
2. **Validates** every incoming command against the constraint
   engine before touching any hardware
3. **Executes** approved commands through the correct
   protocol adapter for each device
4. **Monitors** active overrides continuously and auto-reverts
   when conditions are met or time expires

It does not decide what to do. It does not analyse incidents.
It does not recommend actions. It only executes what has been
approved, within strict constraints, and logs every action
permanently.

---

## 2. The Adapter Design Pattern

The core architectural principle of this service is that
the AI, the Master Agent, and the Relationship API never
need to know how a device is physically connected.

They issue a generic command:
```
Device.TriggerAction(device_id, action, parameters)
```

The Autonomous Control Layer looks up the device in the
registry, finds its connection type, selects the correct
adapter, and handles all protocol-specific communication
internally.

```
Incoming command: TriggerAction("GATE-001", "open", {duration: 300})
        ↓
Device Registry lookup: GATE-001
  connection_type: REST_API
  endpoint: https://gate-controller.client-site.com/api/gate/1
  auth_type: bearer_token
  credentials: [encrypted]
        ↓
REST Adapter selected
        ↓
POST https://gate-controller.client-site.com/api/gate/1/open
Authorization: Bearer [token]
Body: {"duration": 300, "source": "lemtik_c4i", "incident_id": "INC-001"}
        ↓
Response received and logged
        ↓
Confirmation returned to Relationship API
```

The same command structure works whether the device uses
REST, MQTT, hardware bridge, or any future protocol.
Adding a new protocol type means adding one new adapter
class — nothing else in the system changes.

---

## 3. Supported Connection Types

### Type A — REST API (Modern Cloud-Managed Systems)

**Used for:**
Modern commercial security hardware with cloud management
platforms. Examples: Verkada CCTV, Cisco Meraki access
control, HID Global door controllers, Genetec security centre,
modern elevator DCS (Destination Control Systems).

**How it works:**
Standard HTTPS POST/PUT requests to the manufacturer's
cloud API or local controller API. Authentication via
API key, OAuth 2.0, or bearer token stored encrypted
in the device registry.

**Latency:** 100ms–2000ms depending on whether
the API is cloud-hosted or local.

**Failure behaviour:**
If REST call fails, retry up to 3 times with exponential
backoff (1s, 2s, 4s). After 3 failures, mark device as
unreachable, alert Relationship API, log failure.

```python
class RESTAdapter:
    async def execute(self, device: dict, action: str,
                      params: dict) -> dict:
        config = device["connection_config"]
        url = f"{config['base_url']}{config['action_paths'][action]}"
        headers = self._build_auth_headers(config)

        for attempt in range(3):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        url,
                        json={**params,
                              "source": "lemtik_c4i",
                              "incident_id": params.get("incident_id")},
                        headers=headers,
                        timeout=10.0
                    )
                    response.raise_for_status()
                    return {"success": True,
                            "response": response.json(),
                            "adapter": "REST",
                            "attempt": attempt + 1}
            except Exception as e:
                if attempt == 2:
                    return {"success": False,
                            "error": str(e),
                            "adapter": "REST",
                            "attempts": 3}
                await asyncio.sleep(2 ** attempt)
```

---

### Type B — MQTT / CoAP / AMQP (Real-Time IoT Systems)

**Used for:**
Traffic light controllers, industrial IoT sensors,
real-time security loops, edge devices where sub-second
latency is mandatory and cloud dependency is unacceptable.
Municipal traffic management systems commonly use NTCIP 1202
protocol over MQTT or direct serial. EMQX is the recommended
MQTT broker for this service.

**How it works:**
The service maintains persistent MQTT connections to
configured brokers. Commands are published to device-specific
topics. Devices publish acknowledgement to response topics.
The service subscribes to response topics and waits for
hardware confirmation before returning success.

**Latency:** 10ms–200ms (significantly faster than REST)

**Failure behaviour:**
MQTT is designed for unreliable networks. If the broker
connection drops, the adapter reconnects automatically
with QoS 1 (at-least-once delivery) ensuring commands
are not silently lost. If device acknowledgement is not
received within timeout, the command is flagged as
unconfirmed and a human alert is raised.

```python
class MQTTAdapter:
    def __init__(self):
        self.client = mqtt.Client()
        self.pending_acks = {}

    async def execute(self, device: dict, action: str,
                      params: dict) -> dict:
        config = device["connection_config"]
        command_topic = f"{config['topic_prefix']}/{device['id']}/command"
        ack_topic = f"{config['topic_prefix']}/{device['id']}/ack"
        correlation_id = str(uuid.uuid4())

        payload = json.dumps({
            "correlation_id": correlation_id,
            "action": action,
            "parameters": params,
            "source": "lemtik_c4i",
            "timestamp": now_iso()
        })

        # Subscribe to ack topic and wait for response
        ack_future = asyncio.Future()
        self.pending_acks[correlation_id] = ack_future

        self.client.publish(command_topic, payload, qos=1)

        try:
            ack = await asyncio.wait_for(ack_future, timeout=5.0)
            return {"success": True, "ack": ack, "adapter": "MQTT"}
        except asyncio.TimeoutError:
            return {"success": False,
                    "error": "Device acknowledgement timeout",
                    "adapter": "MQTT",
                    "confirmed": False,
                    "requires_manual_verification": True}
```

---

### Type C — Hardware Bridge / Edge Gateway

**Used for:**
Legacy infrastructure with no modern API or IoT capability.
Older traffic light controllers, legacy elevator relay
systems, traditional access control panels using RS-485,
Modbus, dry contacts, or serial protocols.

**How it works:**
A small Lemtik Edge Gateway device is installed on-site
at the client's premises. This gateway:
- Runs a lightweight Node-RED or Python runtime locally
- Connects to Lemtik's cloud via a secure persistent tunnel
- Translates Lemtik REST commands into legacy hardware
  protocols on the local network
- Acts as a bridge between modern cloud commands
  and physical relay outputs

The gateway communicates with the Autonomous Control Layer
via an encrypted WebSocket tunnel. Commands flow down,
telemetry flows up.

**Latency:** 50ms–500ms (adds gateway translation time)

**Hardware bridge spec:**
- Small form factor device (Raspberry Pi 4 or equivalent)
- Can be industrial-grade for harsh environments
- Connects via Ethernet or WiFi to client local network
- 4G/LTE failover for when local network drops
- Local buffering — queues commands if cloud connectivity
  drops and executes when reconnected (with expiry limits)

```python
class HardwareBridgeAdapter:
    async def execute(self, device: dict, action: str,
                      params: dict) -> dict:
        config = device["connection_config"]
        gateway_ws_url = config["gateway_websocket_url"]

        command = {
            "type": "execute_action",
            "device_local_id": config["local_device_id"],
            "action": action,
            "parameters": params,
            "correlation_id": str(uuid.uuid4()),
            "expires_at": (datetime.now() +
                          timedelta(seconds=30)).isoformat()
        }

        async with websockets.connect(
            gateway_ws_url,
            extra_headers={"X-Bridge-Key": config["bridge_key"]}
        ) as ws:
            await ws.send(json.dumps(command))
            response = await asyncio.wait_for(
                ws.recv(), timeout=15.0)
            return {"success": True,
                    "bridge_response": json.loads(response),
                    "adapter": "HARDWARE_BRIDGE"}
```

---

## 4. Supported Device Types & Actions

The registry supports any device type. This list is not
exhaustive — new device types are added by registering
them with their supported actions. The service does not
need to be redeployed to support a new device type.

### 4.1 CCTV Cameras

```
Supported actions:
  activate              — Power on camera, begin recording
  deactivate            — Return to standby (does not delete footage)
  stream_to_dashboard   — Route live feed to C4I dashboard
  ptz_move              — Pan, tilt, zoom to coordinates or direction
  ptz_track             — Begin tracking a detected object/person
  ptz_preset            — Move to a saved preset position
  snapshot              — Capture still image and store
  set_recording_quality — Adjust resolution/bitrate for bandwidth
  flag_footage          — Mark time segment as evidence (prevent overwrite)

Approval required: None for activate, stream, snapshot
                   Supervisor for ptz_track, flag_footage
```

### 4.2 Smart Gates (Vehicle & Pedestrian)

```
Supported actions:
  open                  — Open gate (with optional duration)
  close                 — Close gate
  open_and_hold         — Open and lock open until released
  lock                  — Lock gate closed (cannot be opened locally)
  unlock                — Release lock, return to normal operation
  emergency_open        — Override all locks (fire safety mode)
  get_status            — Query current state

Approval required: Supervisor for open, open_and_hold
                   Manager for lock (prevents local exit)
                   Auto-execute never for emergency_open
                     (requires active incident + manager)
```

### 4.3 Smart Doors & Access Control

```
Supported actions:
  unlock                — Grant access through specific door
  lock                  — Secure door (local badge still works unless...)
  lock_all_local        — Override local badge readers (high risk)
  grant_access_officer  — Unlock for specific officer badge only
  restrict_area         — Lock all doors in a defined zone
  get_status            — Query current state

Connection protocols: OSDP, Genetec API, HID Global API,
                      Software House API, REST webhook

Approval required: Supervisor for unlock, lock
                   Manager for lock_all_local, restrict_area
```

### 4.4 Smart Elevators

```
Supported actions:
  hold_at_floor         — Hold elevator at specific floor
  send_to_floor         — Send elevator to floor immediately
  vip_mode              — Ignore hall calls, serve one officer only
  restrict_floors       — Prevent access to specific floors
  release               — Return to normal operation
  get_status            — Query current position and mode

Connection: Manufacturer DCS API
  Otis Compass API
  TK Elevator AGILE API
  Schindler PORT API
  KONE Connect API
  Generic BMS (Building Management System) API

Approval required: Supervisor for hold_at_floor, send_to_floor,
                              vip_mode
                   Manager for restrict_floors
```

### 4.5 Smart Escalators

```
Supported actions:
  set_direction         — Change direction of travel
  stop                  — Halt escalator (safety stop)
  start                 — Resume normal operation
  set_speed             — Adjust speed (where supported)
  get_status            — Query current state

Approval required: Supervisor for set_direction
                   Manager for stop (public safety impact)
```

### 4.6 Traffic Light Controllers

```
Supported actions:
  green_corridor        — Signal preemption along officer route
  single_preempt        — Preempt single intersection
  release_intersection  — Return intersection to normal cycle
  release_all           — Release all active preemptions
  get_status            — Query intersection state

Connection protocols: NTCIP 1202 (standard traffic protocol)
                      via CTMS (Central Traffic Management System)
                      MQTT to intersection controllers
                      REST to city traffic management API

Approval required: Manager for green_corridor, single_preempt
                   (systemic public impact)
Auto-revert: Mandatory — all traffic preemptions auto-release
             when officer arrives or after max duration
```

### 4.7 Smart Locks

```
Supported actions:
  lock                  — Engage lock
  unlock                — Release lock
  lock_zone             — Lock all locks in a defined zone
  unlock_zone           — Unlock all locks in a defined zone
  get_status            — Query lock state

Approval required: Supervisor for lock, unlock
                   Manager for lock_zone (contains people)
```

### 4.8 Intercoms & Communication Devices

```
Supported actions:
  broadcast_message     — Push audio message to device
  open_channel          — Open two-way audio with officer
  mute                  — Silence device
  get_status            — Query device state

Approval required: None for broadcast_message
                   Supervisor for open_channel
```

### 4.9 Smart Barriers & Bollards

```
Supported actions:
  raise                 — Raise bollard/barrier (block vehicle)
  lower                 — Lower bollard/barrier (allow vehicle)
  emergency_raise       — Immediate raise regardless of vehicle presence
  get_status            — Query barrier state

Approval required: Supervisor for raise, lower
                   Manager for emergency_raise
                     (risk of vehicle damage)
```

### 4.10 Drones (Where Connected)

```
Supported actions:
  deploy                — Launch drone to coordinates
  return_to_base        — Return drone to charging station
  stream_feed           — Route drone camera to dashboard
  set_waypoints         — Define patrol or surveillance path
  hover                 — Hold position at current location
  land                  — Land immediately at current position

Approval required: Manager for deploy, set_waypoints
                   Supervisor for stream_feed, hover
```

---

## 5. Constraint & Validation Engine

Every command passes through the constraint engine before
any adapter is called. If validation fails, the command
is rejected and the reason is returned to the caller.
No hardware is ever touched before this passes.

### 5.1 Constraint Rules

```python
CONSTRAINT_RULES = {

    # CCTV — passive observation, low risk
    "cctv_activate": {
        "approval_level": None,
        "auto_execute": True,
        "requires_active_incident": True,
        "max_duration_seconds": 3600,
        "auto_revert": True,
        "revert_action": "deactivate",
        "risk_level": "low",
        "log_level": "standard",
        "life_safety_risk": False,
    },
    "cctv_ptz_track": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 3600,
        "auto_revert": False,
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },

    # Elevators — localised physical impact
    "elevator_hold": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 300,
        "auto_revert": True,
        "revert_action": "release",
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },
    "elevator_vip_mode": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 600,
        "auto_revert": True,
        "revert_action": "release",
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },
    "elevator_restrict_floors": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 1800,
        "auto_revert": True,
        "revert_action": "release",
        "risk_level": "high",
        "log_level": "critical",
        "life_safety_risk": True,
        "life_safety_note": "Restricts floor access — verify no medical emergency on restricted floors"
    },

    # Doors & Access — localised physical impact
    "door_unlock": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 120,
        "auto_revert": True,
        "revert_action": "lock",
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },
    "door_lock_zone": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 1800,
        "auto_revert": True,
        "revert_action": "unlock_zone",
        "risk_level": "critical",
        "log_level": "critical",
        "life_safety_risk": True,
        "life_safety_note": "Locks people inside zone — fire exits must remain operational"
    },

    # Gates — localised physical impact
    "gate_open": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 300,
        "auto_revert": True,
        "revert_action": "close",
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },
    "gate_lock": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 1800,
        "auto_revert": True,
        "revert_action": "unlock",
        "risk_level": "high",
        "log_level": "critical",
        "life_safety_risk": True,
        "life_safety_note": "Prevents exit — verify emergency vehicle access maintained"
    },

    # Traffic lights — systemic public impact
    "traffic_green_corridor": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 600,
        "auto_revert": True,
        "revert_action": "release_all",
        "risk_level": "high",
        "log_level": "critical",
        "life_safety_risk": True,
        "life_safety_note": "Affects public road safety — ensure route is clear before preemption"
    },
    "traffic_single_preempt": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 300,
        "auto_revert": True,
        "revert_action": "release_intersection",
        "risk_level": "high",
        "log_level": "critical",
        "life_safety_risk": True,
    },

    # Barriers
    "barrier_raise": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 600,
        "auto_revert": True,
        "revert_action": "lower",
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },
    "barrier_emergency_raise": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 3600,
        "auto_revert": False,
        "risk_level": "critical",
        "log_level": "critical",
        "life_safety_risk": True,
    },

    # Drones
    "drone_deploy": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 1800,
        "auto_revert": True,
        "revert_action": "return_to_base",
        "risk_level": "high",
        "log_level": "critical",
        "life_safety_risk": False,
    },
}
```

### 5.2 Validation Function

```python
def validate_command(
    action_key: str,
    device: dict,
    requestor: dict,
    incident_id: str | None,
    approved_by: str | None
) -> dict:

    constraint = CONSTRAINT_RULES.get(action_key)
    if not constraint:
        return {
            "valid": False,
            "reason": f"Unknown action: {action_key}. "
                      f"Action not in constraint registry."
        }

    # Must have active incident linked
    if constraint["requires_active_incident"] and not incident_id:
        return {
            "valid": False,
            "reason": "No active incident linked. "
                      "All autonomous actions require an active incident ID."
        }

    # Check approval requirement
    if not constraint["auto_execute"]:
        if not approved_by:
            return {
                "valid": False,
                "reason": f"Approval required from: {constraint['approval_level']}",
                "approval_required": True,
                "approval_level": constraint["approval_level"],
                "pending": True
            }
        # Verify approver has sufficient role
        if not requestor_has_role(approved_by, constraint["approval_level"]):
            return {
                "valid": False,
                "reason": f"Approver does not have required role: "
                          f"{constraint['approval_level']}"
            }

    # Life safety warning — never block, always surface
    warnings = []
    if constraint["life_safety_risk"]:
        warnings.append({
            "type": "life_safety",
            "message": constraint.get("life_safety_note",
                "This action has life-safety implications. "
                "Verify safety conditions before executing.")
        })

    return {
        "valid": True,
        "constraint": constraint,
        "warnings": warnings,
        "max_duration_seconds": constraint["max_duration_seconds"],
        "auto_revert": constraint["auto_revert"],
        "revert_action": constraint.get("revert_action"),
        "log_level": constraint["log_level"]
    }
```

---

## 6. Fail-Safe Behaviour

Network drops, device failures, and partial executions
happen in the real world. Every failure scenario has a
defined behaviour that defaults to the safest state.

### 6.1 Network Drop During Active Override

```
Scenario: Traffic light preemption is active.
          Network between Lemtik and CTMS drops.

Behaviour:
  1. The traffic management system detects loss of
     preemption signal
  2. NTCIP standard behaviour: intersection automatically
     reverts to normal programmed cycle after signal loss
     (this is a hardware safety standard, not Lemtik's code)
  3. Lemtik marks the override as "connection_lost"
  4. Alert sent to supervisor: "Traffic preemption signal lost
     — intersection has reverted to normal cycle"
  5. Override marked as inactive in database
  6. When connection restores, Lemtik does NOT
     automatically re-execute — supervisor must re-approve

Safety principle: On network loss, always fail toward
                  the safer state. Never auto-retry
                  safety-critical commands.
```

### 6.2 Device Does Not Acknowledge

```
Scenario: Elevator hold command sent, no ACK received.

Behaviour:
  1. Adapter waits for ACK (5 second timeout for MQTT,
     10 seconds for REST)
  2. On timeout, command logged as "unconfirmed"
  3. Alert to supervisor: "Elevator hold command sent but
     not confirmed by device. Verify manually."
  4. Override marked as "unconfirmed" — not "active"
  5. Auto-revert timer does NOT start (cannot revert
     something we are not sure executed)
  6. Supervisor must manually verify and close
```

### 6.3 Revert Command Fails

```
Scenario: Elevator hold has expired. Revert command
          (release) is sent but fails.

Behaviour:
  1. Revert attempted up to 3 times
  2. On third failure, critical alert to manager:
     "URGENT: Elevator ELEV-001 may still be in hold mode.
      Revert command failed. Manual intervention required."
  3. Override marked as "revert_failed"
  4. Escalation continues every 5 minutes until
     manually resolved
  5. Incident linked — all context preserved for
     on-site engineer
```

### 6.4 Hardware Bridge Goes Offline

```
Scenario: On-site Lemtik Edge Gateway loses power or
          connectivity during an active incident.

Behaviour:
  1. Gateway detects loss of cloud tunnel
  2. Gateway activates local safety mode:
     — All active overrides triggered via this gateway
       are logged as "gateway_offline"
     — Gateway attempts to revert all active commands
       locally before shutting down if possible
  3. Lemtik cloud marks all gateway devices as offline
  4. Alert to supervisor with list of devices now uncontrolled
  5. Gateway buffers any new incoming commands locally
     (up to 60 seconds) in case connectivity restores
  6. If connectivity does not restore within 60 seconds,
     commands expire and are not executed
```

---

## 7. Auto-Revert System

Every action with auto_revert=True has a revert timer
started the moment execution is confirmed.

```python
import asyncio
from datetime import datetime, timedelta

active_overrides = {}

async def start_revert_timer(
    override_id: str,
    device_id: str,
    revert_action: str,
    duration_seconds: int,
    incident_id: str
):
    active_overrides[override_id] = {
        "device_id": device_id,
        "revert_action": revert_action,
        "expires_at": datetime.now() + timedelta(seconds=duration_seconds),
        "incident_id": incident_id,
        "status": "active"
    }

    await asyncio.sleep(duration_seconds)

    # Check if incident is resolved — if so, revert
    # Check if override was manually cancelled — if so, skip
    if active_overrides.get(override_id, {}).get("status") == "active":
        await execute_revert(override_id, device_id, revert_action)

async def execute_revert(override_id, device_id, revert_action):
    device = get_device_from_registry(device_id)
    result = await execute_command(device, revert_action, {
        "source": "auto_revert",
        "override_id": override_id
    })
    if result["success"]:
        active_overrides[override_id]["status"] = "reverted"
        log_action(override_id, "auto_reverted", result)
    else:
        # Revert failed — escalate
        await escalate_revert_failure(override_id, device_id)

def cancel_revert_on_incident_resolve(incident_id: str):
    """Called when an incident is resolved.
       Immediately reverts all active overrides for that incident."""
    for override_id, override in active_overrides.items():
        if (override["incident_id"] == incident_id and
                override["status"] == "active"):
            asyncio.create_task(
                execute_revert(override_id,
                               override["device_id"],
                               override["revert_action"])
            )
```

---

## 8. Device Registry Schema

```sql
-- services schema

CREATE TABLE autonomous_devices (
    id VARCHAR(100) PRIMARY KEY,
    -- e.g. GATE-EKO-001, TL-LEKKI-042, ELEV-HOTEL-B
    org_id UUID NOT NULL,
    building_id VARCHAR(100),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    -- cctv / smart_gate / smart_door / smart_elevator /
    -- smart_escalator / traffic_light / smart_lock /
    -- intercom / smart_barrier / drone
    manufacturer VARCHAR(255),
    model VARCHAR(255),
    lat DECIMAL(10,8),
    lng DECIMAL(11,8),
    floor INTEGER,
    zone VARCHAR(100),
    area VARCHAR(255),
    connection_type VARCHAR(50) NOT NULL,
    -- REST_API / MQTT / HARDWARE_BRIDGE
    connection_config JSONB NOT NULL,
    -- Encrypted connection details:
    -- REST: {base_url, auth_type, credentials, action_paths}
    -- MQTT: {broker_url, topic_prefix, client_id, credentials}
    -- BRIDGE: {gateway_id, gateway_websocket_url, local_device_id, bridge_key}
    supported_actions JSONB DEFAULT '[]',
    -- List of action_keys this device supports
    status VARCHAR(50) DEFAULT 'online',
    -- online / offline / maintenance / unregistered
    last_seen TIMESTAMPTZ,
    last_command_at TIMESTAMPTZ,
    last_command_result VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE autonomous_actions_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(100) NOT NULL,
    org_id UUID NOT NULL,
    incident_id VARCHAR(100),
    action_key VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    requested_by VARCHAR(100),
    approved_by VARCHAR(100),
    approval_level VARCHAR(50),
    approval_timestamp TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    execution_result VARCHAR(50),
    -- success / failed / unconfirmed / timeout
    adapter_used VARCHAR(50),
    response_data JSONB,
    error_message TEXT,
    auto_revert_scheduled_at TIMESTAMPTZ,
    reverted_at TIMESTAMPTZ,
    revert_result VARCHAR(50),
    log_level VARCHAR(50),
    life_safety_risk BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE active_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(100) NOT NULL,
    org_id UUID NOT NULL,
    incident_id VARCHAR(100),
    action_key VARCHAR(100) NOT NULL,
    action_log_id UUID REFERENCES autonomous_actions_log(id),
    status VARCHAR(50) DEFAULT 'active',
    -- active / reverted / revert_failed / cancelled / expired
    started_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revert_action VARCHAR(100),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE hardware_bridges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255),
    gateway_key VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'offline',
    last_connected TIMESTAMPTZ,
    firmware_version VARCHAR(50),
    ip_address VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 9. Input & Output Contract

### 9.1 Input from Relationship API

```json
{
  "request_type": "execute_action",
  "request_id": "req_auto_001",
  "org_id": "org_abc123",
  "action": {
    "action_key": "elevator_hold",
    "device_id": "ELEV-EKO-002",
    "parameters": {
      "floor": 0,
      "duration_seconds": 300,
      "reason": "Officer dispatch to Floor 3 incident"
    }
  },
  "authorisation": {
    "approved_by": "user_supervisor_001",
    "approval_timestamp": "ISO8601",
    "approval_level": "supervisor",
    "incident_id": "INC-2024-001"
  }
}
```

### 9.2 Output to Relationship API

```json
{
  "request_id": "req_auto_001",
  "status": "success",
  "data": {
    "action_log_id": "uuid",
    "device_id": "ELEV-EKO-002",
    "device_name": "Main Elevator Block B",
    "action_key": "elevator_hold",
    "execution_result": "success",
    "adapter_used": "REST_API",
    "executed_at": "ISO8601",
    "confirmed": true,
    "auto_revert_scheduled": true,
    "revert_at": "ISO8601",
    "revert_action": "release",
    "warnings": [],
    "active_override_id": "uuid"
  }
}
```

---

## 10. API Endpoints

```
POST /execute              — Execute an autonomous action
POST /revert/:override_id  — Manually revert an active override
GET  /overrides/active     — List all active overrides for an org
GET  /devices              — List registered devices for an org
POST /devices              — Register a new device
PUT  /devices/:id          — Update device configuration
GET  /devices/:id/status   — Get real-time device status
GET  /log                  — Query action log (audit)
POST /incident/resolved    — Trigger auto-revert for resolved incident
GET  /health               — Service health + adapter connectivity
GET  /health/bridges       — Hardware bridge connection status
```

---

## 11. Tech Stack

```
Language:          Python 3.11+
Framework:         FastAPI
MQTT Broker:       EMQX (cloud-hosted, free tier available)
WebSocket:         websockets library (hardware bridge tunnels)
HTTP Client:       httpx (async REST adapter)
Scheduler:         APScheduler (auto-revert timers)
Database:          Supabase PostgreSQL (services schema)
Encryption:        cryptography library (device credentials at rest)
Hosting:           Render web service
Cost:              $7/month (Starter)

EMQX Free Tier:    1M session minutes/month
                   Sufficient for MVP with <50 devices
```

---

## 12. Environment Variables

```env
DATABASE_URL=
INTERNAL_API_KEY=
RELATIONSHIP_API_URL=
RELATIONSHIP_API_KEY=

# MQTT Broker
EMQX_BROKER_URL=
EMQX_USERNAME=
EMQX_PASSWORD=

# Encryption key for device credentials storage
DEVICE_CREDENTIALS_ENCRYPTION_KEY=

# Safety limits
MAX_TRAFFIC_PREEMPTION_SECONDS=600
MAX_LOCKDOWN_SECONDS=1800
MAX_ELEVATOR_HOLD_SECONDS=600
REVERT_RETRY_COUNT=3

ENVIRONMENT=production
PORT=8000
```

---

## 13. Build Checklist

Before pushing to Render:

- [ ] REST adapter tested with mock device endpoint
- [ ] MQTT adapter tested with EMQX sandbox broker
- [ ] Hardware bridge adapter tested with local Node-RED
- [ ] Constraint engine tested for every action type
- [ ] Approval validation tested for each role level
- [ ] Auto-revert timer tested end-to-end
- [ ] Revert failure escalation tested
- [ ] Network drop fail-safe tested (REST timeout)
- [ ] MQTT timeout and unconfirmed state tested
- [ ] Incident resolve triggers all override reverts
- [ ] Device registry CRUD tested
- [ ] Action log writing correctly for every execution
- [ ] Credential encryption verified at rest
- [ ] Life safety warnings surfaced on every
      applicable action
- [ ] Health endpoint shows all adapter connectivity
- [ ] Internal API key validation working

---

## 14. Security Requirements

This service controls physical infrastructure.
Security is not optional.

```
Device credentials:   AES-256 encrypted at rest
                      Never logged, never returned in API responses
                      Decrypted in memory only at execution time

Audit log:            Immutable — no DELETE or UPDATE on log table
                      Every action logged regardless of success/failure
                      Includes who approved, when, and from which IP

Network:              Service accepts connections only from
                      Relationship API IP address
                      Hardware bridge connections use
                      mutual TLS authentication

Credentials rotation: Device credentials rotatable without
                      service restart via PUT /devices/:id

Penetration testing:  Required before any government deployment
                      Recommended before first enterprise client
```

---

*Version 1.0 — Lemtik Security Engineering — Restricted*
*This service controls physical infrastructure in the real world.*
*Every line of code here has consequences beyond the screen.*
*Build carefully. Test exhaustively. Never rush a deployment.*