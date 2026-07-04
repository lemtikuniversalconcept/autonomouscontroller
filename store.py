from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import psycopg
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    psycopg = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def _json_loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _resolve_sqlite_path(database_url: str | None) -> Path | None:
    if not database_url:
        return None
    if database_url.startswith("sqlite:///"):
        return Path(database_url.removeprefix("sqlite:///"))
    if database_url.startswith("sqlite://"):
        return Path(database_url.removeprefix("sqlite://"))
    if database_url.endswith(".sqlite") or database_url.endswith(".db"):
        return Path(database_url)
    return None


def _is_postgres_url(database_url: str | None) -> bool:
    return bool(database_url and database_url.startswith("postgres"))


class AdaptiveStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.override_tasks: dict[str, asyncio.Task] = {}
        self.adapter_status: dict[str, dict[str, Any]] = {
            "REST_API": {"status": "unknown"},
            "MQTT": {"status": "unknown"},
            "HARDWARE_BRIDGE": {"status": "unknown"},
        }
        self.hardware_bridges: dict[str, dict[str, Any]] = {}
        self.bridge_command_queue: list[dict[str, Any]] = []
        self.devices: dict[str, dict[str, Any]] = {}
        self.actions: list[dict[str, Any]] = []
        self.overrides: dict[str, dict[str, Any]] = {}
        database_url = os.getenv("DATABASE_URL")
        self._sqlite_path = _resolve_sqlite_path(database_url)
        self._postgres_url = database_url if _is_postgres_url(database_url) else None
        self._conn: sqlite3.Connection | None = None
        self._pg_conn: Any | None = None
        if self._sqlite_path:
            self._init_sqlite()
        elif self._postgres_url:
            self._init_postgres()
        self._load_state()

    def _init_sqlite(self) -> None:
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS autonomous_devices (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                building_id TEXT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                manufacturer TEXT,
                model TEXT,
                lat REAL,
                lng REAL,
                floor INTEGER,
                zone TEXT,
                area TEXT,
                connection_type TEXT NOT NULL,
                connection_config TEXT NOT NULL,
                connection_config_encrypted TEXT,
                supported_actions TEXT DEFAULT '[]',
                status TEXT DEFAULT 'online',
                last_seen TEXT,
                last_command_at TEXT,
                last_command_result TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS autonomous_actions_log (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                incident_id TEXT,
                action_key TEXT NOT NULL,
                parameters TEXT DEFAULT '{}',
                requested_by TEXT,
                requested_from_ip TEXT,
                approved_by TEXT,
                approval_level TEXT,
                approval_timestamp TEXT,
                executed_at TEXT,
                execution_result TEXT,
                adapter_used TEXT,
                response_data TEXT,
                error_message TEXT,
                auto_revert_scheduled_at TEXT,
                reverted_at TEXT,
                revert_result TEXT,
                log_level TEXT,
                life_safety_risk INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS active_overrides (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                incident_id TEXT,
                action_key TEXT NOT NULL,
                action_log_id TEXT,
                status TEXT DEFAULT 'active',
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                revert_action TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                auto_revert INTEGER DEFAULT 0
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hardware_bridges (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT,
                gateway_key TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'offline',
                last_connected TEXT,
                firmware_version TEXT,
                ip_address TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._conn.commit()

    def _init_postgres(self) -> None:
        if psycopg is None:
            raise RuntimeError("psycopg is required for PostgreSQL DATABASE_URL values.")
        self._pg_conn = psycopg.connect(self._postgres_url)
        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS autonomous_devices (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    building_id TEXT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    manufacturer TEXT,
                    model TEXT,
                    lat DOUBLE PRECISION,
                    lng DOUBLE PRECISION,
                    floor INTEGER,
                    zone TEXT,
                    area TEXT,
                    connection_type TEXT NOT NULL,
                    connection_config TEXT NOT NULL,
                    connection_config_encrypted TEXT,
                    supported_actions TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'online',
                    last_seen TEXT,
                    last_command_at TEXT,
                    last_command_result TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS autonomous_actions_log (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    incident_id TEXT,
                    action_key TEXT NOT NULL,
                    parameters TEXT DEFAULT '{}',
                    requested_by TEXT,
                    requested_from_ip TEXT,
                    approved_by TEXT,
                    approval_level TEXT,
                    approval_timestamp TEXT,
                    executed_at TEXT,
                    execution_result TEXT,
                    adapter_used TEXT,
                    response_data TEXT,
                    error_message TEXT,
                    auto_revert_scheduled_at TEXT,
                    reverted_at TEXT,
                    revert_result TEXT,
                    log_level TEXT,
                    life_safety_risk INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS active_overrides (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    incident_id TEXT,
                    action_key TEXT NOT NULL,
                    action_log_id TEXT,
                    status TEXT DEFAULT 'active',
                    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT NOT NULL,
                    revert_action TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    auto_revert INTEGER DEFAULT 0
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS hardware_bridges (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    location TEXT,
                    gateway_key TEXT UNIQUE NOT NULL,
                    status TEXT DEFAULT 'offline',
                    last_connected TEXT,
                    firmware_version TEXT,
                    ip_address TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        self._pg_conn.commit()

    def _load_state(self) -> None:
        self.devices = {}
        self.actions = []
        self.overrides = {}
        if self._conn:
            for row in self._conn.execute("SELECT * FROM autonomous_devices"):
                record = dict(row)
                record["connection_config"] = _json_loads(record["connection_config"], {})
                record["supported_actions"] = _json_loads(record["supported_actions"], [])
                self.devices[record["id"]] = record
            for row in self._conn.execute("SELECT * FROM autonomous_actions_log ORDER BY created_at ASC"):
                record = dict(row)
                record["parameters"] = _json_loads(record["parameters"], {})
                record["response_data"] = _json_loads(record["response_data"], {})
                record["life_safety_risk"] = bool(record.get("life_safety_risk"))
                self.actions.append(record)
            for row in self._conn.execute("SELECT * FROM active_overrides"):
                record = dict(row)
                record["auto_revert"] = bool(record.get("auto_revert"))
                self.overrides[record["id"]] = record
            for row in self._conn.execute("SELECT * FROM hardware_bridges"):
                self.hardware_bridges[row["id"]] = dict(row)
        elif self._pg_conn:
            with self._pg_conn.cursor() as cur:
                cur.execute("SELECT * FROM autonomous_devices")
                for row in cur.fetchall():
                    record = dict(row)
                    record["connection_config"] = _json_loads(record["connection_config"], {})
                    record["supported_actions"] = _json_loads(record["supported_actions"], [])
                    self.devices[record["id"]] = record
                cur.execute("SELECT * FROM autonomous_actions_log ORDER BY created_at ASC")
                for row in cur.fetchall():
                    record = dict(row)
                    record["parameters"] = _json_loads(record["parameters"], {})
                    record["response_data"] = _json_loads(record["response_data"], {})
                    record["life_safety_risk"] = bool(record.get("life_safety_risk"))
                    self.actions.append(record)
                cur.execute("SELECT * FROM active_overrides")
                for row in cur.fetchall():
                    record = dict(row)
                    record["auto_revert"] = bool(record.get("auto_revert"))
                    self.overrides[record["id"]] = record
                cur.execute("SELECT * FROM hardware_bridges")
                for row in cur.fetchall():
                    self.hardware_bridges[row["id"]] = dict(row)

    async def upsert_device(self, device: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            record = {
                **device,
                "updated_at": now_iso(),
                "created_at": device.get("created_at", now_iso()),
                "last_seen": device.get("last_seen"),
                "last_command_at": device.get("last_command_at"),
                "last_command_result": device.get("last_command_result"),
                "status": device.get("status", "online"),
            }
            self.devices[record["id"]] = record
            if self._conn:
                self._conn.execute(
                    """
                    INSERT INTO autonomous_devices (
                        id, org_id, building_id, name, type, manufacturer, model, lat, lng,
                        floor, zone, area, connection_type, connection_config,
                        connection_config_encrypted, supported_actions, status, last_seen,
                        last_command_at, last_command_result, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        org_id=excluded.org_id,
                        building_id=excluded.building_id,
                        name=excluded.name,
                        type=excluded.type,
                        manufacturer=excluded.manufacturer,
                        model=excluded.model,
                        lat=excluded.lat,
                        lng=excluded.lng,
                        floor=excluded.floor,
                        zone=excluded.zone,
                        area=excluded.area,
                        connection_type=excluded.connection_type,
                        connection_config=excluded.connection_config,
                        connection_config_encrypted=excluded.connection_config_encrypted,
                        supported_actions=excluded.supported_actions,
                        status=excluded.status,
                        last_seen=excluded.last_seen,
                        last_command_at=excluded.last_command_at,
                        last_command_result=excluded.last_command_result,
                        updated_at=excluded.updated_at
                    """,
                    (
                        record.get("id"),
                        record.get("org_id"),
                        record.get("building_id"),
                        record.get("name"),
                        record.get("type"),
                        record.get("manufacturer"),
                        record.get("model"),
                        record.get("lat"),
                        record.get("lng"),
                        record.get("floor"),
                        record.get("zone"),
                        record.get("area"),
                        record.get("connection_type"),
                        _json_dumps(record.get("connection_config", {})),
                        record.get("connection_config_encrypted"),
                        _json_dumps(record.get("supported_actions", [])),
                        record.get("status"),
                        record.get("last_seen"),
                        record.get("last_command_at"),
                        record.get("last_command_result"),
                        record.get("created_at"),
                        record.get("updated_at"),
                    ),
                )
                self._conn.commit()
            elif self._pg_conn:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO autonomous_devices (
                            id, org_id, building_id, name, type, manufacturer, model, lat, lng,
                            floor, zone, area, connection_type, connection_config,
                            connection_config_encrypted, supported_actions, status, last_seen,
                            last_command_at, last_command_result, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            org_id = EXCLUDED.org_id,
                            building_id = EXCLUDED.building_id,
                            name = EXCLUDED.name,
                            type = EXCLUDED.type,
                            manufacturer = EXCLUDED.manufacturer,
                            model = EXCLUDED.model,
                            lat = EXCLUDED.lat,
                            lng = EXCLUDED.lng,
                            floor = EXCLUDED.floor,
                            zone = EXCLUDED.zone,
                            area = EXCLUDED.area,
                            connection_type = EXCLUDED.connection_type,
                            connection_config = EXCLUDED.connection_config,
                            connection_config_encrypted = EXCLUDED.connection_config_encrypted,
                            supported_actions = EXCLUDED.supported_actions,
                            status = EXCLUDED.status,
                            last_seen = EXCLUDED.last_seen,
                            last_command_at = EXCLUDED.last_command_at,
                            last_command_result = EXCLUDED.last_command_result,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (
                            record.get("id"),
                            record.get("org_id"),
                            record.get("building_id"),
                            record.get("name"),
                            record.get("type"),
                            record.get("manufacturer"),
                            record.get("model"),
                            record.get("lat"),
                            record.get("lng"),
                            record.get("floor"),
                            record.get("zone"),
                            record.get("area"),
                            record.get("connection_type"),
                            _json_dumps(record.get("connection_config", {})),
                            record.get("connection_config_encrypted"),
                            _json_dumps(record.get("supported_actions", [])),
                            record.get("status"),
                            record.get("last_seen"),
                            record.get("last_command_at"),
                            record.get("last_command_result"),
                            record.get("created_at"),
                            record.get("updated_at"),
                        ),
                    )
                self._pg_conn.commit()
            return record

    async def get_device(self, device_id: str) -> dict[str, Any] | None:
        async with self._lock:
            return self.devices.get(device_id)

    async def list_devices(self) -> list[dict[str, Any]]:
        async with self._lock:
            return list(self.devices.values())

    async def append_action(self, entry: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            self.actions.append(entry)
            if self._conn:
                self._conn.execute(
                    """
                    INSERT INTO autonomous_actions_log (
                        id, device_id, org_id, incident_id, action_key, parameters, requested_by,
                        requested_from_ip, approved_by, approval_level, approval_timestamp,
                        executed_at, execution_result, adapter_used, response_data, error_message,
                        auto_revert_scheduled_at, reverted_at, revert_result, log_level,
                        life_safety_risk, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.get("id"),
                        entry.get("device_id"),
                        entry.get("org_id"),
                        entry.get("incident_id"),
                        entry.get("action_key"),
                        _json_dumps(entry.get("parameters", {})),
                        entry.get("requested_by"),
                        entry.get("requested_from_ip"),
                        entry.get("approved_by"),
                        entry.get("approval_level"),
                        entry.get("approval_timestamp"),
                        entry.get("executed_at"),
                        entry.get("execution_result"),
                        entry.get("adapter_used"),
                        _json_dumps(entry.get("response_data", {})),
                        entry.get("error_message"),
                        entry.get("auto_revert_scheduled_at"),
                        entry.get("reverted_at"),
                        entry.get("revert_result"),
                        entry.get("log_level"),
                        int(bool(entry.get("life_safety_risk"))),
                        entry.get("created_at"),
                    ),
                )
                self._conn.commit()
            elif self._pg_conn:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO autonomous_actions_log (
                            id, device_id, org_id, incident_id, action_key, parameters, requested_by,
                            requested_from_ip, approved_by, approval_level, approval_timestamp,
                            executed_at, execution_result, adapter_used, response_data, error_message,
                            auto_revert_scheduled_at, reverted_at, revert_result, log_level,
                            life_safety_risk, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            entry.get("id"),
                            entry.get("device_id"),
                            entry.get("org_id"),
                            entry.get("incident_id"),
                            entry.get("action_key"),
                            _json_dumps(entry.get("parameters", {})),
                            entry.get("requested_by"),
                            entry.get("requested_from_ip"),
                            entry.get("approved_by"),
                            entry.get("approval_level"),
                            entry.get("approval_timestamp"),
                            entry.get("executed_at"),
                            entry.get("execution_result"),
                            entry.get("adapter_used"),
                            _json_dumps(entry.get("response_data", {})),
                            entry.get("error_message"),
                            entry.get("auto_revert_scheduled_at"),
                            entry.get("reverted_at"),
                            entry.get("revert_result"),
                            entry.get("log_level"),
                            int(bool(entry.get("life_safety_risk"))),
                            entry.get("created_at"),
                        ),
                    )
                self._pg_conn.commit()
            return entry

    async def update_action_log(self, action_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self._lock:
            for entry in self.actions:
                if entry.get("id") == action_id:
                    entry.update(changes)
                    if self._conn:
                        self._conn.execute(
                            """
                            UPDATE autonomous_actions_log
                            SET auto_revert_scheduled_at = COALESCE(?, auto_revert_scheduled_at),
                                reverted_at = COALESCE(?, reverted_at),
                                revert_result = COALESCE(?, revert_result),
                                response_data = COALESCE(?, response_data)
                            WHERE id = ?
                            """,
                            (
                                changes.get("auto_revert_scheduled_at"),
                                changes.get("reverted_at"),
                                changes.get("revert_result"),
                                _json_dumps(changes["response_data"]) if "response_data" in changes else None,
                                action_id,
                            ),
                        )
                        self._conn.commit()
                    elif self._pg_conn:
                        with self._pg_conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE autonomous_actions_log
                                SET auto_revert_scheduled_at = COALESCE(%s, auto_revert_scheduled_at),
                                    reverted_at = COALESCE(%s, reverted_at),
                                    revert_result = COALESCE(%s, revert_result),
                                    response_data = COALESCE(%s, response_data)
                                WHERE id = %s
                                """,
                                (
                                    changes.get("auto_revert_scheduled_at"),
                                    changes.get("reverted_at"),
                                    changes.get("revert_result"),
                                    _json_dumps(changes["response_data"]) if "response_data" in changes else None,
                                    action_id,
                                ),
                            )
                        self._pg_conn.commit()
                    return entry
            return None

    async def list_actions(self) -> list[dict[str, Any]]:
        async with self._lock:
            return list(self.actions)

    async def create_override(self, override: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            self.overrides[override["id"]] = override
            if self._conn:
                self._conn.execute(
                    """
                    INSERT INTO active_overrides (
                        id, device_id, org_id, incident_id, action_key, action_log_id,
                        status, started_at, expires_at, revert_action, updated_at, auto_revert
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        override.get("id"),
                        override.get("device_id"),
                        override.get("org_id"),
                        override.get("incident_id"),
                        override.get("action_key"),
                        override.get("action_log_id"),
                        override.get("status", "active"),
                        override.get("started_at", now_iso()),
                        override.get("expires_at"),
                        override.get("revert_action"),
                        override.get("updated_at", now_iso()),
                        int(bool(override.get("auto_revert"))),
                    ),
                )
                self._conn.commit()
            elif self._pg_conn:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO active_overrides (
                            id, device_id, org_id, incident_id, action_key, action_log_id,
                            status, started_at, expires_at, revert_action, updated_at, auto_revert
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            override.get("id"),
                            override.get("device_id"),
                            override.get("org_id"),
                            override.get("incident_id"),
                            override.get("action_key"),
                            override.get("action_log_id"),
                            override.get("status", "active"),
                            override.get("started_at", now_iso()),
                            override.get("expires_at"),
                            override.get("revert_action"),
                            override.get("updated_at", now_iso()),
                            int(bool(override.get("auto_revert"))),
                        ),
                    )
                self._pg_conn.commit()
            return override

    async def get_override(self, override_id: str) -> dict[str, Any] | None:
        async with self._lock:
            return self.overrides.get(override_id)

    async def update_override(self, override_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self._lock:
            if override_id not in self.overrides:
                return None
            self.overrides[override_id].update(changes)
            self.overrides[override_id]["updated_at"] = now_iso()
            if self._conn:
                sets = []
                values: list[Any] = []
                for key, value in changes.items():
                    sets.append(f"{key} = ?")
                    values.append(value)
                sets.append("updated_at = ?")
                values.append(self.overrides[override_id]["updated_at"])
                values.append(override_id)
                self._conn.execute(
                    f"UPDATE active_overrides SET {', '.join(sets)} WHERE id = ?",
                    values,
                )
                self._conn.commit()
            elif self._pg_conn:
                sets = []
                values = []
                for key, value in changes.items():
                    sets.append(f"{key} = %s")
                    values.append(value)
                sets.append("updated_at = %s")
                values.append(self.overrides[override_id]["updated_at"])
                values.append(override_id)
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        f"UPDATE active_overrides SET {', '.join(sets)} WHERE id = %s",
                        values,
                    )
                self._pg_conn.commit()
            return self.overrides[override_id]

    async def list_active_overrides(self, org_id: str | None = None) -> list[dict[str, Any]]:
        async with self._lock:
            overrides = [
                override
                for override in self.overrides.values()
                if override.get("status") in {"active", "unconfirmed"}
            ]
            if org_id:
                overrides = [override for override in overrides if override.get("org_id") == org_id]
            return overrides

    async def list_overrides_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                override
                for override in self.overrides.values()
                if override.get("incident_id") == incident_id and override.get("status") == "active"
            ]

    async def set_adapter_status(self, adapter_name: str, status: str, detail: dict[str, Any] | None = None) -> None:
        async with self._lock:
            self.adapter_status[adapter_name] = {
                "status": status,
                "detail": detail or {},
                "updated_at": now_iso(),
            }

    async def upsert_hardware_bridge(self, bridge: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            record = {
                **bridge,
                "created_at": bridge.get("created_at", now_iso()),
            }
            self.hardware_bridges[record["id"]] = record
            if self._conn:
                self._conn.execute(
                    """
                    INSERT INTO hardware_bridges (
                        id, org_id, name, location, gateway_key, status,
                        last_connected, firmware_version, ip_address, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        org_id=excluded.org_id,
                        name=excluded.name,
                        location=excluded.location,
                        gateway_key=excluded.gateway_key,
                        status=excluded.status,
                        last_connected=excluded.last_connected,
                        firmware_version=excluded.firmware_version,
                        ip_address=excluded.ip_address
                    """,
                    (
                        record.get("id"),
                        record.get("org_id"),
                        record.get("name"),
                        record.get("location"),
                        record.get("gateway_key"),
                        record.get("status"),
                        record.get("last_connected"),
                        record.get("firmware_version"),
                        record.get("ip_address"),
                        record.get("created_at"),
                    ),
                )
                self._conn.commit()
            elif self._pg_conn:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO hardware_bridges (
                            id, org_id, name, location, gateway_key, status,
                            last_connected, firmware_version, ip_address, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT(id) DO UPDATE SET
                            org_id=EXCLUDED.org_id,
                            name=EXCLUDED.name,
                            location=EXCLUDED.location,
                            gateway_key=EXCLUDED.gateway_key,
                            status=EXCLUDED.status,
                            last_connected=EXCLUDED.last_connected,
                            firmware_version=EXCLUDED.firmware_version,
                            ip_address=EXCLUDED.ip_address
                        """,
                        (
                            record.get("id"),
                            record.get("org_id"),
                            record.get("name"),
                            record.get("location"),
                            record.get("gateway_key"),
                            record.get("status"),
                            record.get("last_connected"),
                            record.get("firmware_version"),
                            record.get("ip_address"),
                            record.get("created_at"),
                        ),
                    )
                self._pg_conn.commit()
            return record

    async def list_hardware_bridges(self) -> list[dict[str, Any]]:
        async with self._lock:
            return list(self.hardware_bridges.values())

    async def queue_bridge_command(self, command: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            if "id" not in command:
                command = {**command, "id": f"bridge-{len(self.bridge_command_queue) + 1}-{int(datetime.now(timezone.utc).timestamp())}"}
            self.bridge_command_queue.append(command)
            return command

    async def list_bridge_queue(self) -> list[dict[str, Any]]:
        async with self._lock:
            return list(self.bridge_command_queue)

    async def remove_bridge_command(self, command_id: str) -> None:
        async with self._lock:
            self.bridge_command_queue = [command for command in self.bridge_command_queue if command.get("id") != command_id]

    async def prune_expired_bridge_commands(self) -> list[dict[str, Any]]:
        async with self._lock:
            now = datetime.now(timezone.utc)
            remaining: list[dict[str, Any]] = []
            expired: list[dict[str, Any]] = []
            for command in self.bridge_command_queue:
                expires_at = parse_iso(command.get("expires_at"))
                if expires_at and expires_at <= now:
                    command["status"] = "expired"
                    expired.append(command)
                else:
                    remaining.append(command)
            self.bridge_command_queue = remaining
            return expired


STORE = AdaptiveStore()
