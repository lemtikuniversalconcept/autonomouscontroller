from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


APPROVAL_RANK = {
    None: 0,
    "supervisor": 1,
    "manager": 2,
}

AUTOMATION_MODE_NAMES = {
    0: "advisory_only",
    1: "human_approval",
    2: "policy_automation",
    3: "emergency_response",
}

AUTOMATION_MODE_DEFAULT = 1

MODE_2_AUTOMATED_ACTIONS = {
    "cctv_activate",
    "cctv_deactivate",
    "cctv_stream_to_dashboard",
    "cctv_snapshot",
    "cctv_ptz_move",
    "cctv_ptz_preset",
    "elevator_get_status",
    "gate_get_status",
    "door_get_status",
    "traffic_get_status",
    "barrier_get_status",
    "lock_get_status",
    "intercom_get_status",
    "siren_deactivate",
    "siren_get_status",
    "turnstile_get_status",
}

EMERGENCY_EXIT_LOCK_ACTIONS = {
    "gate_lock",
    "door_lock",
    "door_lock_all_local",
    "door_restrict_area",
    "door_restrict_floors",
    "lock_lock",
    "lock_lock_zone",
    "traffic_green_corridor",
    "traffic_single_preempt",
    "barrier_emergency_raise",
    "turnstile_lock",
    "turnstile_lockdown",
}

EMERGENCY_EXIT_TERMS = {
    "emergency exit",
    "emergency_exit",
    "exit route",
    "exit_route",
    "fire exit",
    "fire_exit",
    "evac route",
    "evac_route",
    "evacuation route",
    "evacuation_route",
}


ACTION_ALIASES = {
    "activate": "cctv_activate",
    "deactivate": "cctv_deactivate",
    "stream_to_dashboard": "cctv_stream_to_dashboard",
    "ptz_move": "cctv_ptz_move",
    "ptz_track": "cctv_ptz_track",
    "ptz_preset": "cctv_ptz_preset",
    "snapshot": "cctv_snapshot",
    "set_recording_quality": "cctv_set_recording_quality",
    "flag_footage": "cctv_flag_footage",
    "open": "gate_open",
    "close": "gate_close",
    "open_and_hold": "gate_open_and_hold",
    "lock": "gate_lock",
    "unlock": "gate_unlock",
    "emergency_open": "gate_emergency_open",
    "get_status": "gate_get_status",
    "unlock_door": "door_unlock",
    "lock_door": "door_lock",
    "lock_all_local": "door_lock_all_local",
    "grant_access_officer": "door_grant_access_officer",
    "restrict_area": "door_restrict_area",
    "hold_at_floor": "elevator_hold",
    "send_to_floor": "elevator_send_to_floor",
    "vip_mode": "elevator_vip_mode",
    "restrict_floors": "elevator_restrict_floors",
    "release": "elevator_release",
    "set_direction": "escalator_set_direction",
    "stop": "escalator_stop",
    "start": "escalator_start",
    "set_speed": "escalator_set_speed",
    "green_corridor": "traffic_green_corridor",
    "single_preempt": "traffic_single_preempt",
    "release_intersection": "traffic_release_intersection",
    "release_all": "traffic_release_all",
    "lock_zone": "lock_lock_zone",
    "unlock_zone": "lock_unlock_zone",
    "broadcast_message": "intercom_broadcast_message",
    "open_channel": "intercom_open_channel",
    "mute": "intercom_mute",
    "raise": "barrier_raise",
    "lower": "barrier_lower",
    "emergency_raise": "barrier_emergency_raise",
    "deploy": "drone_deploy",
    "return_to_base": "drone_return_to_base",
    "stream_feed": "drone_stream_feed",
    "set_waypoints": "drone_set_waypoints",
    "hover": "drone_hover",
    "land": "drone_land",
    "activate_siren": "siren_activate",
    "deactivate_siren": "siren_deactivate",
    "test_siren": "siren_test",
    "unlock_turnstile": "turnstile_unlock",
    "lock_turnstile": "turnstile_lock",
    "free_pass_turnstile": "turnstile_free_pass",
    "turnstile_lockdown": "turnstile_lockdown",
}

DEVICE_ACTION_ALIASES = {
    "smart_gate": {
        "open": "gate_open",
        "close": "gate_close",
        "lock": "gate_lock",
        "unlock": "gate_unlock",
        "emergency_open": "gate_emergency_open",
        "get_status": "gate_get_status",
    },
    "smart_door": {
        "unlock": "door_unlock",
        "lock": "door_lock",
        "lock_all_local": "door_lock_all_local",
        "grant_access_officer": "door_grant_access_officer",
        "restrict_area": "door_restrict_area",
        "get_status": "door_get_status",
    },
    "smart_elevator": {
        "hold_at_floor": "elevator_hold",
        "send_to_floor": "elevator_send_to_floor",
        "vip_mode": "elevator_vip_mode",
        "restrict_floors": "elevator_restrict_floors",
        "release": "elevator_release",
        "get_status": "elevator_get_status",
    },
    "traffic_light": {
        "green_corridor": "traffic_green_corridor",
        "single_preempt": "traffic_single_preempt",
        "release_intersection": "traffic_release_intersection",
        "release_all": "traffic_release_all",
        "get_status": "traffic_get_status",
    },
    "smart_barrier": {
        "raise": "barrier_raise",
        "lower": "barrier_lower",
        "emergency_raise": "barrier_emergency_raise",
        "get_status": "barrier_get_status",
    },
    "smart_lock": {
        "lock": "lock_lock",
        "unlock": "lock_unlock",
        "lock_zone": "lock_lock_zone",
        "unlock_zone": "lock_unlock_zone",
        "get_status": "lock_get_status",
    },
    "drone": {
        "deploy": "drone_deploy",
        "return_to_base": "drone_return_to_base",
        "stream_feed": "drone_stream_feed",
        "set_waypoints": "drone_set_waypoints",
        "hover": "drone_hover",
        "land": "drone_land",
    },
    "smart_siren": {
        "activate": "siren_activate",
        "deactivate": "siren_deactivate",
        "test": "siren_test",
        "get_status": "siren_get_status",
    },
    "turnstile": {
        "unlock": "turnstile_unlock",
        "lock": "turnstile_lock",
        "free_pass": "turnstile_free_pass",
        "lockdown": "turnstile_lockdown",
        "get_status": "turnstile_get_status",
    },
}


CONSTRAINT_RULES: dict[str, dict[str, Any]] = {
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
        "life_safety_note": "Restricts floor access - verify no medical emergency on restricted floors.",
    },
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
    "door_lock": {
        "approval_level": "supervisor",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 120,
        "auto_revert": True,
        "revert_action": "unlock",
        "risk_level": "medium",
        "log_level": "high",
        "life_safety_risk": False,
    },
    "door_lock_all_local": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 1800,
        "auto_revert": True,
        "revert_action": "unlock",
        "risk_level": "critical",
        "log_level": "critical",
        "life_safety_risk": True,
        "life_safety_note": "Locks people inside zone - fire exits must remain operational.",
    },
    "door_restrict_area": {
        "approval_level": "manager",
        "auto_execute": False,
        "requires_active_incident": True,
        "max_duration_seconds": 1800,
        "auto_revert": True,
        "revert_action": "unlock",
        "risk_level": "critical",
        "log_level": "critical",
        "life_safety_risk": True,
    },
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
        "life_safety_note": "Prevents exit - verify emergency vehicle access maintained.",
    },
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
        "life_safety_note": "Affects public road safety - ensure route is clear before preemption.",
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


CONSTRAINT_RULES.update(
    {
        "cctv_deactivate": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 3600,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "cctv_stream_to_dashboard": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 3600,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "cctv_ptz_move": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "cctv_ptz_preset": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "cctv_snapshot": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "cctv_set_recording_quality": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "cctv_flag_footage": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 3600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "gate_close": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "gate_unlock": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "gate_emergency_open": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "critical",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "gate_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "door_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "door_grant_access_officer": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "elevator_send_to_floor": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "elevator_release": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "elevator_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "escalator_set_direction": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "escalator_stop": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "high",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "escalator_start": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "escalator_set_speed": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "escalator_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "traffic_release_intersection": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "traffic_release_all": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "traffic_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "lock_lock": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "lock_unlock": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "lock_lock_zone": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "critical",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "lock_unlock_zone": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "critical",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "lock_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "intercom_broadcast_message": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 300,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "intercom_open_channel": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "intercom_mute": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "intercom_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "barrier_lower": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "barrier_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "drone_return_to_base": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "drone_stream_feed": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "drone_set_waypoints": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "high",
            "log_level": "critical",
            "life_safety_risk": False,
        },
        "drone_hover": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 600,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "drone_land": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "siren_activate": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "critical",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "siren_deactivate": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 1800,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "siren_test": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": False,
            "max_duration_seconds": 120,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "siren_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
        "turnstile_unlock": {
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
        "turnstile_lock": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": True,
            "revert_action": "unlock",
            "risk_level": "high",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "turnstile_free_pass": {
            "approval_level": "supervisor",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": False,
            "risk_level": "medium",
            "log_level": "high",
            "life_safety_risk": False,
        },
        "turnstile_lockdown": {
            "approval_level": "manager",
            "auto_execute": False,
            "requires_active_incident": True,
            "max_duration_seconds": 120,
            "auto_revert": True,
            "revert_action": "unlock",
            "risk_level": "critical",
            "log_level": "critical",
            "life_safety_risk": True,
        },
        "turnstile_get_status": {
            "approval_level": None,
            "auto_execute": True,
            "requires_active_incident": False,
            "max_duration_seconds": 30,
            "auto_revert": False,
            "risk_level": "low",
            "log_level": "standard",
            "life_safety_risk": False,
        },
    }
)


def normalize_action_key(action_key: str) -> str:
    return ACTION_ALIASES.get(action_key, action_key)


def resolve_action_key(device_type: str | None, action_key: str) -> str:
    if action_key in CONSTRAINT_RULES:
        return action_key
    if device_type and action_key in DEVICE_ACTION_ALIASES.get(device_type, {}):
        return DEVICE_ACTION_ALIASES[device_type][action_key]
    return normalize_action_key(action_key)


def requestor_has_role(requestor_role: str | None, required_role: str | None) -> bool:
    if required_role is None:
        return True
    return APPROVAL_RANK.get(requestor_role, 0) >= APPROVAL_RANK.get(required_role, 0)


def normalize_automation_mode(value: Any) -> int:
    try:
        mode = int(value)
    except (TypeError, ValueError):
        return AUTOMATION_MODE_DEFAULT
    return mode if mode in AUTOMATION_MODE_NAMES else AUTOMATION_MODE_DEFAULT


def resolve_automation_mode(request: dict[str, Any]) -> int:
    manifest = request.get("manifest") or {}
    constraints = request.get("constraints") or {}
    auth = request.get("authorisation") or {}
    if "automation_mode" in request and request.get("automation_mode") is not None:
        return normalize_automation_mode(request.get("automation_mode"))
    if "automation_mode" in manifest and manifest.get("automation_mode") is not None:
        return normalize_automation_mode(manifest.get("automation_mode"))
    if "automation_mode" in constraints and constraints.get("automation_mode") is not None:
        return normalize_automation_mode(constraints.get("automation_mode"))
    if "automation_mode" in auth and auth.get("automation_mode") is not None:
        return normalize_automation_mode(auth.get("automation_mode"))
    return AUTOMATION_MODE_DEFAULT


def canonical_signature_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_signature(payload: dict[str, Any], signature: str | None, secret: str | None) -> bool:
    if not signature or not secret:
        return False
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_signature_payload(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(digest, signature)


def safety_override_reason(action_key: str, device: dict[str, Any], parameters: dict[str, Any]) -> str | None:
    route_bits = parameters.get("route_ids")
    route_text = " ".join(route_bits) if isinstance(route_bits, list) else ""
    parts = [
        action_key,
        str(device.get("id", "")),
        str(device.get("type", "")),
        str(parameters.get("reason", "")),
        str(parameters.get("zone", "")),
        str(parameters.get("area", "")),
        str(parameters.get("target_route", "")),
        str(parameters.get("route", "")),
        str(parameters.get("route_name", "")),
        route_text,
    ]
    haystack = " ".join(part.lower() for part in parts if part)
    if action_key in EMERGENCY_EXIT_LOCK_ACTIONS:
        for term in EMERGENCY_EXIT_TERMS:
            if term in haystack:
                return f"Safety override: {action_key} cannot be applied to emergency exit or evacuation routes."
    if ("emergency exit" in haystack or "evacuation route" in haystack) and action_key in {
        "gate_lock",
        "door_lock",
        "door_lock_all_local",
        "door_restrict_area",
        "lock_lock",
        "lock_lock_zone",
        "turnstile_lock",
        "turnstile_lockdown",
    }:
        return "Safety override: locking an emergency exit route is prohibited."
    return None


def validate_command(
    action_key: str,
    device: dict[str, Any],
    requestor: dict[str, Any],
    incident_id: str | None,
    approved_by: str | None,
    bypass_approval: bool = False,
) -> dict[str, Any]:
    constraint = CONSTRAINT_RULES.get(action_key)
    if not constraint:
        return {
            "valid": False,
            "reason": f"Unknown action: {action_key}. Action not in constraint registry.",
        }

    if constraint["requires_active_incident"] and not incident_id:
        return {
            "valid": False,
            "reason": "No active incident linked. All autonomous actions require an active incident ID.",
        }

    approval_level = constraint["approval_level"]
    if not constraint["auto_execute"] and not bypass_approval:
        if not approved_by:
            return {
                "valid": False,
                "reason": f"Approval required from: {approval_level}",
                "approval_required": True,
                "approval_level": approval_level,
                "pending": True,
            }
        approver_level = requestor.get("approval_level")
        if not requestor_has_role(approver_level, approval_level):
            return {
                "valid": False,
                "reason": f"Approver does not have required role: {approval_level}",
            }

    warnings: list[dict[str, Any]] = []
    if constraint["life_safety_risk"]:
        warnings.append(
            {
                "type": "life_safety",
                "message": constraint.get(
                    "life_safety_note",
                    "This action has life-safety implications. Verify safety conditions before executing.",
                ),
            }
        )

    return {
        "valid": True,
        "constraint": constraint,
        "warnings": warnings,
        "max_duration_seconds": constraint["max_duration_seconds"],
        "auto_revert": constraint["auto_revert"],
        "revert_action": constraint.get("revert_action"),
        "log_level": constraint["log_level"],
    }
