from __future__ import annotations

import math

EARTH_RADIUS_METRES = 6_371_000.0

COMPASS_POINTS = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]


def haversine_metres(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_METRES * math.asin(min(1.0, math.sqrt(a)))


def bearing_degrees(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Compass bearing in degrees (0=North, 90=East, ...) from point 1 to point 2."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dlambda = math.radians(lng2 - lng1)
    x = math.sin(dlambda) * math.cos(phi2)
    y = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(dlambda)
    return (math.degrees(math.atan2(x, y)) + 360) % 360


def compass_point(bearing: float) -> str:
    index = round(bearing / 45) % 8
    return COMPASS_POINTS[index]
