"""GeoIP-based satellite selection for TCP tunnel routing.

When a CLI client requests a tunnel, the API selects the nearest satellite
to minimize latency. Selection priority:
  1. Resource has ``satellite`` pinned → use that satellite (no GeoIP needed)
  2. GeoIP lookup on client source IP → nearest satellite by haversine distance
  3. Fallback → configured default satellite

MaxMind GeoLite2-City database is optional. When absent, GeoIP lookups
return None and the fallback chain continues to step 3.

Install the database:
  Download GeoLite2-City.mmdb from MaxMind and place at the path
  configured in ``settings.geoip_database_path`` (default:
  ``/usr/share/GeoIP/GeoLite2-City.mmdb``).
"""

from __future__ import annotations

import math
from ipaddress import ip_address

from bamf.logging_config import get_logger

logger = get_logger(__name__)

# Lazy-loaded MaxMind reader state.  Using a dict avoids ``global`` and lets
# us distinguish "not yet attempted" (key absent) from "unavailable" (None).
_geoip_state: dict[str, object] = {}


def _get_reader():
    """Return a geoip2 DatabaseReader, or None if unavailable."""
    if "reader" in _geoip_state:
        return _geoip_state["reader"]

    try:
        import geoip2.database  # type: ignore[import-untyped]

        from bamf.config import settings

        path = settings.geoip_database_path
        reader = geoip2.database.Reader(path)
        logger.info("GeoIP database loaded", path=path)
        _geoip_state["reader"] = reader
        return reader
    except Exception:  # noqa: BLE001 — graceful fallback when geoip2/database missing
        _geoip_state["reader"] = None
        logger.debug("GeoIP database not available — satellite selection will use defaults")
        return None


def geoip_lookup(source_ip: str) -> tuple[float, float] | None:
    """Look up latitude/longitude for an IP address.

    Returns (latitude, longitude) or None if lookup fails.
    Private/reserved IPs always return None.
    """
    try:
        addr = ip_address(source_ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            return None
    except ValueError:
        return None

    reader = _get_reader()
    if reader is None:
        return None

    try:
        response = reader.city(source_ip)
        if response.location.latitude is not None and response.location.longitude is not None:
            return (response.location.latitude, response.location.longitude)
    except Exception:  # noqa: BLE001 — IP may not exist in database
        return None

    return None


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance in km between two points.

    Uses the haversine formula. Earth radius = 6371 km.
    """
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


async def select_nearest_satellite(
    source_ip: str,
    satellites: list[dict],
) -> str | None:
    """Select the nearest satellite to a client IP.

    Args:
        source_ip: Client's source IP address.
        satellites: List of dicts with keys: name, latitude, longitude.

    Returns:
        Satellite name, or None if GeoIP lookup fails or no satellites
        have coordinates.
    """
    client_coords = geoip_lookup(source_ip)
    if client_coords is None:
        return None

    client_lat, client_lon = client_coords

    best_name = None
    best_distance = float("inf")

    for sat in satellites:
        lat = sat.get("latitude")
        lon = sat.get("longitude")
        if lat is None or lon is None:
            continue
        dist = haversine_distance(client_lat, client_lon, lat, lon)
        if dist < best_distance:
            best_distance = dist
            best_name = sat["name"]

    if best_name:
        logger.debug(
            "GeoIP satellite selected",
            source_ip=source_ip,
            satellite=best_name,
            distance_km=round(best_distance, 1),
        )

    return best_name
