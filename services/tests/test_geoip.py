"""Tests for GeoIP-based satellite selection.

Tests the haversine distance calculation, IP address classification,
and nearest-satellite selection logic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from bamf.services.geoip import (
    geoip_lookup,
    haversine_distance,
    select_nearest_satellite,
)


# ── haversine_distance ───────────────────────────────────────────────────


class TestHaversineDistance:
    def test_same_point_is_zero(self):
        assert haversine_distance(51.5, -0.1, 51.5, -0.1) == 0.0

    def test_london_to_dublin(self):
        # London (51.5074, -0.1278) to Dublin (53.3498, -6.2603)
        dist = haversine_distance(51.5074, -0.1278, 53.3498, -6.2603)
        # ~464 km
        assert 450 < dist < 480

    def test_new_york_to_los_angeles(self):
        # NYC (40.7128, -74.0060) to LA (34.0522, -118.2437)
        dist = haversine_distance(40.7128, -74.0060, 34.0522, -118.2437)
        # ~3944 km
        assert 3900 < dist < 4000

    def test_antipodal_points(self):
        # Opposite sides of the earth — should be ~20015 km (half circumference)
        dist = haversine_distance(0.0, 0.0, 0.0, 180.0)
        assert 20000 < dist < 20100

    def test_symmetry(self):
        d1 = haversine_distance(51.5, -0.1, 53.3, -6.2)
        d2 = haversine_distance(53.3, -6.2, 51.5, -0.1)
        assert abs(d1 - d2) < 0.001


# ── geoip_lookup ─────────────────────────────────────────────────────────


class TestGeoipLookup:
    def test_private_ip_returns_none(self):
        assert geoip_lookup("10.0.0.1") is None
        assert geoip_lookup("192.168.1.1") is None
        assert geoip_lookup("172.16.0.1") is None

    def test_loopback_returns_none(self):
        assert geoip_lookup("127.0.0.1") is None
        assert geoip_lookup("::1") is None

    def test_invalid_ip_returns_none(self):
        assert geoip_lookup("not-an-ip") is None
        assert geoip_lookup("") is None
        assert geoip_lookup("999.999.999.999") is None

    @patch("bamf.services.geoip._get_reader")
    def test_no_reader_returns_none(self, mock_get_reader):
        mock_get_reader.return_value = None
        assert geoip_lookup("8.8.8.8") is None

    @patch("bamf.services.geoip._get_reader")
    def test_successful_lookup(self, mock_get_reader):
        mock_reader = MagicMock()
        mock_response = MagicMock()
        mock_response.location.latitude = 51.5074
        mock_response.location.longitude = -0.1278
        mock_reader.city.return_value = mock_response
        mock_get_reader.return_value = mock_reader

        result = geoip_lookup("8.8.8.8")
        assert result == (51.5074, -0.1278)
        mock_reader.city.assert_called_once_with("8.8.8.8")

    @patch("bamf.services.geoip._get_reader")
    def test_lookup_with_no_location(self, mock_get_reader):
        mock_reader = MagicMock()
        mock_response = MagicMock()
        mock_response.location.latitude = None
        mock_response.location.longitude = None
        mock_reader.city.return_value = mock_response
        mock_get_reader.return_value = mock_reader

        assert geoip_lookup("8.8.8.8") is None

    @patch("bamf.services.geoip._get_reader")
    def test_reader_exception_returns_none(self, mock_get_reader):
        mock_reader = MagicMock()
        mock_reader.city.side_effect = Exception("DB error")
        mock_get_reader.return_value = mock_reader

        assert geoip_lookup("8.8.8.8") is None


# ── select_nearest_satellite ─────────────────────────────────────────────


class TestSelectNearestSatellite:
    @pytest.mark.asyncio
    @patch("bamf.services.geoip.geoip_lookup")
    async def test_selects_nearest(self, mock_lookup):
        # Client in London
        mock_lookup.return_value = (51.5074, -0.1278)

        satellites = [
            {"name": "us-east", "latitude": 40.7128, "longitude": -74.0060},
            {"name": "eu", "latitude": 53.3498, "longitude": -6.2603},
            {"name": "apac", "latitude": 35.6762, "longitude": 139.6503},
        ]

        result = await select_nearest_satellite("8.8.8.8", satellites)
        assert result == "eu"

    @pytest.mark.asyncio
    @patch("bamf.services.geoip.geoip_lookup")
    async def test_geoip_fails_returns_none(self, mock_lookup):
        mock_lookup.return_value = None

        satellites = [
            {"name": "eu", "latitude": 53.3, "longitude": -6.2},
        ]

        result = await select_nearest_satellite("10.0.0.1", satellites)
        assert result is None

    @pytest.mark.asyncio
    @patch("bamf.services.geoip.geoip_lookup")
    async def test_empty_satellites_returns_none(self, mock_lookup):
        mock_lookup.return_value = (51.5, -0.1)

        result = await select_nearest_satellite("8.8.8.8", [])
        assert result is None

    @pytest.mark.asyncio
    @patch("bamf.services.geoip.geoip_lookup")
    async def test_satellites_without_coords_skipped(self, mock_lookup):
        mock_lookup.return_value = (51.5, -0.1)

        satellites = [
            {"name": "no-coords"},
            {"name": "eu", "latitude": 53.3, "longitude": -6.2},
            {"name": "partial", "latitude": 40.0},
        ]

        result = await select_nearest_satellite("8.8.8.8", satellites)
        assert result == "eu"

    @pytest.mark.asyncio
    @patch("bamf.services.geoip.geoip_lookup")
    async def test_all_satellites_without_coords_returns_none(self, mock_lookup):
        mock_lookup.return_value = (51.5, -0.1)

        satellites = [
            {"name": "a"},
            {"name": "b", "latitude": None, "longitude": None},
        ]

        result = await select_nearest_satellite("8.8.8.8", satellites)
        assert result is None

    @pytest.mark.asyncio
    @patch("bamf.services.geoip.geoip_lookup")
    async def test_single_satellite(self, mock_lookup):
        mock_lookup.return_value = (51.5, -0.1)

        satellites = [
            {"name": "only-one", "latitude": 35.0, "longitude": 139.0},
        ]

        result = await select_nearest_satellite("8.8.8.8", satellites)
        assert result == "only-one"
