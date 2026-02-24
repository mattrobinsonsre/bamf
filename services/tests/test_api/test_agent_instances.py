"""Tests for agent instance management (multi-replica support)."""

import json
import time

import pytest

from bamf.services.agent_instances import (
    cleanup_stale_instances,
    decrement_instance_tunnels,
    drain_instance,
    increment_instance_tunnels,
    register_instance,
    remove_instance,
    select_agent_instance,
    set_instance_has_relay,
    update_instance_tunnel_count,
)


class FakeRedis:
    """Minimal fake Redis for unit testing agent instance operations.

    Only implements the hash (HSET/HGET/HGETALL/HDEL) and key expiry
    operations used by agent_instances.py.
    """

    def __init__(self):
        self._store: dict[str, dict[str, str]] = {}

    async def hset(
        self, key: str, field: str | None = None, value: str | None = None, mapping=None
    ):
        if key not in self._store:
            self._store[key] = {}
        if mapping:
            for k, v in mapping.items():
                self._store[key][k] = v
        elif field is not None and value is not None:
            self._store[key][field] = value

    async def hget(self, key: str, field: str) -> str | None:
        return self._store.get(key, {}).get(field)

    async def hgetall(self, key: str) -> dict[str, str]:
        return dict(self._store.get(key, {}))

    async def hdel(self, key: str, field: str):
        if key in self._store:
            self._store[key].pop(field, None)

    async def expire(self, key: str, ttl: int):
        pass  # No-op for tests


AGENT_ID = "019c5145-6afe-7985-a78b-72d3004b53d4"
INSTANCE_A = "aaaa-1111"
INSTANCE_B = "bbbb-2222"
TTL = 180


class TestRegisterInstance:
    @pytest.mark.asyncio
    async def test_new_instance_initializes_fields(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert raw is not None
        data = json.loads(raw)
        assert data["tunnel_count"] == 0
        assert data["has_relay"] is False
        assert data["status"] == "active"
        assert "last_heartbeat" in data

    @pytest.mark.asyncio
    async def test_reregister_preserves_tunnel_count(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)
        await increment_instance_tunnels(r, AGENT_ID, INSTANCE_A)
        await increment_instance_tunnels(r, AGENT_ID, INSTANCE_A)

        # Re-register should preserve the tunnel_count
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        data = json.loads(raw)
        assert data["tunnel_count"] == 2


class TestSelectAgentInstance:
    @pytest.mark.asyncio
    async def test_returns_none_when_no_instances(self):
        r = FakeRedis()
        result = await select_agent_instance(r, AGENT_ID)
        assert result is None

    @pytest.mark.asyncio
    async def test_selects_instance_with_fewest_tunnels(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)
        await register_instance(r, AGENT_ID, INSTANCE_B, TTL)
        # Give A 3 tunnels, B has 0
        for _ in range(3):
            await increment_instance_tunnels(r, AGENT_ID, INSTANCE_A)

        result = await select_agent_instance(r, AGENT_ID)
        assert result == INSTANCE_B

    @pytest.mark.asyncio
    async def test_skips_draining_instances(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)
        await register_instance(r, AGENT_ID, INSTANCE_B, TTL)
        await drain_instance(r, AGENT_ID, INSTANCE_B)

        result = await select_agent_instance(r, AGENT_ID)
        assert result == INSTANCE_A

    @pytest.mark.asyncio
    async def test_skips_stale_instances(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)
        await register_instance(r, AGENT_ID, INSTANCE_B, TTL)

        # Make A stale by backdating its heartbeat
        key = f"agent:{AGENT_ID}:instances"
        raw = await r.hget(key, INSTANCE_A)
        data = json.loads(raw)
        data["last_heartbeat"] = time.time() - 300  # 5 min ago
        await r.hset(key, INSTANCE_A, json.dumps(data))

        result = await select_agent_instance(r, AGENT_ID)
        assert result == INSTANCE_B

    @pytest.mark.asyncio
    async def test_prefer_no_relay(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)
        await register_instance(r, AGENT_ID, INSTANCE_B, TTL)
        await set_instance_has_relay(r, AGENT_ID, INSTANCE_A, True)

        result = await select_agent_instance(r, AGENT_ID, prefer_no_relay=True)
        assert result == INSTANCE_B


class TestTunnelCounting:
    @pytest.mark.asyncio
    async def test_increment_and_decrement(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        await increment_instance_tunnels(r, AGENT_ID, INSTANCE_A)
        await increment_instance_tunnels(r, AGENT_ID, INSTANCE_A)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert json.loads(raw)["tunnel_count"] == 2

        await decrement_instance_tunnels(r, AGENT_ID, INSTANCE_A)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert json.loads(raw)["tunnel_count"] == 1

    @pytest.mark.asyncio
    async def test_decrement_floors_at_zero(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        await decrement_instance_tunnels(r, AGENT_ID, INSTANCE_A)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert json.loads(raw)["tunnel_count"] == 0

    @pytest.mark.asyncio
    async def test_update_from_agent_reported_count(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        # Simulate drift: Redis says 5, agent says 2
        for _ in range(5):
            await increment_instance_tunnels(r, AGENT_ID, INSTANCE_A)

        await update_instance_tunnel_count(r, AGENT_ID, INSTANCE_A, 2)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert json.loads(raw)["tunnel_count"] == 2

    @pytest.mark.asyncio
    async def test_update_floors_negative_at_zero(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        await update_instance_tunnel_count(r, AGENT_ID, INSTANCE_A, -1)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert json.loads(raw)["tunnel_count"] == 0

    @pytest.mark.asyncio
    async def test_increment_nonexistent_is_noop(self):
        r = FakeRedis()
        # Should not raise
        await increment_instance_tunnels(r, AGENT_ID, "nonexistent")

    @pytest.mark.asyncio
    async def test_decrement_nonexistent_is_noop(self):
        r = FakeRedis()
        await decrement_instance_tunnels(r, AGENT_ID, "nonexistent")


class TestDrainAndRemove:
    @pytest.mark.asyncio
    async def test_drain_sets_status(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        await drain_instance(r, AGENT_ID, INSTANCE_A)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert json.loads(raw)["status"] == "draining"

    @pytest.mark.asyncio
    async def test_remove_deletes_entry(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)

        await remove_instance(r, AGENT_ID, INSTANCE_A)
        raw = await r.hget(f"agent:{AGENT_ID}:instances", INSTANCE_A)
        assert raw is None


class TestCleanupStaleInstances:
    @pytest.mark.asyncio
    async def test_removes_stale_keeps_fresh(self):
        r = FakeRedis()
        await register_instance(r, AGENT_ID, INSTANCE_A, TTL)
        await register_instance(r, AGENT_ID, INSTANCE_B, TTL)

        # Make A stale
        key = f"agent:{AGENT_ID}:instances"
        raw = await r.hget(key, INSTANCE_A)
        data = json.loads(raw)
        data["last_heartbeat"] = time.time() - 300
        await r.hset(key, INSTANCE_A, json.dumps(data))

        removed = await cleanup_stale_instances(r, AGENT_ID)
        assert removed == 1

        assert await r.hget(key, INSTANCE_A) is None
        assert await r.hget(key, INSTANCE_B) is not None

    @pytest.mark.asyncio
    async def test_removes_malformed_entries(self):
        r = FakeRedis()
        key = f"agent:{AGENT_ID}:instances"
        await r.hset(key, "bad-instance", "not-json{{{")

        removed = await cleanup_stale_instances(r, AGENT_ID)
        assert removed == 1
        assert await r.hget(key, "bad-instance") is None
