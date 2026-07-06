"""Tests for reliable API→agent command delivery (agent_commands)."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from bamf.api.agent_commands import (
    COMMAND_QUEUE_TTL_SECONDS,
    command_queue_key,
    enqueue_agent_command,
)


def test_command_queue_key():
    assert command_queue_key("agent-1", "inst-9") == "agent:agent-1:instance:inst-9:commands"


@pytest.mark.asyncio
async def test_enqueue_rpushes_json_and_sets_ttl():
    """A command is appended to the instance list (FIFO) with a refreshed TTL, so
    it survives until an agent (re)connects and drains it."""
    r = MagicMock()
    r.rpush = AsyncMock()
    r.expire = AsyncMock()

    payload = {"command": "dial", "session_id": "s1"}
    await enqueue_agent_command(r, "agent-1", "inst-9", payload)

    key = "agent:agent-1:instance:inst-9:commands"
    r.rpush.assert_awaited_once()
    args = r.rpush.call_args.args
    assert args[0] == key
    assert json.loads(args[1]) == payload  # serialized, round-trips
    r.expire.assert_awaited_once_with(key, COMMAND_QUEUE_TTL_SECONDS)
