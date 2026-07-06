"""Reliable API→agent command delivery.

CONTRACT: this is the producer half of the API→agent command stream; the
consumer is the SSE handler in ``routers/agents.py`` (which drains the same
queue) and the Go agent in ``pkg/agent/sse.go`` / ``pkg/agent/agent.go``.

Commands go to a short-lived per-instance Redis **list** (not fire-and-forget
pub/sub). If a command is issued while the agent's SSE stream is momentarily down
(exponential-backoff reconnect), it is not lost — it waits in the list, bounded
by ``COMMAND_QUEUE_TTL_SECONDS``, and is delivered when the agent re-subscribes.
The SSE handler drains via ``BLPOP``, giving exactly-once delivery to the single
active consumer (no pub/sub duplicate-on-reconnect problem).

Producers map ``command`` → SSE event type (``relay_connect``/``revoke``, else
``tunnel_request``); the consumer switches on the event type and then the inner
``command`` (``dial``/``redial``). Keep producer and consumer in sync.
"""

import json

from redis import asyncio as aioredis

# How long an undelivered command waits for a reconnecting agent. Sized above the
# 30s tunnel-setup timeout with headroom: a command older than this is stale (the
# client's connect attempt has already errored), so letting it expire is correct.
COMMAND_QUEUE_TTL_SECONDS = 60


def command_queue_key(agent_id: str, instance_id: str) -> str:
    """Redis list key for an agent instance's command queue."""
    return f"agent:{agent_id}:instance:{instance_id}:commands"


async def enqueue_agent_command(
    r: aioredis.Redis, agent_id: str, instance_id: str, payload: dict
) -> None:
    """Append a command to an agent instance's reliable delivery queue.

    Refreshes the queue TTL on every push so an active tunnel-setup flow keeps
    the queue alive; an idle queue expires and is garbage-collected.
    """
    key = command_queue_key(agent_id, instance_id)
    await r.rpush(key, json.dumps(payload))
    await r.expire(key, COMMAND_QUEUE_TTL_SECONDS)
