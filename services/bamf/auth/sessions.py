"""Redis-backed session management.

Sessions are the primary authentication mechanism for BAMF API requests.
Clients receive an opaque session token (not a JWT) and include it in
the Authorization header. The server validates by looking up the session
in Redis, enabling immediate revocation.
"""

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import timedelta

from bamf.config import settings
from bamf.db.models import utc_now
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client

logger = get_logger(__name__)

SESSION_PREFIX = "bamf:session:"
USER_SESSIONS_PREFIX = "bamf:user_sessions:"


def _session_ttl() -> int:
    """Session TTL in seconds from config."""
    return settings.auth.session_ttl_hours * 3600


@dataclass
class Session:
    """Server-side session state stored in Redis."""

    email: str
    display_name: str | None
    roles: list[str]
    provider_name: str
    created_at: str  # ISO 8601
    expires_at: str  # ISO 8601
    last_active_at: str  # ISO 8601

    # Kubernetes groups resolved from roles at login (union of all matching roles)
    kubernetes_groups: list[str] = field(default_factory=list)

    # Token is not stored in Redis — it's the key, not the value.
    token: str = field(default="", repr=False)


def generate_session_token() -> str:
    """Generate a cryptographically random session token."""
    return secrets.token_urlsafe(32)


async def create_session(
    email: str,
    display_name: str | None,
    roles: list[str],
    provider_name: str,
    kubernetes_groups: list[str] | None = None,
) -> Session:
    """Create a new session in Redis. Returns the Session with its token."""
    redis = get_redis_client()
    token = generate_session_token()
    ttl = _session_ttl()
    now = utc_now()
    expires_at = now + timedelta(seconds=ttl)

    session = Session(
        email=email,
        display_name=display_name,
        roles=roles,
        provider_name=provider_name,
        created_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
        last_active_at=now.isoformat(),
        kubernetes_groups=kubernetes_groups or [],
        token=token,
    )

    # Store session data (exclude token — it's the key)
    data = asdict(session)
    data.pop("token")

    session_key = SESSION_PREFIX + token
    user_key = USER_SESSIONS_PREFIX + email

    async with redis.pipeline(transaction=True) as pipe:
        pipe.set(session_key, json.dumps(data), ex=ttl)
        pipe.sadd(user_key, token)
        pipe.expire(user_key, ttl)
        await pipe.execute()

    logger.info("Session created", email=email, provider=provider_name)
    return session


async def get_session(token: str) -> Session | None:
    """Look up a session by token. Returns None if not found or expired."""
    redis = get_redis_client()
    data = await redis.get(SESSION_PREFIX + token)
    if data is None:
        return None

    parsed = json.loads(data)
    return Session(token=token, **parsed)


async def revoke_session(token: str) -> bool:
    """Revoke a session by deleting it from Redis.

    Returns True if the session existed, False if it was already gone.
    """
    redis = get_redis_client()
    session_key = SESSION_PREFIX + token

    # Get the session first to find the email for cleanup
    data = await redis.get(session_key)

    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(session_key)
        if data is not None:
            parsed = json.loads(data)
            user_key = USER_SESSIONS_PREFIX + parsed["email"]
            pipe.srem(user_key, token)
        results = await pipe.execute()

    deleted = results[0] > 0
    if deleted:
        logger.info("Session revoked")
    return deleted


async def list_user_sessions(email: str) -> list[Session]:
    """List all active sessions for a user.

    Cleans up stale entries (tokens that have expired from Redis but
    remain in the user's session set).
    """
    redis = get_redis_client()
    user_key = USER_SESSIONS_PREFIX + email

    tokens = await redis.smembers(user_key)
    if not tokens:
        return []

    sessions = []
    stale_tokens = []

    for token_bytes in tokens:
        token = token_bytes if isinstance(token_bytes, str) else token_bytes.decode()
        data = await redis.get(SESSION_PREFIX + token)
        if data is None:
            stale_tokens.append(token)
            continue
        parsed = json.loads(data)
        sessions.append(Session(token=token, **parsed))

    # Clean up stale entries
    if stale_tokens:
        await redis.srem(user_key, *stale_tokens)

    return sessions


async def list_all_sessions() -> list[Session]:
    """List all active sessions across all users.

    Uses SCAN to iterate keys matching the session prefix. Safe for the
    expected scale (infrastructure teams are small).
    """
    redis = get_redis_client()
    sessions: list[Session] = []

    async for key in redis.scan_iter(match=f"{SESSION_PREFIX}*", count=100):
        data = await redis.get(key)
        if data is None:
            continue
        key_str = key if isinstance(key, str) else key.decode()
        token = key_str[len(SESSION_PREFIX) :]
        parsed = json.loads(data)
        sessions.append(Session(token=token, **parsed))

    return sessions


async def revoke_all_user_sessions(email: str) -> int:
    """Revoke all sessions for a user. Returns count of sessions revoked."""
    redis = get_redis_client()
    user_key = USER_SESSIONS_PREFIX + email

    tokens = await redis.smembers(user_key)
    if not tokens:
        return 0

    async with redis.pipeline(transaction=True) as pipe:
        for token_bytes in tokens:
            token = token_bytes if isinstance(token_bytes, str) else token_bytes.decode()
            pipe.delete(SESSION_PREFIX + token)
        pipe.delete(user_key)
        results = await pipe.execute()

    # Count actual deletions (exclude the final delete of the set itself)
    count = sum(1 for r in results[:-1] if r > 0)
    logger.info("Revoked all sessions for user", email=email, count=count)
    return count
