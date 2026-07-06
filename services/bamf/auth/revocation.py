"""Certificate revocation denylist.

Durable source of truth in Postgres (``revoked_certificates``); a working copy
in a Redis set for O(1) cert-auth checks. The set is loaded from Postgres at
startup and updated on each revoke, so it survives an API restart and is shared
across replicas.

Revocation is enforced at the API's cert-auth layer (agent/bridge certs, which
are long-lived). The bridge keeps its zero-runtime-dependency design; tunnel
session certs are 30s TTL and the API won't mint a new one for a revoked
identity, so the tunnel path needs no bridge-side check.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.db.models import RevokedCertificate, utc_now
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client

logger = get_logger(__name__)

_REVOKED_SET = "bamf:revoked_certs"


async def is_certificate_revoked(fingerprint: str) -> bool:
    """Return True if the fingerprint is on the denylist (Redis set)."""
    try:
        redis = get_redis_client()
        return bool(await redis.sismember(_REVOKED_SET, fingerprint))
    except Exception:
        # Fail open on Redis error (consistent with the rate limiter): the
        # durable DB reloads into Redis at startup, so the exposure window is
        # small, and failing closed would break all agent/bridge auth.
        logger.warning("revocation check Redis error, failing open", exc_info=True)
        return False


async def revoke_certificate(
    db: AsyncSession,
    fingerprint: str,
    reason: str | None = None,
    revoked_by: str | None = None,
    subject_cn: str | None = None,
) -> None:
    """Add a certificate fingerprint to the durable denylist and the Redis set."""
    if await db.get(RevokedCertificate, fingerprint) is None:
        db.add(
            RevokedCertificate(
                fingerprint=fingerprint,
                revoked_at=utc_now(),
                reason=reason,
                revoked_by=revoked_by,
                subject_cn=subject_cn,
            )
        )
        await db.flush()
    redis = get_redis_client()
    await redis.sadd(_REVOKED_SET, fingerprint)
    logger.info("certificate revoked", fingerprint=fingerprint[:16], revoked_by=revoked_by)


async def list_revoked_certificates(db: AsyncSession) -> list[RevokedCertificate]:
    """List all revoked certificates, newest first."""
    result = await db.execute(
        select(RevokedCertificate).order_by(RevokedCertificate.revoked_at.desc())
    )
    return list(result.scalars().all())


async def load_revoked_into_redis(db: AsyncSession) -> int:
    """Populate the Redis denylist set from Postgres. Called at startup."""
    result = await db.execute(select(RevokedCertificate.fingerprint))
    fingerprints = [row[0] for row in result.all()]
    if fingerprints:
        redis = get_redis_client()
        await redis.sadd(_REVOKED_SET, *fingerprints)
    logger.info("loaded revoked certificates into Redis", count=len(fingerprints))
    return len(fingerprints)
