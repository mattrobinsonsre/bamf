"""Process-lifecycle signals shared across the app and routers.

A leaf module by design: it imports nothing from ``bamf.api.app`` or the routers,
so importing it from a router does not create an import cycle (app → routers →
app). The lifespan handler sets ``shutdown_event`` on SIGTERM; long-lived SSE
generators check it to close promptly during shutdown.
"""

import asyncio

# Set by the FastAPI lifespan on shutdown; watched by SSE generators.
shutdown_event = asyncio.Event()
