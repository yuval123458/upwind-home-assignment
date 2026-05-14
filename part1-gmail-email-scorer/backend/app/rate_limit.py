"""Shared Limiter instance used by main.py (to register the exception handler)
and by route modules (to decorate specific endpoints).

Keys by client IP address. Per-user keying would require accessing the
authenticated user before the limit check runs, which slowapi can't do cleanly.
In-memory storage — multi-instance deploys would need a Redis backend.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
