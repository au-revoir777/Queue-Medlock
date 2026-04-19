"""
MedLock Rate Limiter — Token-Bucket Middleware (FastAPI + Redis)
================================================================
Implements a per-key token-bucket rate limiter for the /auth/validate endpoint.

Configuration:
    - Capacity  : 100 tokens  (max requests per window)
    - Burst     : 5 tokens    (max burst above refill rate)
    - Refill    : 60 seconds  (full bucket refill interval)
    - Key format: hospital:dept:userId

Algorithm:
    Uses a Redis-backed token bucket via a Lua script for atomic
    decrement + refill. This avoids race conditions under concurrent load.

Returns HTTP 429 Too Many Requests when tokens are exhausted.
"""

import os
import time
import redis.asyncio as aioredis
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


# ----------------------------------------------------------------
# Configuration — override via environment variables
# ----------------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
RATE_LIMIT_CAPACITY = int(os.environ.get("RATE_LIMIT_CAPACITY", "100"))
RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "5"))
RATE_LIMIT_REFILL_SECONDS = int(os.environ.get("RATE_LIMIT_REFILL_SECONDS", "60"))

# ----------------------------------------------------------------
# Lua script for atomic token-bucket operation
# ----------------------------------------------------------------
# Keys: [bucket_key]
# Args: [capacity, refill_rate_per_sec, now, burst_limit]
#
# Returns: [allowed (0/1), tokens_remaining, retry_after_seconds]
TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local burst = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    tokens = capacity
    last_refill = now
end

-- Refill tokens based on elapsed time
local elapsed = now - last_refill
local refill = elapsed * refill_rate
tokens = math.min(capacity + burst, tokens + refill)
last_refill = now

-- Try to consume one token
if tokens < 1 then
    local retry_after = math.ceil((1 - tokens) / refill_rate)
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
    redis.call('EXPIRE', key, 120)
    return {0, math.floor(tokens), retry_after}
end

tokens = tokens - 1
redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
redis.call('EXPIRE', key, 120)
return {1, math.floor(tokens), 0}
"""


class TokenBucketRateLimiter(BaseHTTPMiddleware):
    """
    FastAPI middleware that enforces token-bucket rate limiting on
    the /auth/validate endpoint.

    Key derivation:
        Extracts hospital_id, department, and staff_id from the
        JSON body to build a composite rate-limit key.
        Falls back to client IP if body parsing fails.
    """

    def __init__(self, app, redis_url: str = REDIS_URL):
        super().__init__(app)
        self._redis_url = redis_url
        self._redis = None
        self._script_sha = None

    async def _get_redis(self):
        """Lazy-initialize the async Redis connection."""
        if self._redis is None:
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
            )
            # Pre-load the Lua script
            self._script_sha = await self._redis.script_load(TOKEN_BUCKET_LUA)
        return self._redis

    def _extract_rate_key(self, body: dict, request: Request) -> str:
        """
        Build a rate-limit key from the request body.
        Format: ratelimit:hospital:dept:userId
        Falls back to IP-based key if fields are missing.
        """
        hospital = body.get("hospital_id", "")
        dept = body.get("department", "unknown")
        user = body.get("staff_id", "")

        if hospital and user:
            return f"ratelimit:{hospital}:{dept}:{user}"

        # Fallback: use client IP
        client_ip = request.client.host if request.client else "unknown"
        return f"ratelimit:ip:{client_ip}"

    async def dispatch(self, request: Request, call_next):
        """
        Intercepts requests to /auth/validate and applies rate limiting.
        All other endpoints pass through unmodified.
        """
        # Only rate-limit the validate endpoint
        if request.url.path != "/auth/validate" or request.method != "POST":
            return await call_next(request)

        try:
            # Read and cache the body so downstream can re-read it
            body_bytes = await request.body()

            import json

            try:
                body = json.loads(body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = {}

            rate_key = self._extract_rate_key(body, request)
            r = await self._get_redis()

            now = time.time()
            refill_rate = RATE_LIMIT_CAPACITY / RATE_LIMIT_REFILL_SECONDS

            result = await r.evalsha(
                self._script_sha,
                1,
                rate_key,
                str(RATE_LIMIT_CAPACITY),
                str(refill_rate),
                str(now),
                str(RATE_LIMIT_BURST),
            )

            allowed, remaining, retry_after = (
                int(result[0]),
                int(result[1]),
                int(result[2]),
            )

            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded",
                        "retry_after": retry_after,
                        "limit": RATE_LIMIT_CAPACITY,
                        "remaining": remaining,
                        "key": rate_key,
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(RATE_LIMIT_CAPACITY),
                        "X-RateLimit-Remaining": str(remaining),
                        "X-RateLimit-Reset": str(int(now) + retry_after),
                    },
                )

            # Allowed — proceed with rate-limit headers
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_CAPACITY)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            return response

        except aioredis.ConnectionError:
            # If Redis is down, fail open (allow the request)
            # Log the issue but don't block legitimate traffic
            return await call_next(request)


def attach_rate_limiter(app, redis_url: str = REDIS_URL):
    """
    Convenience function to attach the rate limiter to a FastAPI app.

    Usage:
        from auth.rate_limiter import attach_rate_limiter
        attach_rate_limiter(app)
    """
    app.add_middleware(TokenBucketRateLimiter, redis_url=redis_url)
    return app
