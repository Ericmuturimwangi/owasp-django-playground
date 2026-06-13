import time
from django.core.cache import cache

_attempts: dict[str, list[float]] = {}

def vulnerable_is_rate_limited(request, *, limit=5, window=60) -> bool:

    key = request.META.get("HTTP_X_FORWARDED_FOR", "unknown")
    now = time.time()
    bucket = _attempts.setdefault(key, [])
    bucket.append(now) 

    recent = [t for t in bucket if t > now - window]
    return len(recent) > limit


def _trusted_client_ip(request) -> str:

    return request.META.get("REMOTE_ADDR", "0.0.0.0")



def secure_is_rate_limited(request, *, scope: str, identity: str | None = None, limit=5, window=60) -> bool:

    who = identity or _trusted_client_ip(request)
    key = f"rl:{scope}:{who}"
    try:
        added = cache.add(key, 0, timeout=window)
        count = cache.incr(key)

    except ValueError:

        cache.set(key, 1, timeout=window)
        count = 1
    return count > limit


