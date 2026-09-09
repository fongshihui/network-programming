import os
import json
import time
import hashlib
import threading
from typing import Any, Optional, Tuple, Dict, Callable

# Try importing real redis
try:
    import redis
    REDIS_LIB_AVAILABLE = True
except ImportError:
    REDIS_LIB_AVAILABLE = False


class HTTPCacheHelper:
    """HTTP/1.1 Caching header and ETag generation."""

    @staticmethod
    def generate_etag(data: bytes) -> str:
        """Computes a strong ETag hash."""
        return f'"{hashlib.sha256(data).hexdigest()[:16]}"'

    @staticmethod
    def is_match(client_etag: Optional[str], server_etag: str) -> bool:
        """Compares client's If-None-Match with current server ETag."""
        if not client_etag:
            return False
        clean_client = client_etag.strip().strip('"')
        clean_server = server_etag.strip().strip('"')
        return clean_client == clean_server


class ApplicationCache:
    """
    Tier 1 (L1) In-Memory Fast Cache with TTL expiration and thread safety.
    """
    def __init__(self, default_ttl: int = 30):
        self.default_ttl = default_ttl
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock:
            if key in self._store:
                val, expires_at = self._store[key]
                if now <= expires_at:
                    self.hits += 1
                    return val
                else:
                    del self._store[key]
            self.misses += 1
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        duration = ttl if ttl is not None else self.default_ttl
        expires_at = time.time() + duration
        with self._lock:
            self._store[key] = (value, expires_at)

    def delete(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def clear(self):
        with self._lock:
            self._store.clear()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            hit_rate = round((self.hits / total * 100), 1) if total > 0 else 0.0
            return {
                "layer": "L1 (Application In-Memory)",
                "size": len(self._store),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate_pct": hit_rate,
            }


class RedisCache:
    """
    Tier 2 (L2) Distributed Cache Layer with automatic In-Memory fallback.
    """
    def __init__(self):
        self.host = os.getenv("REDIS_HOST", "127.0.0.1")
        self.port = int(os.getenv("REDIS_PORT", 6379))
        self.default_ttl = int(os.getenv("REDIS_TTL", 60))
        self.client = None
        self.is_connected = False
        self.engine = "Redis (In-Memory Fallback)"
        self.hits = 0
        self.misses = 0

        self._memory_store: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

        self._init_connection()

    def _init_connection(self):
        if REDIS_LIB_AVAILABLE:
            try:
                client = redis.Redis(
                    host=self.host,
                    port=self.port,
                    socket_connect_timeout=1,
                    decode_responses=True,
                )
                client.ping()
                self.client = client
                self.is_connected = True
                self.engine = "Redis (Live Cluster/Instance)"
                print(f"[Cache] Connected to live Redis at {self.host}:{self.port}")
                return
            except Exception:
                pass

        self.is_connected = False
        self.engine = "Redis (In-Memory Fallback)"

    def get(self, key: str) -> Optional[Any]:
        if self.is_connected and self.client:
            try:
                val = self.client.get(key)
                if val is not None:
                    self.hits += 1
                    return json.loads(val)
                self.misses += 1
                return None
            except Exception:
                self.is_connected = False
                self.engine = "Redis (In-Memory Fallback)"

        now = time.time()
        with self._lock:
            if key in self._memory_store:
                raw_json, exp = self._memory_store[key]
                if now <= exp:
                    self.hits += 1
                    return json.loads(raw_json)
                else:
                    del self._memory_store[key]
            self.misses += 1
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        duration = ttl if ttl is not None else self.default_ttl
        raw_json = json.dumps(value)

        if self.is_connected and self.client:
            try:
                self.client.setex(key, duration, raw_json)
                return
            except Exception:
                self.is_connected = False
                self.engine = "Redis (In-Memory Fallback)"

        with self._lock:
            self._memory_store[key] = (raw_json, time.time() + duration)

    def delete(self, key: str):
        if self.is_connected and self.client:
            try:
                self.client.delete(key)
            except Exception:
                pass
        with self._lock:
            self._memory_store.pop(key, None)

    def flush(self):
        if self.is_connected and self.client:
            try:
                self.client.flushdb()
            except Exception:
                pass
        with self._lock:
            self._memory_store.clear()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            hit_rate = round((self.hits / total * 100), 1) if total > 0 else 0.0
            return {
                "layer": "L2 (Redis)",
                "engine": self.engine,
                "is_live_redis": self.is_connected,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate_pct": hit_rate,
            }


class MultiTierCacheManager:
    """
    Orchestrates the multi-tier caching pipeline:
    HTTP (ETag / Client) -> Application (L1) -> Redis (L2) -> Database (MySQL/SQLite)
    """
    def __init__(self):
        self.l1_app = ApplicationCache(default_ttl=15)
        self.l2_redis = RedisCache()
        self.db_queries_count = 0
        self._lock = threading.Lock()

    def get_or_fetch(self, key: str, fetch_fn: Callable[[], Any], ttl: int = 30) -> Tuple[Any, str]:
        """
        Hierarchical Cache Resolver:
        1. Check L1 (App in-memory)
        2. Check L2 (Redis)
        3. Fetch DB -> Populate L2 -> Populate L1
        Returns: (data, source: "L1_APP_CACHE" | "L2_REDIS_CACHE" | "DATABASE")
        """
        # 1. Check L1
        data = self.l1_app.get(key)
        if data is not None:
            return data, "L1_APP_CACHE"

        # 2. Check L2
        data = self.l2_redis.get(key)
        if data is not None:
            # Promote to L1
            self.l1_app.set(key, data, ttl=ttl // 2)
            return data, "L2_REDIS_CACHE"

        # 3. Fetch from Database
        with self._lock:
            self.db_queries_count += 1

        db_result = fetch_fn()
        if db_result is not None:
            # Store in L2 and L1
            self.l2_redis.set(key, db_result, ttl=ttl)
            self.l1_app.set(key, db_result, ttl=ttl // 2)

        return db_result, "DATABASE"

    def invalidate(self, *keys: str):
        """Invalidates keys across all cache tiers."""
        for key in keys:
            self.l1_app.delete(key)
            self.l2_redis.delete(key)

    def get_full_stats(self) -> Dict[str, Any]:
        """Returns comprehensive caching telemetry."""
        return {
            "hierarchy": "HTTP (ETag) -> L1 Application -> L2 Redis -> Database",
            "l1_application": self.l1_app.get_stats(),
            "l2_redis": self.l2_redis.get_stats(),
            "database_queries_executed": self.db_queries_count,
        }
