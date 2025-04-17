import redis
from flask_caching import Cache

# ---------------------------------------------------------------------
# SECRET_KEY: used for session signing and encrypted field decryption.
# Generate with: openssl rand -base64 32
# ---------------------------------------------------------------------
SECRET_KEY = "<your-secret-key>"

# ---------------------------------------------------------------------
# Flask-Limiter (rate-limiting) settings
# ---------------------------------------------------------------------
RATELIMIT_ENABLED = True
RATELIMIT_STORAGE_URI = "redis://superset_cache:6379/0"
RATELIMIT_STRATEGY = "fixed-window"

# ---------------------------------------------------------------------
# Results Caching
# Uses RedisCache to cache query results and chart fragments.
# ---------------------------------------------------------------------
CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_URL": "redis://superset_cache:6379/1",
}

# ---------------------------------------------------------------------
# Celery (asynchronous query execution)
# Broker and backend both use Redis
# ---------------------------------------------------------------------
CELERY_BROKER_URL = "redis://superset_cache:6379/2"
CELERY_RESULT_BACKEND = "redis://superset_cache:6379/3"

# ---------------------------------------------------------------------
# Session storage (optional)
# Store session data in Redis for shared sessions across workers
# ---------------------------------------------------------------------
SESSION_TYPE = "redis"
SESSION_REDIS = redis.StrictRedis(
    host="superset_cache",
    port=6379,
    db=4,
    decode_responses=True
)
