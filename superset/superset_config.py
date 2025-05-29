import os
import redis

# -----------------------------------------------------------------------------
# Database
# Build SQLALCHEMY_DATABASE_URI from your .env
# -----------------------------------------------------------------------------
SQLALCHEMY_DATABASE_URI = (
    f"{os.environ['DATABASE_DIALECT']}+psycopg2://"
    f"{os.environ['DATABASE_USER']}:"
    f"{os.environ['DATABASE_PASSWORD']}@"
    f"{os.environ['DATABASE_HOST']}:"
    f"{os.environ['DATABASE_PORT']}/"
    f"{os.environ['DATABASE_DB']}"
)

# ---------------------------------------------------------------------
# SECRET_KEY: used for session signing and encrypted field decryption.
# (You can override by setting SECRET_KEY in your .env)
# ---------------------------------------------------------------------
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "LrKNhNDps82/5j1qV0FE51E6VlDpl2jedeGAcrZlsUkaKwCHySKSy8hJ",
)

# ---------------------------------------------------------------------
# Flask-Limiter (rate-limiting)
# ---------------------------------------------------------------------
RATELIMIT_ENABLED = True
RATELIMIT_STORAGE_URI = "redis://superset_cache:6379/0"
RATELIMIT_STRATEGY = "fixed-window"

# ---------------------------------------------------------------------
# Results Caching (queries & chart fragments)
# ---------------------------------------------------------------------
CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_URL": "redis://superset_cache:6379/1",
}

# ---------------------------------------------------------------------
# Celery (async query execution)
# ---------------------------------------------------------------------
CELERY_BROKER_URL = "redis://superset_cache:6379/2"
CELERY_RESULT_BACKEND = "redis://superset_cache:6379/3"

# ---------------------------------------------------------------------
# Session storage (optional)
# ---------------------------------------------------------------------
SESSION_TYPE = "redis"
SESSION_REDIS = redis.StrictRedis(
    host="superset_cache", port=6379, db=4, decode_responses=True
)

# ---------------------------------------------------------------------
# Enable Anonymous Access in Superset
# ---------------------------------------------------------------------
PUBLIC_ROLE_LIKE = "Gamma"
AUTH_TYPE = 2

# ---------------------------------------------------------------------
# Enable fine‑grained dashboard sharing
# ---------------------------------------------------------------------
FEATURE_FLAGS = {
  "EMBEDDED_SUPERSET": True,    # Enable the embedded‑mode
  "DASHBOARD_RBAC": True,       # if you want per‑dashboard grant checkboxes
  "ALERT_REPORTS": True,        # for the Alerts & Reports UI
  "DRILL_BY": True,             # so drill menus appear
  "DRILL_TO_DETAIL": True,      # if you’re doing detail‑page drill‑throughs
}

# ---------------------------------------------------------------------
# Ensures Correct URL redirects and logging
# ---------------------------------------------------------------------
ENABLE_PROXY_FIX = True

# ---------------------------------------------------------------------
# For email reports or thumbnails to use correct external URL
# ---------------------------------------------------------------------
WEBDRIVER_BASEURL = "https://www.sentryhawk.org"

# ---------------------------------------------------------------------
# Override Superset’s default headers to allow framing:
#   - X‑Frame‑Options = ALLOWALL
#   - frame‑ancestors include your domain
# ---------------------------------------------------------------------
HTTP_HEADERS = {
    "X-Frame-Options": "ALLOWALL",
    "Content-Security-Policy": "frame-ancestors 'self' https://www.sentryhawk.org; "
                              "default-src 'self'; img-src 'self' data:; "
                              "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
}

# -----------------------------------------------------------------------------
# Branding
# -----------------------------------------------------------------------------
# The application name shown in the browser tab and top bar
APP_NAME = "Sentryhawk"

# Path to your logo (must live under static/assets/images/Sentryhawk/logo.png)
APP_ICON = "/static/assets/images/Sentryhawk/logo.png"
APP_ICON_WIDTH = 220

# Where clicking the logo should take the user
LOGO_TARGET_PATH = "/"

# Hover tooltip for logo
LOGO_TOOLTIP = "Sentryhawk"

# (Optional) text to display next to logo—uncomment and edit if desired
# LOGO_RIGHT_TEXT = "Your Department Name"

# Favicon files (all must live under
# static/assets/images/Sentryhawk/favicon/)
FAVICONS = [
    {"href": "/favicon.ico"},
    {"href": "/static/assets/images/Sentryhawk/favicon/favicon.ico"},
    {"href": "/static/assets/images/Sentryhawk/favicon/favicon-96x96.png", "sizes": "96x96"},
    {"href": "/static/assets/images/Sentryhawk/favicon/apple-touch-icon.png", "sizes": "180x180"},
    {"href": "/static/assets/images/Sentryhawk/favicon/favicon.svg", "type": "image/svg+xml"},
]

APP_EXTRA_CSS = ["/static/assets/custom-styling.css"]

# -----------------------------------------------------------------------------
# Custom Color Theme (override defaultTheme in superset-frontend)
# -----------------------------------------------------------------------------
# THEME_OVERRIDES = {
#     "colors": {
#         "text": {
#             "label": "#879399",
#             "help": "#737373",
#         },
#         "primary": {
#             "base": "grey",
#         },
#         "secondary": {
#             "base": "black",
#         },
#         "grayscale": {
#             "base": "black",
#         },
#         "error": {
#             "base": "orange",
#         },
#     },
#     "typography": {
#         "families": {
#             "sansSerif": "Inter",
#             "serif": "Georgia",
#             "monospace": "Fira Code",
#         },
#         "weights": {
#             "light": 200,
#             "normal": 400,
#             "medium": 500,
#             "bold": 600,
#         },
#     },
# }
