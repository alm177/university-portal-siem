import os
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    return int(os.environ.get(name, str(default)))


# Flask
SECRET_KEY = os.environ.get("SECRET_KEY", "")
FLASK_DEBUG = _env_bool("FLASK_DEBUG", False)
SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
ALLOW_INSECURE_DEMO_CONFIG = _env_bool("ALLOW_INSECURE_DEMO_CONFIG", False)

# Database
DATABASE = os.environ.get("DATABASE", "database.db")

# OpenSearch / SIEM
OS_URL = os.environ.get("OS_URL", "https://localhost:9200")
OS_INDEX = os.environ.get("OS_INDEX", "uni-auth-logs")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OS_PASS", "")
OS_VERIFY_SSL = _env_bool("OS_VERIFY_SSL", False)
TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", False)

# Seeded admin account
DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_EMAIL = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@uni.local")
DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "")

# Rate limiting
LOGIN_THRESHOLD = _env_int("LOGIN_THRESHOLD", 5)
REGISTER_THRESHOLD = _env_int("REGISTER_THRESHOLD", 5)
RESET_THRESHOLD = _env_int("RESET_THRESHOLD", 3)
WINDOW_MINUTES = _env_int("WINDOW_MINUTES", 2)
LOCK_MINUTES = _env_int("LOCK_MINUTES", 30)
RESET_WINDOW_MINUTES = _env_int("RESET_WINDOW_MINUTES", 10)

# Session timeout
SESSION_IDLE_MINUTES = _env_int("SESSION_IDLE_MINUTES", 1)
SESSION_ABSOLUTE_HOURS = _env_int("SESSION_ABSOLUTE_HOURS", 3)

# DoS Protection
DOS_WARNING_THRESHOLD = _env_int("DOS_WARNING_THRESHOLD", 60)
DOS_BLOCK_THRESHOLD = _env_int("DOS_BLOCK_THRESHOLD", 120)
DOS_WINDOW_SECONDS = _env_int("DOS_WINDOW_SECONDS", 60)
DOS_BLOCK_MINUTES = _env_int("DOS_BLOCK_MINUTES", 5)

# Password reset
RESET_TOKEN_EXPIRE_MINUTES = _env_int("RESET_TOKEN_EXPIRE_MINUTES", 15)

# Verification codes (password reset + email MFA)
VERIFICATION_CODE_EXPIRE_MINUTES = _env_int("VERIFICATION_CODE_EXPIRE_MINUTES", 10)
VERIFICATION_CODE_MAX_ATTEMPTS = _env_int("VERIFICATION_CODE_MAX_ATTEMPTS", 5)

# Security headers
SECURITY_HEADERS_ENABLED = _env_bool("SECURITY_HEADERS_ENABLED", True)

# SMTP (optional; leave empty for on-screen fallback)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "")
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@uni.local")


def validate_security_config():
    """Fail fast when public-clone defaults would create unsafe credentials."""
    if ALLOW_INSECURE_DEMO_CONFIG:
        return

    errors = []
    if (
        len(SECRET_KEY) < 32
        or SECRET_KEY in {"change-this-secret-in-production", "replace-with-a-random-32-plus-character-secret"}
    ):
        errors.append("set SECRET_KEY to a random value of at least 32 characters")
    if len(DEFAULT_ADMIN_PASSWORD) < 12 or DEFAULT_ADMIN_PASSWORD == "change-this-admin-password":
        errors.append("set DEFAULT_ADMIN_PASSWORD to a strong password")

    if errors:
        raise RuntimeError(
            "Unsafe configuration detected. "
            + "; ".join(errors)
            + ". For an isolated classroom demo only, set ALLOW_INSECURE_DEMO_CONFIG=true."
        )
