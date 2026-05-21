import os
from dotenv import load_dotenv

load_dotenv()

# Flask
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-in-production")

# Database
DATABASE = os.environ.get("DATABASE", "database.db")

# OpenSearch / SIEM
OS_URL = os.environ.get("OS_URL", "https://localhost:9200")
OS_INDEX = os.environ.get("OS_INDEX", "uni-auth-logs")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OS_PASS", "change-this-opensearch-password")
OS_VERIFY_SSL = os.environ.get("OS_VERIFY_SSL", "false").lower() == "true"

# Seeded admin account
DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_EMAIL = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@uni.local")
DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "change-this-admin-password")

# Rate limiting
LOGIN_THRESHOLD = int(os.environ.get("LOGIN_THRESHOLD", "5"))
REGISTER_THRESHOLD = int(os.environ.get("REGISTER_THRESHOLD", "5"))
RESET_THRESHOLD = int(os.environ.get("RESET_THRESHOLD", "3"))
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "2"))
LOCK_MINUTES = int(os.environ.get("LOCK_MINUTES", "30"))
RESET_WINDOW_MINUTES = int(os.environ.get("RESET_WINDOW_MINUTES", "10"))

# Session timeout
SESSION_IDLE_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", "1"))
SESSION_ABSOLUTE_HOURS = int(os.environ.get("SESSION_ABSOLUTE_HOURS", "3"))

# DoS Protection
DOS_WARNING_THRESHOLD = int(os.environ.get("DOS_WARNING_THRESHOLD", "60"))
DOS_BLOCK_THRESHOLD = int(os.environ.get("DOS_BLOCK_THRESHOLD", "120"))
DOS_WINDOW_SECONDS = int(os.environ.get("DOS_WINDOW_SECONDS", "60"))
DOS_BLOCK_MINUTES = int(os.environ.get("DOS_BLOCK_MINUTES", "5"))

# Password reset
RESET_TOKEN_EXPIRE_MINUTES = int(os.environ.get("RESET_TOKEN_EXPIRE_MINUTES", "15"))

# Verification codes (password reset + email MFA)
VERIFICATION_CODE_EXPIRE_MINUTES = int(os.environ.get("VERIFICATION_CODE_EXPIRE_MINUTES", "10"))
VERIFICATION_CODE_MAX_ATTEMPTS = int(os.environ.get("VERIFICATION_CODE_MAX_ATTEMPTS", "5"))

# Security headers
SECURITY_HEADERS_ENABLED = os.environ.get("SECURITY_HEADERS_ENABLED", "true").lower() == "true"

# SMTP (optional; leave empty for on-screen fallback)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@uni.local")
