import os
import secrets
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Database configuration
SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
if not SQLALCHEMY_DATABASE_URI:
    # Fallback to in-memory SQLite if no database URL is provided
    SQLALCHEMY_DATABASE_URI = "sqlite:///security_app.db"

# Flask configuration
SECRET_KEY = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
DEBUG = True
TESTING = False

# JWT configuration
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
JWT_ACCESS_TOKEN_EXPIRES = 30 * 60  # 30 minutes in seconds
JWT_REFRESH_TOKEN_EXPIRES = 30 * 24 * 60 * 60  # 30 days in seconds

# Security settings
PASSWORD_MIN_LENGTH = 10
FAILED_LOGIN_ATTEMPTS = 5  # Number of failed attempts before account lockout
LOCKOUT_TIME = 15 * 60  # 15 minutes in seconds
SESSION_TIMEOUT = 30 * 60  # 30 minutes in seconds

# TOTP configuration
TOTP_ISSUER = "Zero Trust Auth System"
QR_CODE_ENDPOINT = "/auth/qrcode/"

# Roles and permissions
ROLES = {
    "admin": ["read", "write", "delete", "manage_users", "view_logs", "manage_system"],
    "user": ["read", "write", "delete_own"],
    "readonly": ["read"]
}

# IP Whitelist/Blacklist
IP_WHITELIST = os.environ.get("IP_WHITELIST", "").split(",") if os.environ.get("IP_WHITELIST") else []
IP_BLACKLIST = os.environ.get("IP_BLACKLIST", "").split(",") if os.environ.get("IP_BLACKLIST") else []
