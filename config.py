import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-session-key-change-in-production")

# Detect Vercel environment: Vercel serverless filesystem is read-only except /tmp
if os.environ.get("VERCEL"):
    DATABASE_PATH = "/tmp/secure_exam.db"
    UPLOAD_FOLDER = "/tmp/secure_vault"
else:
    DATABASE_PATH = os.path.join(BASE_DIR, "secure_exam.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "secure_vault")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Master Key for AES-256-GCM (32 bytes)
MASTER_KEY = os.environ.get("MASTER_KEY", "01234567890123456789012345678901").encode("utf-8")