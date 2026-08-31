import os

class Config:
    SECRET_KEY = "vulnlab-insecure-key-12345"
    SQLALCHEMY_DATABASE_URI = "sqlite:///vulnlab.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECURITY_LEVEL = os.environ.get("SECURITY_LEVEL", "LOW").upper()

    A04_HARDcoded_KEY = "super-secret-key-do-not-share"
    A04_WEAK_JWT_SECRET = "jwt-secret"

    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = "Lax"
