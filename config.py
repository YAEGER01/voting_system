import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default-fallback-key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Primary database (Supabase)
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")

    # Backup database (MariaDB localhost)
    BACKUP_DB_HOST = os.getenv("BACKUP_DB_HOST", "localhost")
    BACKUP_DB_PORT = int(os.getenv("BACKUP_DB_PORT", "3307"))
    BACKUP_DB_USER = os.getenv("BACKUP_DB_USER", "root")
    BACKUP_DB_PASSWORD = os.getenv("BACKUP_DB_PASSWORD", "new_password")
    BACKUP_DB_NAME = os.getenv("BACKUP_DB_NAME", "UNI_django")

    # Database connection settings
    DB_CONNECTION_TIMEOUT = int(os.getenv("DB_CONNECTION_TIMEOUT", "5"))
    DB_MAX_RETRIES = int(os.getenv("DB_MAX_RETRIES", "3"))
    DB_RETRY_DELAY = float(os.getenv("DB_RETRY_DELAY", "1.0"))

    # Fallback settings
    ENABLE_BACKUP_DB = os.getenv("ENABLE_BACKUP_DB", "true").lower() == "true"
    PREFER_PRIMARY_DB = os.getenv("PREFER_PRIMARY_DB", "true").lower() == "true"
