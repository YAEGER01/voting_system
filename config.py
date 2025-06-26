import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default-fallback-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("SUPABASE_DB_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
