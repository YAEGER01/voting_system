# config.py

class Config:
    SECRET_KEY = 'your-secret-key'  # For sessions, CSRF, etc.
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:loleris1234@localhost/voting_system'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
