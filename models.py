# models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.String(50), nullable=False)
    course = db.Column(db.String(100))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    role = db.Column(db.String(20), nullable=False, default='user')
    id_photo_front = db.Column(db.String(255))
    id_photo_back = db.Column(db.String(255))

class Position(db.Model):
    __tablename__ = 'positions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    candidates = db.relationship('Candidate', back_populates='position', lazy=True)

class Candidate(db.Model):
    __tablename__ = 'candidates'
    id = db.Column(db.Integer, primary_key=True)
    position_id = db.Column(db.Integer, db.ForeignKey('positions.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(255))
    campaign_message = db.Column(db.Text)
    position = db.relationship('Position', back_populates='candidates')

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(50), nullable=False)
    voting_deadline = db.Column(db.DateTime)

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50))  # not a foreign key, but linked by value
    position_id = db.Column(db.Integer)
    candidate_id = db.Column(db.Integer)
    department = db.Column(db.String(100))