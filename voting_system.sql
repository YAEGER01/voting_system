-- Voting System Database Schema
-- Create database
CREATE DATABASE voting_system;
USE voting_system;

-- Create positions table
CREATE TABLE positions (
    id INT(11) NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    PRIMARY KEY (id)
);

-- Create candidates table
CREATE TABLE candidates (
    id INT(11) NOT NULL AUTO_INCREMENT,
    position_id INT(11) NOT NULL,
    name VARCHAR(100) NOT NULL,
    image VARCHAR(255) DEFAULT NULL,
    campaign_message TEXT DEFAULT NULL,
    PRIMARY KEY (id),
    KEY (position_id),
    FOREIGN KEY (position_id) REFERENCES positions(id)
);

-- Create settings table
CREATE TABLE settings (
    id INT(11) NOT NULL AUTO_INCREMENT,
    department VARCHAR(50) NOT NULL,
    voting_deadline DATETIME DEFAULT NULL,
    PRIMARY KEY (id)
);

-- Create users table
CREATE TABLE users (
    id INT(11) NOT NULL AUTO_INCREMENT,
    school_id VARCHAR(50) NOT NULL,
    course VARCHAR(100) DEFAULT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    id_photo_front VARCHAR(255) DEFAULT NULL,
    id_photo_back VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (id)
);

-- Create votes table
CREATE TABLE votes (
    id INT(11) NOT NULL AUTO_INCREMENT,
    student_id VARCHAR(50) DEFAULT NULL,
    position_id INT(11) DEFAULT NULL,
    candidate_id INT(11) DEFAULT NULL,
    department VARCHAR(100) DEFAULT NULL,
    PRIMARY KEY (id),
    KEY (student_id),
    FOREIGN KEY (student_id) REFERENCES users(school_id),
    FOREIGN KEY (position_id) REFERENCES positions(id),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id)
);