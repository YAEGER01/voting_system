#!/usr/bin/env python3
"""
MariaDB Backup Database Setup Script

This script helps set up the MariaDB backup database for the Flask application.
Run this script to create the necessary tables and configure the backup database.
"""

import os
import sys
import pymysql
from config import Config

def create_backup_database():
    """Create the backup database if it doesn't exist"""
    config = Config()

    print(f"Setting up backup database: {config.BACKUP_DB_NAME}")
    print(f"Host: {config.BACKUP_DB_HOST}:{config.BACKUP_DB_PORT}")
    print(f"User: {config.BACKUP_DB_USER}")
    print("-" * 50)

    try:
        # Connect to MySQL server (without specifying database)
        connection = pymysql.connect(
            host=config.BACKUP_DB_HOST,
            port=config.BACKUP_DB_PORT,
            user=config.BACKUP_DB_USER,
            password=config.BACKUP_DB_PASSWORD,
            connect_timeout=10
        )

        with connection.cursor() as cursor:
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config.BACKUP_DB_NAME}")
            print(f"✓ Database '{config.BACKUP_DB_NAME}' created or already exists")

        connection.close()
        return True

    except Exception as e:
        print(f"✗ Failed to create database: {e}")
        return False


def create_tables():
    """Create necessary tables in the backup database"""
    config = Config()

    try:
        # Connect to the specific database
        connection = pymysql.connect(
            host=config.BACKUP_DB_HOST,
            port=config.BACKUP_DB_PORT,
            user=config.BACKUP_DB_USER,
            password=config.BACKUP_DB_PASSWORD,
            database=config.BACKUP_DB_NAME,
            connect_timeout=10,
            autocommit=True
        )

        with connection.cursor() as cursor:
            # Create user table (equivalent to Supabase user table)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    school_id VARCHAR(50) UNIQUE NOT NULL,
                    department VARCHAR(100),
                    course VARCHAR(100),
                    course_code VARCHAR(50),
                    track VARCHAR(50),
                    year_level VARCHAR(20),
                    section VARCHAR(20),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    phone VARCHAR(20),
                    role VARCHAR(50) DEFAULT 'user',
                    active VARCHAR(20) DEFAULT 'OFFLINE',
                    id_photo_front TEXT,
                    id_photo_back TEXT,
                    reset_token VARCHAR(255),
                    reset_token_expiry DATETIME,
                    reset_otp VARCHAR(10),
                    reset_otp_expiry DATETIME,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            print("✓ Created user table")

            # Create pending_users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pending_users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    school_id VARCHAR(50) UNIQUE NOT NULL,
                    department VARCHAR(100),
                    course VARCHAR(100),
                    course_code VARCHAR(50),
                    track VARCHAR(50),
                    year_level VARCHAR(20),
                    section VARCHAR(20),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_plain VARCHAR(255) NOT NULL,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    phone VARCHAR(20),
                    id_photo_front TEXT,
                    id_photo_back TEXT,
                    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("✓ Created pending_users table")

            # Create positions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS positions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    department VARCHAR(100) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("✓ Created positions table")

            # Create candidates table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS candidates (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    position_id INT NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    image TEXT,
                    campaign_message TEXT,
                    department VARCHAR(100) NOT NULL,
                    year_level VARCHAR(20),
                    course VARCHAR(100),
                    skills TEXT,
                    platform TEXT,
                    goals TEXT,
                    sg_years VARCHAR(10),
                    previous_role TEXT,
                    experience TEXT,
                    achievements TEXT,
                    slogan TEXT,
                    note TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE
                )
            """)
            print("✓ Created candidates table")

            # Create votes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS votes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_id VARCHAR(50) NOT NULL,
                    position_id INT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_ref INT NOT NULL,
                    department VARCHAR(100) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE
                )
            """)
            print("✓ Created votes table")

            # Create logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    action VARCHAR(255) NOT NULL,
                    table_name VARCHAR(100),
                    query_type VARCHAR(50),
                    target TEXT,
                    new_data TEXT,
                    old_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE SET NULL
                )
            """)
            print("✓ Created logs table")

            # Create settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    department VARCHAR(100) NOT NULL,
                    start_time DATETIME,
                    end_time DATETIME,
                    filing_start DATETIME,
                    filing_end DATETIME,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_department (department)
                )
            """)
            print("✓ Created settings table")

            # Create dashboard_status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_status (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    dashboard_name VARCHAR(100) UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("✓ Created dashboard_status table")

            # Insert default dashboard statuses
            cursor.execute("""
                INSERT IGNORE INTO dashboard_status (dashboard_name, is_active) VALUES
                ('ssc_dashboard', TRUE),
                ('dashboard', TRUE),
                ('classroom_dashboard', TRUE)
            """)
            print("✓ Inserted default dashboard statuses")

        connection.close()
        print("\n✓ All tables created successfully!")
        return True

    except Exception as e:
        print(f"✗ Failed to create tables: {e}")
        return False


def create_classroom_tables():
    """Create classroom-specific tables"""
    config = Config()

    try:
        connection = pymysql.connect(
            host=config.BACKUP_DB_HOST,
            port=config.BACKUP_DB_PORT,
            user=config.BACKUP_DB_USER,
            password=config.BACKUP_DB_PASSWORD,
            database=config.BACKUP_DB_NAME,
            connect_timeout=10,
            autocommit=True
        )

        with connection.cursor() as cursor:
            # Create classroom_settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS classroom_settings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    course VARCHAR(100) NOT NULL,
                    year_level VARCHAR(20) NOT NULL,
                    section VARCHAR(20) NOT NULL,
                    track VARCHAR(50) NOT NULL,
                    start_time DATETIME,
                    end_time DATETIME,
                    filing_start DATETIME,
                    filing_end DATETIME,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_classroom (course, year_level, section, track)
                )
            """)
            print("✓ Created classroom_settings table")

            # Create classroom_positions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS classroom_positions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    course VARCHAR(100) NOT NULL,
                    year_level VARCHAR(20) NOT NULL,
                    section VARCHAR(20) NOT NULL,
                    track VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("✓ Created classroom_positions table")

            # Create classroom_candidates table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS classroom_candidates (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    position_id INT NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    image TEXT,
                    campaign_message TEXT,
                    course VARCHAR(100) NOT NULL,
                    year_level VARCHAR(20) NOT NULL,
                    section VARCHAR(20) NOT NULL,
                    track VARCHAR(50) NOT NULL,
                    skills TEXT,
                    platform TEXT,
                    goals TEXT,
                    sg_years VARCHAR(10),
                    previous_role TEXT,
                    experience TEXT,
                    achievements TEXT,
                    slogan TEXT,
                    note TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (position_id) REFERENCES classroom_positions(id) ON DELETE CASCADE
                )
            """)
            print("✓ Created classroom_candidates table")

            # Create classroom_votes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS classroom_votes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_id VARCHAR(50) NOT NULL,
                    position_id INT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_ref INT NOT NULL,
                    course VARCHAR(100) NOT NULL,
                    year_level VARCHAR(20) NOT NULL,
                    section VARCHAR(20) NOT NULL,
                    track VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (position_id) REFERENCES classroom_positions(id) ON DELETE CASCADE
                )
            """)
            print("✓ Created classroom_votes table")

        connection.close()
        print("✓ Classroom tables created successfully!")
        return True

    except Exception as e:
        print(f"✗ Failed to create classroom tables: {e}")
        return False


def main():
    """Main setup function"""
    print("🔧 MariaDB Backup Database Setup")
    print("=" * 50)

    # Step 1: Create database
    if not create_backup_database():
        print("\n❌ Database setup failed!")
        return 1

    # Step 2: Create main tables
    print("\n📋 Creating main tables...")
    if not create_tables():
        print("\n❌ Table creation failed!")
        return 1

    # Step 3: Create classroom tables
    print("\n🏫 Creating classroom tables...")
    if not create_classroom_tables():
        print("\n❌ Classroom table creation failed!")
        return 1

    # Step 4: Success message
    print("\n" + "=" * 50)
    print("🎉 Backup database setup completed successfully!")
    print("=" * 50)
    print("\n📝 Next steps:")
    print("1. Update your environment variables with backup database credentials")
    print("2. Set ENABLE_BACKUP_DB=true to enable backup database")
    print("3. Run 'python test_backup_db.py' to test the connection")
    print("4. Restart your Flask application")

    print("\n🔧 Environment variables to set:")
    print(f"BACKUP_DB_HOST={os.getenv('BACKUP_DB_HOST', 'localhost')}")
    print(f"BACKUP_DB_PORT={os.getenv('BACKUP_DB_PORT', '3306')}")
    print(f"BACKUP_DB_USER={os.getenv('BACKUP_DB_USER', 'root')}")
    print("BACKUP_DB_PASSWORD=<your_mysql_password>")
    print(f"BACKUP_DB_NAME={os.getenv('BACKUP_DB_NAME', 'univote_backup')}")
    print("ENABLE_BACKUP_DB=true"

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)