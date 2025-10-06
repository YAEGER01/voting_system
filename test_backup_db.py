#!/usr/bin/env python3
"""
Test script for backup database connection functionality

This script tests the backup MariaDB connection and fallback logic.
Run this script to verify that the backup database system is working correctly.
"""

import os
import sys
import logging
from typing import Dict, Any

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database_manager import get_database_manager, DatabaseType, DatabaseConnectionError
from config import Config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_config():
    """Test configuration loading"""
    logger.info("Testing configuration...")

    config = Config()

    logger.info(f"Primary DB (Supabase) URL: {'Set' if config.SUPABASE_URL else 'Not set'}")
    logger.info(f"Primary DB (Supabase) Key: {'Set' if config.SUPABASE_KEY else 'Not set'}")
    logger.info(f"Backup DB Host: {config.BACKUP_DB_HOST}")
    logger.info(f"Backup DB Port: {config.BACKUP_DB_PORT}")
    logger.info(f"Backup DB User: {config.BACKUP_DB_USER}")
    logger.info(f"Backup DB Name: {config.BACKUP_DB_NAME}")
    logger.info(f"Backup DB Enabled: {config.ENABLE_BACKUP_DB}")
    logger.info(f"Prefer Primary DB: {config.PREFER_PRIMARY_DB}")

    return True


def test_primary_connection(db_manager) -> bool:
    """Test primary database connection"""
    logger.info("Testing primary database connection...")

    try:
        # Try to connect to primary only
        if db_manager._connect_primary():
            logger.info("✓ Primary database connection successful")
            return True
        else:
            logger.warning("✗ Primary database connection failed")
            return False
    except Exception as e:
        logger.error(f"✗ Primary database connection error: {e}")
        return False


def test_backup_connection(db_manager) -> bool:
    """Test backup database connection"""
    logger.info("Testing backup database connection...")

    try:
        # Close any existing connections first
        db_manager._primary_client = None
        db_manager._backup_connection = None
        db_manager._current_db_type = None

        # Try to connect to backup only
        if db_manager._connect_backup():
            logger.info("✓ Backup database connection successful")

            # Test a simple query
            mysql_conn = db_manager.get_mysql_connection()
            if mysql_conn:
                with mysql_conn.cursor() as cursor:
                    cursor.execute("SELECT 1 as test")
                    result = cursor.fetchone()
                    if result and result[0] == 1:
                        logger.info("✓ Backup database test query successful")
                        return True
                    else:
                        logger.error("✗ Backup database test query failed")
                        return False
            else:
                logger.error("✗ Could not get MySQL connection")
                return False
        else:
            logger.warning("✗ Backup database connection failed")
            return False
    except Exception as e:
        logger.error(f"✗ Backup database connection error: {e}")
        return False


def test_fallback_logic(db_manager) -> bool:
    """Test fallback logic"""
    logger.info("Testing fallback logic...")

    try:
        # Close all connections
        db_manager._primary_client = None
        db_manager._backup_connection = None
        db_manager._current_db_type = None

        # Test full connection with fallback
        if db_manager.connect():
            current_db = db_manager.get_current_db_type()
            logger.info(f"✓ Connected to database via fallback logic: {current_db.value}")

            # Test health check
            is_healthy, db_type = db_manager.check_health()
            if is_healthy:
                logger.info(f"✓ Database health check passed: {db_type.value}")
                return True
            else:
                logger.error("✗ Database health check failed")
                return False
        else:
            logger.error("✗ Fallback connection failed")
            return False
    except Exception as e:
        logger.error(f"✗ Fallback logic error: {e}")
        return False


def test_database_operations(db_manager) -> bool:
    """Test basic database operations"""
    logger.info("Testing database operations...")

    try:
        def test_operation_supabase(client):
            """Test Supabase operation"""
            return client.table("user").select("*").limit(1).execute()

        def test_operation_mysql(connection):
            """Test MySQL operation"""
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 as test_value")
                return cursor.fetchall()

        # Test operation with fallback
        result = db_manager.execute_with_fallback(
            test_operation_supabase if db_manager.get_current_db_type() == DatabaseType.PRIMARY else test_operation_mysql
        )

        if result:
            logger.info("✓ Database operation successful")
            return True
        else:
            logger.error("✗ Database operation returned no results")
            return False

    except Exception as e:
        logger.error(f"✗ Database operation error: {e}")
        return False


def create_test_tables():
    """Create test tables in backup database if they don't exist"""
    logger.info("Creating test tables in backup database...")

    db_manager = get_database_manager()

    try:
        # Connect to backup database
        if not db_manager._connect_backup():
            logger.error("Cannot connect to backup database for table creation")
            return False

        mysql_conn = db_manager.get_mysql_connection()
        if not mysql_conn:
            logger.error("No MySQL connection available")
            return False

        with mysql_conn.cursor() as cursor:
            # Create test user table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_user (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    school_id VARCHAR(50) UNIQUE NOT NULL,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create test logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    action VARCHAR(255) NOT NULL,
                    table_name VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES test_user(id)
                )
            """)

            mysql_conn.commit()
            logger.info("✓ Test tables created successfully")
            return True

    except Exception as e:
        logger.error(f"✗ Failed to create test tables: {e}")
        return False


def main():
    """Main test function"""
    logger.info("Starting backup database connection tests...")

    # Test 1: Configuration
    if not test_config():
        logger.error("Configuration test failed")
        return 1

    # Initialize database manager
    db_manager = get_database_manager()

    # Test 2: Primary connection (if credentials available)
    primary_success = test_primary_connection(db_manager)

    # Test 3: Backup connection
    backup_success = test_backup_connection(db_manager)

    # Test 4: Fallback logic
    fallback_success = test_fallback_logic(db_manager)

    # Test 5: Database operations
    operations_success = test_database_operations(db_manager)

    # Test 6: Create test tables
    tables_success = create_test_tables()

    # Summary
    logger.info("\n" + "="*50)
    logger.info("TEST SUMMARY")
    logger.info("="*50)
    logger.info(f"Primary DB Connection: {'✓ PASS' if primary_success else '✗ FAIL'}")
    logger.info(f"Backup DB Connection:  {'✓ PASS' if backup_success else '✗ FAIL'}")
    logger.info(f"Fallback Logic:        {'✓ PASS' if fallback_success else '✗ FAIL'}")
    logger.info(f"Database Operations:   {'✓ PASS' if operations_success else '✗ FAIL'}")
    logger.info(f"Test Tables:           {'✓ PASS' if tables_success else '✗ FAIL'}")

    # Overall result
    all_passed = all([primary_success or backup_success, fallback_success, operations_success, tables_success])

    if all_passed:
        logger.info("\n🎉 All tests passed! Backup database system is working correctly.")
        return 0
    else:
        logger.error("\n❌ Some tests failed. Please check the configuration and database setup.")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)