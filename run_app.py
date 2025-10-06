#!/usr/bin/env python3
"""
Flask Application Runner for Windows

This script runs the Flask application using the built-in development server,
which is perfect for testing the backup database functionality on Windows.
"""

import os
import sys
from app import app
from database_manager import get_database_manager
from config import Config

def test_database_connections():
    """Test both primary and backup database connections"""
    print("🧪 Testing Database Connections...")
    print("-" * 50)

    db_manager = get_database_manager()
    config = Config()

    # Test primary database (Supabase)
    print("Testing Primary Database (Supabase)...")
    if config.SUPABASE_URL and config.SUPABASE_KEY:
        try:
            if db_manager._connect_primary():
                print("✅ Primary database connection successful")
            else:
                print("❌ Primary database connection failed")
        except Exception as e:
            print(f"❌ Primary database error: {e}")
    else:
        print("⚠️  Primary database credentials not configured")

    # Test backup database (MariaDB)
    print("\nTesting Backup Database (MariaDB)...")
    if config.ENABLE_BACKUP_DB:
        try:
            if db_manager._connect_backup():
                print("✅ Backup database connection successful")

                # Test a simple query
                mysql_conn = db_manager.get_mysql_connection()
                if mysql_conn:
                    with mysql_conn.cursor() as cursor:
                        cursor.execute("SELECT 1 as test")
                        result = cursor.fetchone()
                        if result and result[0] == 1:
                            print("✅ Backup database test query successful")
                        else:
                            print("❌ Backup database test query failed")
            else:
                print("❌ Backup database connection failed")
        except Exception as e:
            print(f"❌ Backup database error: {e}")
    else:
        print("⚠️  Backup database is disabled")

    # Test fallback logic
    print("\nTesting Fallback Logic...")
    try:
        db_manager._primary_client = None
        db_manager._backup_connection = None
        db_manager._current_db_type = None

        if db_manager.connect():
            current_db = db_manager.get_current_db_type()
            print(f"✅ Fallback logic working - Connected to: {current_db.value}")
        else:
            print("❌ Fallback logic failed")
    except Exception as e:
        print(f"❌ Fallback logic error: {e}")

    print("-" * 50)

def main():
    """Main function to run the Flask app"""
    print("🚀 Starting UNIVOTE Flask Application with Backup Database Support")
    print("=" * 70)

    # Test database connections first
    test_database_connections()

    print("\n📋 Application Configuration:")
    print(f"Debug Mode: {app.debug}")
    print(f"Host: 0.0.0.0")
    print(f"Port: 5000")
    print(f"Backup DB Enabled: {os.getenv('ENABLE_BACKUP_DB', 'true')}")
    print(f"Prefer Primary DB: {os.getenv('PREFER_PRIMARY_DB', 'true')}")

    print("\n🌐 Starting Flask development server...")
    print("📝 Note: The backup database system will automatically activate if Supabase fails")
    print("🔗 Access your app at: http://localhost:5000")
    print("⚡ Press Ctrl+C to stop the server")
    print("=" * 70)

    try:
        # Run Flask development server on port 5000 (Django is using 8000)
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=True
        )
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
    except Exception as e:
        print(f"\n❌ Error running application: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)