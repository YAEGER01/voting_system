"""
Database Connection Manager with Fallback Support

This module provides a robust database connection system that:
1. Attempts to connect to the primary database (Supabase)
2. Falls back to backup database (MariaDB) if primary fails
3. Provides connection health checks and retry logic
4. Maintains consistent interface for database operations
"""

import time
import logging
from typing import Optional, Dict, Any, Tuple
from contextlib import contextmanager
from enum import Enum

import pymysql
from supabase import create_client, Client
from config import Config


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Database type enumeration"""
    PRIMARY = "primary"
    BACKUP = "backup"


class DatabaseConnectionError(Exception):
    """Custom exception for database connection errors"""
    pass


class DatabaseManager:
    """
    Manages database connections with fallback support
    """

    def __init__(self):
        self.config = Config()
        self._primary_client: Optional[Client] = None
        self._backup_connection: Optional[pymysql.Connection] = None
        self._current_db_type: Optional[DatabaseType] = None
        self._connection_attempts = 0
        self._last_successful_connection = 0

    def _connect_primary(self) -> bool:
        """
        Attempt to connect to primary database (Supabase)

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if not self.config.SUPABASE_URL or not self.config.SUPABASE_KEY:
                logger.warning("Primary database credentials not configured")
                return False

            self._primary_client = create_client(
                self.config.SUPABASE_URL,
                self.config.SUPABASE_KEY
            )

            # Test the connection
            self._primary_client.table("user").select("*").limit(1).execute()
            self._current_db_type = DatabaseType.PRIMARY
            self._connection_attempts = 0
            self._last_successful_connection = time.time()
            logger.info("Successfully connected to primary database (Supabase)")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to primary database: {e}")
            self._primary_client = None
            return False

    def _connect_backup(self) -> bool:
        """
        Attempt to connect to backup database (MariaDB)

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if not self.config.ENABLE_BACKUP_DB:
                logger.warning("Backup database is disabled")
                return False

            self._backup_connection = pymysql.connect(
                host=self.config.BACKUP_DB_HOST,
                port=self.config.BACKUP_DB_PORT,
                user=self.config.BACKUP_DB_USER,
                password=self.config.BACKUP_DB_PASSWORD,
                database=self.config.BACKUP_DB_NAME,
                connect_timeout=self.config.DB_CONNECTION_TIMEOUT,
                autocommit=True
            )

            self._current_db_type = DatabaseType.BACKUP
            self._connection_attempts = 0
            self._last_successful_connection = time.time()
            logger.info("Successfully connected to backup database (MariaDB)")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to backup database: {e}")
            self._backup_connection = None
            return False

    def connect(self) -> bool:
        """
        Establish database connection with fallback logic

        Returns:
            bool: True if any connection successful, False if all failed
        """
        # Try primary database first if preferred
        if self.config.PREFER_PRIMARY_DB:
            if self._connect_primary():
                return True
            logger.warning("Primary database connection failed, trying backup...")

        # Try backup database
        if self._connect_backup():
            return True

        # If backup also failed and we prefer primary, try primary again
        if self.config.PREFER_PRIMARY_DB:
            if self._connect_primary():
                return True

        logger.error("All database connections failed")
        return False

    def is_connected(self) -> bool:
        """
        Check if currently connected to any database

        Returns:
            bool: True if connected, False otherwise
        """
        if self._current_db_type == DatabaseType.PRIMARY:
            return self._primary_client is not None
        elif self._current_db_type == DatabaseType.BACKUP:
            return self._backup_connection is not None and not self._backup_connection.closed
        return False

    def get_current_db_type(self) -> Optional[DatabaseType]:
        """
        Get the currently active database type

        Returns:
            DatabaseType or None: Current database type or None if not connected
        """
        return self._current_db_type

    def _check_primary_health(self) -> bool:
        """
        Check if primary database is healthy

        Returns:
            bool: True if healthy, False otherwise
        """
        if not self._primary_client:
            return False

        try:
            self._primary_client.table("user").select("*").limit(1).execute()
            return True
        except Exception:
            return False

    def _check_backup_health(self) -> bool:
        """
        Check if backup database is healthy

        Returns:
            bool: True if healthy, False otherwise
        """
        if not self._backup_connection or self._backup_connection.closed:
            return False

        try:
            with self._backup_connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return True
        except Exception:
            return False

    def check_health(self) -> Tuple[bool, Optional[DatabaseType]]:
        """
        Check health of current connection and attempt fallback if needed

        Returns:
            Tuple[bool, DatabaseType]: (is_healthy, current_db_type)
        """
        if not self.is_connected():
            logger.warning("No active database connection")
            return False, None

        current_type = self._current_db_type

        if current_type == DatabaseType.PRIMARY:
            if self._check_primary_health():
                return True, DatabaseType.PRIMARY
            else:
                logger.warning("Primary database unhealthy, attempting fallback...")
                if self._connect_backup():
                    return True, DatabaseType.BACKUP
                return False, None

        elif current_type == DatabaseType.BACKUP:
            if self._check_backup_health():
                return True, DatabaseType.BACKUP
            else:
                logger.warning("Backup database unhealthy, attempting fallback...")
                if self._connect_primary():
                    return True, DatabaseType.PRIMARY
                return False, None

        return False, None

    def get_supabase_client(self) -> Optional[Client]:
        """
        Get the Supabase client if connected to primary database

        Returns:
            Client or None: Supabase client or None if not connected to primary
        """
        if self._current_db_type == DatabaseType.PRIMARY:
            return self._primary_client
        return None

    def get_mysql_connection(self) -> Optional[pymysql.Connection]:
        """
        Get the MySQL connection if connected to backup database

        Returns:
            Connection or None: MySQL connection or None if not connected to backup
        """
        if self._current_db_type == DatabaseType.BACKUP:
            return self._backup_connection
        return None

    def execute_with_fallback(self, operation_func, *args, **kwargs) -> Any:
        """
        Execute a database operation with automatic fallback

        Args:
            operation_func: Function that takes a database connection as first argument
            *args: Additional positional arguments for the operation
            **kwargs: Additional keyword arguments

        Returns:
            Any: Result of the operation

        Raises:
            DatabaseConnectionError: If all database connections fail
        """
        max_retries = self.config.DB_MAX_RETRIES
        retry_delay = self.config.DB_RETRY_DELAY

        for attempt in range(max_retries):
            try:
                # Ensure we have a connection
                if not self.is_connected():
                    if not self.connect():
                        raise DatabaseConnectionError("Failed to establish database connection")

                # Check connection health
                is_healthy, db_type = self.check_health()
                if not is_healthy:
                    raise DatabaseConnectionError("Database connection unhealthy")

                # Execute the operation
                if self._current_db_type == DatabaseType.PRIMARY:
                    return operation_func(self._primary_client, *args, **kwargs)
                elif self._current_db_type == DatabaseType.BACKUP:
                    return operation_func(self._backup_connection, *args, **kwargs)
                else:
                    raise DatabaseConnectionError("Unknown database type")

            except Exception as e:
                logger.warning(f"Database operation failed (attempt {attempt + 1}/{max_retries}): {e}")

                # Try to reconnect and retry
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    # Force reconnection attempt
                    self._primary_client = None
                    self._backup_connection = None
                    self._current_db_type = None
                    continue

                raise DatabaseConnectionError(f"All database operations failed after {max_retries} attempts: {e}")

    def close(self):
        """Close all database connections"""
        if self._primary_client:
            # Supabase client doesn't need explicit closing
            self._primary_client = None

        if self._backup_connection and not self._backup_connection.closed:
            self._backup_connection.close()
            self._backup_connection = None

        self._current_db_type = None
        logger.info("All database connections closed")

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Global database manager instance
db_manager = DatabaseManager()


def get_database_manager() -> DatabaseManager:
    """
    Get the global database manager instance

    Returns:
        DatabaseManager: Global database manager instance
    """
    return db_manager


@contextmanager
def get_database_connection():
    """
    Context manager for database connections with automatic fallback

    Usage:
        with get_database_connection() as db:
            if db.get_current_db_type() == DatabaseType.PRIMARY:
                # Use Supabase operations
                result = db.get_supabase_client().table("users").select("*").execute()
            else:
                # Use MySQL operations
                with db.get_mysql_connection().cursor() as cursor:
                    cursor.execute("SELECT * FROM users")
                    result = cursor.fetchall()
    """
    try:
        yield db_manager
    finally:
        pass  # Connection cleanup handled by DatabaseManager