import os
import logging
from typing import Optional
from supabase import create_client, Client
from database_manager import get_database_manager, DatabaseType, DatabaseConnectionError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Access secrets from environment
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

# Global variables for backward compatibility
supabase: Optional[Client] = None
_backup_mode = False


def initialize_database():
    """
    Initialize database connections with fallback support
    """
    global supabase, _backup_mode

    db_manager = get_database_manager()

    try:
        # Attempt to connect with fallback logic
        if db_manager.connect():
            current_db = db_manager.get_current_db_type()

            if current_db == DatabaseType.PRIMARY:
                # Connected to primary (Supabase)
                if SUPABASE_URL and SUPABASE_KEY:
                    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
                    _backup_mode = False
                    logger.info("Connected to primary database (Supabase)")
                else:
                    logger.error("Supabase credentials not configured")
                    supabase = None
            elif current_db == DatabaseType.BACKUP:
                # Connected to backup (MariaDB)
                supabase = None
                _backup_mode = True
                logger.warning("Connected to backup database (MariaDB)")
            else:
                logger.error("Unknown database type")
                supabase = None
        else:
            logger.error("Failed to connect to any database")
            supabase = None

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        supabase = None


def get_supabase_client() -> Optional[Client]:
    """
    Get the current Supabase client, with fallback handling

    Returns:
        Client or None: Supabase client if connected to primary database
    """
    global supabase, _backup_mode

    if _backup_mode:
        logger.warning("Attempted to get Supabase client while in backup mode")
        return None

    if supabase is None:
        logger.warning("Supabase client not initialized, attempting reconnection...")
        initialize_database()

    return supabase


def is_using_backup() -> bool:
    """
    Check if currently using backup database

    Returns:
        bool: True if using backup database, False otherwise
    """
    return _backup_mode


def execute_with_fallback(operation_func, *args, **kwargs):
    """
    Execute a database operation with automatic fallback

    Args:
        operation_func: Function that performs the database operation
        *args: Positional arguments for the operation
        **kwargs: Keyword arguments for the operation

    Returns:
        Result of the operation

    Raises:
        DatabaseConnectionError: If operation fails on all databases
    """
    db_manager = get_database_manager()

    def supabase_operation(db_client, *args, **kwargs):
        if db_client is None:
            raise DatabaseConnectionError("Supabase client not available")
        return operation_func(db_client, *args, **kwargs)

    def mysql_operation(db_connection, *args, **kwargs):
        if db_connection is None:
            raise DatabaseConnectionError("MySQL connection not available")

        # Convert Supabase-style operations to MySQL
        # This is a simplified conversion - you may need to customize based on your needs
        if hasattr(operation_func, '__name__'):
            op_name = operation_func.__name__

            if 'table' in op_name and 'select' in op_name:
                # Handle table select operations
                table_name = args[0] if args else kwargs.get('table')
                if table_name:
                    with db_connection.cursor() as cursor:
                        cursor.execute(f"SELECT * FROM {table_name}")
                        return cursor.fetchall()

            elif 'insert' in op_name:
                # Handle insert operations
                table_name = args[0] if args else kwargs.get('table')
                data = args[1] if len(args) > 1 else kwargs.get('data')
                if table_name and data:
                    with db_connection.cursor() as cursor:
                        columns = ', '.join(data.keys())
                        placeholders = ', '.join(['%s'] * len(data))
                        values = tuple(data.values())
                        cursor.execute(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})", values)
                        db_connection.commit()
                        return {"data": [{"id": cursor.lastrowid}]}

        # Fallback to original function if conversion not handled
        return operation_func(db_connection, *args, **kwargs)

    return db_manager.execute_with_fallback(
        supabase_operation if not _backup_mode else mysql_operation,
        *args,
        **kwargs
    )


# Initialize database on module import
initialize_database()
