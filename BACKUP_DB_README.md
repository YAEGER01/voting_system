# Flask App Backup Database System

This Flask application now includes a robust backup database connection system that automatically falls back to a local MariaDB database when the primary Supabase database is unavailable.

## Features

- **Automatic Fallback**: Seamlessly switches to backup database when primary fails
- **Connection Health Monitoring**: Continuously monitors database connections
- **Retry Logic**: Automatically retries failed operations with configurable delays
- **Comprehensive Logging**: Detailed logs for troubleshooting and monitoring
- **Backward Compatibility**: Existing code continues to work without changes

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Flask App     │────│ Database Manager │────│   Supabase      │
│                 │    │                  │    │   (Primary)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   MariaDB        │
                       │   (Backup)       │
                       └──────────────────┘
```

## Configuration

### Environment Variables

Add these environment variables to your `.env` file or deployment environment:

```bash
# Primary Database (Supabase)
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key

# Backup Database (MariaDB)
BACKUP_DB_HOST=localhost
BACKUP_DB_PORT=3306
BACKUP_DB_USER=root
BACKUP_DB_PASSWORD=your_mysql_password
BACKUP_DB_NAME=univote_backup

# Backup System Settings
ENABLE_BACKUP_DB=true
PREFER_PRIMARY_DB=true
DB_CONNECTION_TIMEOUT=5
DB_MAX_RETRIES=3
DB_RETRY_DELAY=1.0
```

### Configuration Options

| Variable                | Default          | Description                           |
| ----------------------- | ---------------- | ------------------------------------- |
| `BACKUP_DB_HOST`        | `localhost`      | MariaDB server hostname               |
| `BACKUP_DB_PORT`        | `3306`           | MariaDB server port                   |
| `BACKUP_DB_USER`        | `root`           | MariaDB username                      |
| `BACKUP_DB_PASSWORD`    | `""`             | MariaDB password                      |
| `BACKUP_DB_NAME`        | `univote_backup` | MariaDB database name                 |
| `ENABLE_BACKUP_DB`      | `true`           | Enable/disable backup database        |
| `PREFER_PRIMARY_DB`     | `true`           | Prefer primary DB when both available |
| `DB_CONNECTION_TIMEOUT` | `5`              | Connection timeout in seconds         |
| `DB_MAX_RETRIES`        | `3`              | Maximum retry attempts                |
| `DB_RETRY_DELAY`        | `1.0`            | Delay between retries in seconds      |

## Setup Instructions

### 1. Install MariaDB

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install mariadb-server
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

**CentOS/RHEL:**

```bash
sudo yum install mariadb-server
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

**macOS (using Homebrew):**

```bash
brew install mariadb
brew services start mariadb
```

**Windows:**
Download and install MariaDB from [mariadb.com](https://mariadb.com/downloads/)

### 2. Configure MariaDB

```bash
# Connect to MariaDB
sudo mysql -u root

# Create database and user
CREATE DATABASE univote_backup;
CREATE USER 'backup_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON univote_backup.* TO 'backup_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. Set Environment Variables

Update your environment variables with the MariaDB connection details:

```bash
export BACKUP_DB_HOST="localhost"
export BACKUP_DB_PORT="3306"
export BACKUP_DB_USER="backup_user"
export BACKUP_DB_PASSWORD="your_secure_password"
export BACKUP_DB_NAME="univote_backup"
export ENABLE_BACKUP_DB="true"
```

### 4. Run Setup Script

```bash
python setup_backup_db.py
```

This script will:

- Create the backup database (if it doesn't exist)
- Create all necessary tables
- Set up proper indexes and relationships

### 5. Test the Setup

```bash
python test_backup_db.py
```

This will test:

- Primary database connection
- Backup database connection
- Fallback logic
- Database operations

## Usage

### Basic Usage

The backup system works automatically. Your existing code continues to work without changes:

```python
from supabase_client import supabase

# This will automatically use backup DB if Supabase fails
try:
    result = supabase.table("user").select("*").execute()
except Exception as e:
    print(f"Database operation failed: {e}")
```

### Advanced Usage

For more control, use the database manager directly:

```python
from database_manager import get_database_manager, DatabaseType

db_manager = get_database_manager()

# Check current database type
current_db = db_manager.get_current_db_type()
print(f"Currently using: {current_db.value}")

# Execute operations with fallback
def my_operation(db_client):
    return db_client.table("users").select("*").execute()

result = db_manager.execute_with_fallback(my_operation)
```

### Manual Fallback

Force a specific database connection:

```python
db_manager = get_database_manager()

# Force backup database
if db_manager._connect_backup():
    print("Using backup database")
else:
    print("Backup database not available")
```

## Database Schema

The backup database mirrors the Supabase schema with these main tables:

### Core Tables

- `user` - User accounts and profiles
- `pending_users` - Users awaiting approval
- `positions` - Election positions
- `candidates` - Election candidates
- `votes` - Vote records
- `logs` - System activity logs
- `settings` - System configuration

### Classroom Tables

- `classroom_settings` - Classroom-specific settings
- `classroom_positions` - Classroom election positions
- `classroom_candidates` - Classroom election candidates
- `classroom_votes` - Classroom vote records

### System Tables

- `dashboard_status` - Dashboard activation status

## Monitoring and Troubleshooting

### Check Database Status

```python
from database_manager import get_database_manager

db_manager = get_database_manager()
print(f"Connected: {db_manager.is_connected()}")
print(f"Current DB: {db_manager.get_current_db_type()}")
```

### View Logs

The system logs all database operations and fallback events:

```
INFO - Connected to primary database (Supabase)
WARNING - Primary database unhealthy, attempting fallback...
INFO - Successfully connected to backup database (MariaDB)
ERROR - Failed to connect to backup database: Access denied
```

### Common Issues

**1. Connection Timeout**

```
ERROR - Failed to connect to backup database: (2003, "Can't connect to MySQL server on 'localhost'")
```

**Solution**: Check if MariaDB is running and accessible

**2. Authentication Failed**

```
ERROR - Failed to connect to backup database: Access denied for user 'root'@'localhost'
```

**Solution**: Verify username and password in environment variables

**3. Database Not Found**

```
ERROR - Failed to connect to backup database: Unknown database 'univote_backup'
```

**Solution**: Run the setup script to create the database

## Performance Considerations

- **Connection Pooling**: The system creates new connections as needed
- **Health Checks**: Regular health checks may add slight overhead
- **Retry Delays**: Failed operations are retried with delays
- **Memory Usage**: Backup connections are properly closed when not in use

## Security Best Practices

1. **Use Strong Passwords**: Always use secure passwords for database access
2. **Limit Permissions**: Create dedicated users with minimal required permissions
3. **Network Security**: Restrict database access to localhost or trusted networks
4. **Environment Variables**: Never hardcode credentials in source code

## Migration from Supabase

If you need to migrate data from Supabase to MariaDB:

1. Export data from Supabase
2. Use the setup script to create tables
3. Import data using standard MySQL tools
4. Test thoroughly before switching

## Support

For issues and questions:

1. Check the logs for detailed error messages
2. Run the test script to diagnose connection issues
3. Verify environment variables are set correctly
4. Ensure MariaDB is running and accessible

## Example Deployment

### Docker Compose Example

```yaml
version: "3.8"
services:
  web:
    build: .
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_KEY=${SUPABASE_KEY}
      - BACKUP_DB_HOST=mariadb
      - BACKUP_DB_PASSWORD=${BACKUP_DB_PASSWORD}
      - ENABLE_BACKUP_DB=true
    depends_on:
      - mariadb

  mariadb:
    image: mariadb:10.11
    environment:
      - MYSQL_ROOT_PASSWORD=${BACKUP_DB_PASSWORD}
      - MYSQL_DATABASE=univote_backup
    volumes:
      - mariadb_data:/var/lib/mysql

volumes:
  mariadb_data:
```

This setup provides a complete backup database solution that ensures your Flask application remains available even when the primary database experiences issues.
