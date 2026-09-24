"""
UTILITIES: Helper functions and configuration

Includes:
- Database connection management
- Logging configuration
- Environment validation
- Data export utilities

Author: Senior Cybersecurity Engineer
"""

import os
import sys
from typing import Dict, Any, Optional
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from loguru import logger
from dotenv import load_dotenv


# ===== LOGGING CONFIGURATION =====

def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """
    Configure structured logging with Loguru.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for log output
    """
    logger.remove()  # Remove default handler
    
    # Console handler with colors
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level,
        colorize=True
    )
    
    # File handler (if specified)
    if log_file:
        logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level=level,
            rotation="10 MB",
            retention="30 days",
            compression="zip"
        )
    
    logger.info(f"Logging configured: level={level}")


# ===== ENVIRONMENT VALIDATION =====

def validate_environment() -> Dict[str, Any]:
    """
    Validate required environment variables and return config.
    
    Returns:
        Configuration dictionary
        
    Raises:
        ValueError: If required variables are missing
    """
    load_dotenv()
    
    required_vars = ['DATABASE_URL']
    optional_vars = {
        'NVD_API_KEY': None,
        'ANTHROPIC_API_KEY': None,
        'OLLAMA_BASE_URL': 'http://localhost:11434'
    }
    
    config = {}
    missing = []
    
    # Check required variables
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            missing.append(var)
        else:
            config[var] = value
    
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
    
    # Add optional variables
    for var, default in optional_vars.items():
        config[var] = os.getenv(var, default)
    
    logger.info("Environment validation passed")
    return config


# ===== DATABASE UTILITIES =====

class DatabaseManager:
    """
    Database connection pool manager.
    
    Usage:
        db = DatabaseManager(database_url)
        conn = db.get_connection()
        # ... use connection ...
        db.put_connection(conn)
    """
    
    def __init__(self, database_url: str, min_conn: int = 1, max_conn: int = 10):
        """
        Args:
            database_url: PostgreSQL connection string
            min_conn: Minimum connections in pool
            max_conn: Maximum connections in pool
        """
        self.pool = SimpleConnectionPool(min_conn, max_conn, database_url)
        logger.info(f"Database pool initialized: {min_conn}-{max_conn} connections")
    
    def get_connection(self):
        """Get connection from pool"""
        return self.pool.getconn()
    
    def put_connection(self, conn):
        """Return connection to pool"""
        self.pool.putconn(conn)
    
    def close_all(self):
        """Close all connections in pool"""
        self.pool.closeall()
        logger.info("Database pool closed")


def test_database_connection(database_url: str) -> bool:
    """
    Test database connectivity.
    
    Args:
        database_url: PostgreSQL connection string
        
    Returns:
        True if connection successful
    """
    try:
        conn = psycopg2.connect(database_url)
        with conn.cursor() as cursor:
            cursor.execute("SELECT version();")
            version = cursor.fetchone()[0]
            logger.info(f"Database connection successful: {version}")
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False


# ===== DATA EXPORT UTILITIES =====

def export_risk_register_to_json(database_url: str, output_path: str):
    """
    Export complete risk register to JSON for external analysis.
    
    Args:
        database_url: PostgreSQL connection string
        output_path: Output JSON file path
    """
    import json
    from datetime import datetime
    
    conn = psycopg2.connect(database_url)
    
    export_data = {
        'export_timestamp': datetime.utcnow().isoformat(),
        'assets': [],
        'vulnerabilities': [],
        'risk_analysis': [],
        'compliance_mappings': [],
        'remediation_options': [],
        'optimization_runs': []
    }
    
    try:
        with conn.cursor() as cursor:
            # Export each table
            tables = [
                ('assets', 'SELECT * FROM assets'),
                ('vulnerabilities', 'SELECT * FROM vulnerabilities'),
                ('risk_analysis', 'SELECT * FROM risk_analysis'),
                ('compliance_mappings', 'SELECT * FROM compliance_mappings'),
                ('remediation_options', 'SELECT * FROM remediation_options'),
                ('optimization_runs', 'SELECT * FROM optimization_runs')
            ]
            
            for table_name, query in tables:
                cursor.execute(query)
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                
                export_data[table_name] = [
                    dict(zip(columns, row))
                    for row in rows
                ]
                
                logger.info(f"Exported {len(rows)} rows from {table_name}")
        
        # Write to JSON
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Risk register exported to {output_path}")
        
    finally:
        conn.close()


def export_executive_summary_to_pdf(database_url: str, output_path: str):
    """
    PHASE 2: Export executive summary to PDF.
    
    Requires: reportlab library
    """
    logger.warning("PDF export is a Phase 2 feature (not implemented in MVP)")
    pass


# ===== PERFORMANCE MONITORING =====

class PerformanceTimer:
    """
    Context manager for timing code blocks.
    
    Usage:
        with PerformanceTimer("My Operation"):
            # ... code to time ...
    """
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.start_time = None
    
    def __enter__(self):
        import time
        self.start_time = time.time()
        logger.debug(f"Starting: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        elapsed = time.time() - self.start_time
        logger.info(f"✓ {self.operation_name} completed in {elapsed:.2f}s")


# ===== DATA VALIDATION =====

def validate_cvss_score(score: float) -> bool:
    """Validate CVSS score is in valid range"""
    return 0.0 <= score <= 10.0


def validate_epss_score(score: float) -> bool:
    """Validate EPSS score is in valid range"""
    return 0.0 <= score <= 1.0


def validate_cve_format(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNNN)"""
    import re
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))


# ===== MAIN =====

def main():
    """Test utilities"""
    setup_logging(level="DEBUG")
    
    try:
        config = validate_environment()
        logger.info(f"Configuration loaded: {list(config.keys())}")
        
        # Test database
        test_database_connection(config['DATABASE_URL'])
        
        logger.info("All utilities validated successfully")
        
    except Exception as e:
        logger.error(f"Utility validation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
