"""
Database operations and models for the visitor tracking application.
Handles PostgreSQL connections and all database CRUD operations.
"""

import os
import json
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras

# Database connection
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    """Get database connection"""
    if not DATABASE_URL:
        return None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    if not conn:
        print("Database not configured, skipping initialization")
        return

    try:
        cursor = conn.cursor()

        # Create visitors table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS visitors (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                city TEXT,
                region TEXT,
                country TEXT,
                org TEXT,
                asn TEXT,
                asn_info TEXT,
                vpn TEXT,
                chain TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add asn_info column if it doesn't exist (for existing databases)
        try:
            cursor.execute("ALTER TABLE visitors ADD COLUMN IF NOT EXISTS asn_info TEXT")
            conn.commit()
        except Exception as e:
            print(f"Column addition warning: {e}")

        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_hash TEXT NOT NULL,
                geo_password_lat DOUBLE PRECISION,
                geo_password_lng DOUBLE PRECISION,
                network_org TEXT,
                network_asn TEXT,
                network_ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                email_verified BOOLEAN DEFAULT FALSE,
                phone_verified BOOLEAN DEFAULT FALSE
            )
        """)

        # Create pending_registrations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                geo_password_lat DOUBLE PRECISION,
                geo_password_lng DOUBLE PRECISION,
                email_code TEXT NOT NULL,
                sms_code TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)

        # Create system_config table for geographic challenges and other system settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                id SERIAL PRIMARY KEY,
                config_key TEXT UNIQUE NOT NULL,
                config_value JSONB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Insert default Granny's driveway configuration if it doesn't exist
        cursor.execute("""
            INSERT INTO system_config (config_key, config_value)
            VALUES ('granny_driveway', %s)
            ON CONFLICT (config_key) DO NOTHING
        """, [json.dumps({
            'lat': 39.14662374973502,
            'lng': -93.88223955845123,
            'name': "Granny's Driveway",
            'country': "United States",
            'tolerance_meters': 20.0
        })])

        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

# Visitor operations
def db_save_visitor(ip, city=None, region=None, country=None, org=None, asn=None, asn_info=None, vpn=None, chain=None):
    """Save visitor data to database"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO visitors (ip, city, region, country, org, asn, asn_info, vpn, chain)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (ip, city, region, country, org, asn, asn_info, vpn, chain))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database visitor save error: {e}")
        return False

# User operations
def db_create_user(email, phone, password_hash, geo_lat, geo_lng, network_org, network_asn, network_ip):
    """Create a new user in the database"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (email, phone, password_hash, geo_password_lat, geo_password_lng,
                             network_org, network_asn, network_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (email, phone, password_hash, geo_lat, geo_lng, network_org, network_asn, network_ip))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database user creation error: {e}")
        return False

def db_get_user_by_email(email):
    """Get user data by email from database"""
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        print(f"Database user lookup error: {e}")
        return None

def db_update_user_login(email):
    """Update user's last login timestamp"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = %s", (email,))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database login update error: {e}")
        return False

def db_check_user_exists(email):
    """Check if user exists"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        exists = cursor.fetchone() is not None
        cursor.close()
        conn.close()
        return exists
    except Exception as e:
        print(f"Database user existence check error: {e}")
        return False

# System config operations
def db_get_system_config(config_key):
    """Get system configuration value"""
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", (config_key,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return result['config_value']
        return None
    except Exception as e:
        print(f"Database system config lookup error: {e}")
        return None

def db_set_system_config(config_key, config_value):
    """Set system configuration value"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO system_config (config_key, config_value)
            VALUES (%s, %s)
            ON CONFLICT (config_key) DO UPDATE SET
                config_value = EXCLUDED.config_value,
                updated_at = CURRENT_TIMESTAMP
        """, (config_key, json.dumps(config_value)))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database system config update error: {e}")
        return False

# Pending registration operations
def db_save_pending_registration(email, phone, geo_lat, geo_lng, email_code, sms_code, expires_at):
    """Save pending registration"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pending_registrations (email, phone, geo_password_lat, geo_password_lng,
                                             email_code, sms_code, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (email, phone, geo_lat, geo_lng, email_code, sms_code, expires_at))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database pending registration save error: {e}")
        return False

def db_get_pending_registration(email):
    """Get pending registration by email"""
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM pending_registrations WHERE email = %s", (email,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return dict(result) if result else None
    except Exception as e:
        print(f"Database pending registration lookup error: {e}")
        return None

def db_delete_pending_registration(email):
    """Delete pending registration"""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pending_registrations WHERE email = %s", (email,))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database pending registration delete error: {e}")
        return False</content>
<parameter name="filePath">/Users/robertlober/Documents/Deploy to Render/database.py