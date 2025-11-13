import mysql.connector
import hashlib
import os
import argparse
from dotenv import load_dotenv

load_dotenv()

# Config from .env file
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'scuser'),
    'password': os.getenv('DB_PASSWORD', 'scpass'),
    'database': os.getenv('DB_NAME', 'securechat')
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

def init_db():
    """Creates the users table if it doesn't exist."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt_hex CHAR(32) NOT NULL,   -- 16 bytes stored as 32 hex chars
            pwd_hash CHAR(64) NOT NULL,   -- SHA-256 hash (64 hex chars)
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        print("[+] DB Initialized: 'users' table ready.")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[-] DB Init Failed: {e}")

def hash_password(password: str, salt: bytes) -> str:
    """Returns SHA256(salt + password) as hex string."""
    return hashlib.sha256(salt + password.encode()).hexdigest()

def create_user(email, username, password_str):
    """
    1. Generate random Salt (16 bytes)
    2. Compute Hash = SHA256(Salt + Password)
    3. Store (email, username, salt_hex, hash)
    """
    salt = os.urandom(16)
    pwd_hash = hash_password(password_str, salt)
    salt_hex = salt.hex()

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, username, salt_hex, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt_hex, pwd_hash)
        )
        conn.commit()
        return True
    except mysql.connector.IntegrityError:
        return False  # User/Email already exists
    finally:
        cursor.close()
        conn.close()

def verify_user(email, password_str):
    """
    1. Fetch user by email
    2. Get stored Salt
    3. Recompute Hash
    4. Compare
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return False
    
    # Convert hex salt back to bytes
    stored_salt = bytes.fromhex(user['salt_hex'])
    stored_hash = user['pwd_hash']
    
    # Check
    computed_hash = hash_password(password_str, stored_salt)
    return computed_hash == stored_hash

if __name__ == "__main__":
    # Allow running this file directly to init the DB
    parser = argparse.ArgumentParser()
    parser.add_argument('--init', action='store_true')
    args = parser.parse_args()
    if args.init:
        init_db()