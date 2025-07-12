
import os
import psycopg2
import psycopg2.extras
import hashlib
import secrets
from werkzeug.security import generate_password_hash


# Postgres-only connection
DATABASE_URL = os.environ.get("DATABASE_URL")
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


# No init_db or migration helpers needed for Postgres (handled by migrations or manually)


# No migration helpers needed for Postgres


# m3u8_cache helpers
def get_m3u8_url(tmdb_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT m3u8_url FROM m3u8_cache WHERE tmdb_id=%s", (tmdb_id,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result["m3u8_url"]
    return None

def save_url(tmdb_id, url):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO m3u8_cache (tmdb_id, m3u8_url) VALUES (%s, %s) ON CONFLICT (tmdb_id) DO UPDATE SET m3u8_url = EXCLUDED.m3u8_url",
        (tmdb_id, url)
    )
    conn.commit()
    conn.close()

def get_all_cached_urls():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT tmdb_id, m3u8_url FROM m3u8_cache")
    results = c.fetchall()
    conn.close()
    return {row["tmdb_id"]: row["m3u8_url"] for row in results}
# ---------------- User Auth ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_api_key():
    return secrets.token_hex(32)

from werkzeug.security import generate_password_hash

def create_user(user_data, password, is_admin=False):
    conn = get_db_connection()
    hashed_password = generate_password_hash(password)
    api_key = secrets.token_hex(32)
    is_admin_bool = True if is_admin else False
    from datetime import datetime
    now = datetime.utcnow().isoformat()
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash, api_key, is_admin, is_verified, otp_code, otp_expires_at, plan, requests_today, last_request_date, account_created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_data["name"],
                user_data["email"],
                hashed_password,
                api_key,
                is_admin_bool,
                False,
                user_data.get("otp_code"),
                user_data.get("otp_expires_at"),
                user_data.get("plan", "free"),
                0,
                None,
                now
            )
        )
        conn.commit()
        print(f"✅ User created successfully: {user_data['email']}")
    except psycopg2.errors.UniqueViolation as e:
        conn.rollback()
        print(f"❌ User creation failed - email already exists: {user_data['email']}")
        raise ValueError("User with this email already exists")
    except Exception as e:
        conn.rollback()
        print(f"❌ User creation failed: {e}")
        raise
    finally:
        conn.close()
# Get user by email
def get_user_by_email(email):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = c.fetchone()
    conn.close()
    return user
# Get all users (admin only)
def get_all_users():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, email, api_key, is_admin, plan, requests_today, last_request_date, account_created_at FROM users ORDER BY id ASC")
    users = c.fetchall()
    conn.close()
    return users


def authenticate_user(email, password_hash):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT api_key FROM users WHERE email=%s AND password_hash=%s", (email, password_hash))
    row = c.fetchone()
    conn.close()
    return row["api_key"] if row else None

# Get user by username
def get_user_by_username(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE name = %s", (username,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = c.fetchone()
    conn.close()
    return user


def is_valid_api_key(api_key):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE api_key=%s", (api_key,))
    result = c.fetchone()
    conn.close()
    return result is not None

# Regenerate API key for a user
def regenerate_api_key(user_id):
    import secrets
    conn = get_db_connection()
    new_key = secrets.token_hex(32)
    c = conn.cursor()
    c.execute("UPDATE users SET api_key = %s WHERE id = %s", (new_key, user_id))
    conn.commit()
    conn.close()
    return new_key

# Plan limits
PLAN_LIMITS = {
    "free": 100,
    "plus": 1000,
    "pro": 10000
}

# Check and increment rate limit for a user
from datetime import datetime
def check_and_increment_rate_limit(user):
    today = datetime.utcnow().strftime("%Y-%m-%d")
    requests_today = user["requests_today"]
    last_request_date = user["last_request_date"]
    if last_request_date != today:
        requests_today = 0
        last_request_date = today
    limit = PLAN_LIMITS.get(user["plan"], 100)
    if requests_today >= limit:
        return False, limit
    # Increment
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE users SET requests_today = %s, last_request_date = %s WHERE id = %s",
        (requests_today + 1, today, user["id"])
    )
    conn.commit()
    conn.close()
    return True, limit