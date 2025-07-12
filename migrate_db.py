#!/usr/bin/env python3
"""
Database Migration: Fix users table ID auto-increment
"""

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def fix_users_table():
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if not DATABASE_URL:
        print("❌ DATABASE_URL not found in environment")
        return
    
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        print("🔍 Checking current users table structure...")
        
        # Check if users table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            );
        """)
        
        table_exists = cursor.fetchone()[0]
        
        if not table_exists:
            print("📝 Creating users table with proper auto-increment...")
            cursor.execute("""
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    api_key VARCHAR(64) UNIQUE NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    is_verified BOOLEAN DEFAULT FALSE,
                    otp_code VARCHAR(10),
                    otp_expires_at TIMESTAMP,
                    plan VARCHAR(50) DEFAULT 'free',
                    requests_today INTEGER DEFAULT 0,
                    last_request_date DATE,
                    account_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            print("✅ Users table created successfully!")
        else:
            print("📝 Users table exists. Checking ID column...")
            
            # Check if ID column is auto-increment
            cursor.execute("""
                SELECT column_default 
                FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'id';
            """)
            
            result = cursor.fetchone()
            if result and 'nextval' in str(result[0]):
                print("✅ ID column is already auto-incrementing")
            else:
                print("🔧 Fixing ID column to be auto-incrementing...")
                
                # Create sequence if it doesn't exist
                cursor.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT 1 FROM pg_sequences WHERE sequencename = 'users_id_seq') THEN
                            CREATE SEQUENCE users_id_seq;
                        END IF;
                    END $$;
                """)
                
                # Set the sequence to start from max existing ID + 1
                cursor.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM users;")
                next_id = cursor.fetchone()[0]
                
                cursor.execute(f"ALTER SEQUENCE users_id_seq RESTART WITH {next_id};")
                
                # Make ID column use the sequence
                cursor.execute("""
                    ALTER TABLE users 
                    ALTER COLUMN id SET DEFAULT nextval('users_id_seq');
                """)
                
                print(f"✅ ID column fixed! Next ID will be: {next_id}")
        
        # Check/create m3u8_cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS m3u8_cache (
                tmdb_id INTEGER PRIMARY KEY,
                m3u8_url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        conn.commit()
        print("✅ Database migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    fix_users_table()
