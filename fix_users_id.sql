-- Fix users table ID auto-increment
-- Run this SQL directly in your Neon database console

-- First, create sequence if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_sequences WHERE sequencename = 'users_id_seq') THEN
        CREATE SEQUENCE users_id_seq;
    END IF;
END $$;

-- Set sequence to start from next available ID
SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 0) + 1, false);

-- Make ID column use sequence as default
ALTER TABLE users ALTER COLUMN id SET DEFAULT nextval('users_id_seq');

-- Verify the fix
SELECT column_name, column_default, is_nullable, data_type 
FROM information_schema.columns 
WHERE table_name = 'users' AND column_name = 'id';
