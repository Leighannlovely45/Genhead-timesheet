-- Migration: Add hashed password columns and admin role support
-- Run this in phpMyAdmin on the genhead_timesheet database BEFORE deploying the new code

-- 1. Add password_hash column (stores bcrypt hash for manager/hr/admin)
ALTER TABLE users
  ADD COLUMN password_hash VARCHAR(255) DEFAULT NULL AFTER password;

-- 2. Add password_set flag (1 = user has set their own password)
ALTER TABLE users
  ADD COLUMN password_set TINYINT(1) NOT NULL DEFAULT 0 AFTER password_hash;

-- 3. Allow 'admin' as a valid role value
-- (Only needed if role column uses ENUM; skip if it's VARCHAR)
-- ALTER TABLE users MODIFY COLUMN role ENUM('employee','manager','hr','admin') NOT NULL DEFAULT 'employee';

-- 4. (Optional) Add Leighann as admin user — update the name/email as needed
-- INSERT INTO users (name, email, role, password_set, status)
-- VALUES ('Leighann Lovely', 'Leighann.lovely@genhead.com', 'admin', 0, 'active');
-- (password_set=0 means she'll be prompted to create her password on first login)

-- Verify the columns were added:
-- DESCRIBE users;
