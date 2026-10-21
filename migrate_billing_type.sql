-- Add billing_type column to timesheet_entries
-- Run this once in phpMyAdmin or via MySQL CLI

ALTER TABLE timesheet_entries
  ADD COLUMN billing_type VARCHAR(20) NOT NULL DEFAULT 'billable'
  AFTER billable;

-- Backfill existing rows based on billable flag
UPDATE timesheet_entries SET billing_type = 'billable'    WHERE billable = 1;
UPDATE timesheet_entries SET billing_type = 'nonbillable' WHERE billable = 0;
