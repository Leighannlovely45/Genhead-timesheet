<?php
// schema.php — brings any database (staging or live) up to what the code needs.
// Safe to run repeatedly: it only ADDS missing tables/columns. It never drops,
// renames or changes existing data. Runs once per SCHEMA_VERSION, then skips.

define('SCHEMA_VERSION', '2026-10-26.3');

function ensureSchema($db) {
    static $done = false;
    if ($done) return;
    $done = true;

    try { $v = $db->query("SELECT `value` FROM settings WHERE `key` = 'schema_version' LIMIT 1")->fetchColumn(); }
    catch (Exception $e) { $v = null; }
    if ($v === SCHEMA_VERSION) return;

    $exec = function ($sql) use ($db) { try { $db->exec($sql); } catch (Exception $e) { error_log('schema: ' . $e->getMessage()); } };
    $hasCol = function ($t, $c) use ($db) {
        $st = $db->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?");
        $st->execute([$t, $c]);
        return (int)$st->fetchColumn() > 0;
    };
    $hasTable = function ($t) use ($db) {
        $st = $db->prepare("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?");
        $st->execute([$t]);
        return (int)$st->fetchColumn() > 0;
    };
    $add = function ($t, $c, $def) use ($exec, $hasCol, $hasTable) {
        if ($hasTable($t) && !$hasCol($t, $c)) $exec("ALTER TABLE `$t` ADD COLUMN `$c` $def");
    };

    // ── New tables (projects & tasks) ────────────────────────────────────────
    $exec("CREATE TABLE IF NOT EXISTS projects (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        client_id INT NULL,
        client_name VARCHAR(255) NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        billing_type VARCHAR(20) NULL DEFAULT 'billable',
        due_date DATE NULL,
        description TEXT NULL,
        estimated_hours DECIMAL(8,2) NULL,
        created_by INT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )");
    $exec("CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        project_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT NULL,
        assigned_to INT NULL,
        assigned_name VARCHAR(255) NULL,
        priority VARCHAR(10) NOT NULL DEFAULT 'medium',
        stage VARCHAR(20) NOT NULL DEFAULT 'backlog',
        due_date DATE NULL,
        billing_type VARCHAR(20) NULL,
        estimated_hours DECIMAL(8,2) NULL,
        logged_hours DECIMAL(8,2) NULL,
        created_by INT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (project_id), INDEX (assigned_to)
    )");
    $exec("CREATE TABLE IF NOT EXISTS task_comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        task_id INT NOT NULL,
        user_id INT NULL,
        user_name VARCHAR(255) NULL,
        comment TEXT NOT NULL,
        is_activity TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX (task_id)
    )");
    $exec("CREATE TABLE IF NOT EXISTS task_followers (
        task_id INT NOT NULL,
        user_id INT NOT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (task_id, user_id)
    )");
    $exec("CREATE TABLE IF NOT EXISTS project_members (
        project_id INT NOT NULL,
        user_id INT NOT NULL,
        added_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (project_id, user_id)
    )");
    $exec("CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timesheet_id INT NULL,
        user_id INT NULL,
        action VARCHAR(50) NULL,
        before_state TEXT NULL,
        after_state TEXT NULL,
        ip_address VARCHAR(64) NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP
    )");
    $exec("CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        actor_id INT NULL,
        actor_name VARCHAR(255) NULL,
        kind VARCHAR(30) NOT NULL,
        task_id INT NULL,
        project_id INT NULL,
        message TEXT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        read_at DATETIME NULL,
        INDEX (user_id, id)
    )");
    $exec("CREATE TABLE IF NOT EXISTS timesheet_comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timesheet_id INT NOT NULL,
        user_id INT NULL,
        type VARCHAR(30) NULL,
        comment TEXT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX (timesheet_id)
    )");

    // ── users.role must accept every role (live had an ENUM without 'admin') ──
    try {
        $st = $db->prepare("SELECT DATA_TYPE, COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'role'");
        $st->execute();
        $rc = $st->fetch();
        if ($rc && strtolower($rc['DATA_TYPE']) === 'enum' && stripos($rc['COLUMN_TYPE'], "'admin'") === false) {
            $exec("ALTER TABLE users MODIFY role VARCHAR(20) NOT NULL DEFAULT 'employee'");
        }
    } catch (Exception $e) { error_log('schema role: ' . $e->getMessage()); }

    // ── Columns added to existing tables ─────────────────────────────────────
    $add('users', 'password_hash',  "VARCHAR(255) NULL");
    $add('users', 'password_set',   "TINYINT(1) NOT NULL DEFAULT 0");
    $add('users', 'pin_set',        "TINYINT(1) NOT NULL DEFAULT 0");
    $add('users', 'manager_id',     "INT NULL");
    $add('users', 'delegate_to',    "INT NULL");
    $add('users', 'ghl_contact_id', "VARCHAR(100) NULL");
    $add('users', 'added_from_ghl', "TINYINT(1) NOT NULL DEFAULT 0");

    $add('timesheet_entries', 'billing_type', "VARCHAR(20) NULL");
    $add('timesheet_entries', 'source',       "VARCHAR(20) NULL");
    $add('timesheet_entries', 'client_label', "VARCHAR(255) NULL");
    $add('timesheet_entries', 'project_id',   "INT NULL");
    $add('timesheet_entries', 'task_id',      "INT NULL");
    $add('timesheet_entries', 'ext_location', "VARCHAR(100) NULL");
    $add('timesheet_entries', 'ext_session',  "INT NULL");
    $add('timesheet_entries', 'ext_tracked',  "DECIMAL(10,4) NULL");
    $add('timesheet_entries', 'ext_adjust',   "DECIMAL(10,4) NOT NULL DEFAULT 0");
    $add('timesheet_entries', 'updated_at',   "TIMESTAMP NULL DEFAULT NULL");

    $add('timesheets', 'period_index', "INT NULL");
    $add('timesheets', 'period_start', "DATE NULL");
    $add('timesheets', 'period_end',   "DATE NULL");
    $add('timesheets', 'approved_by',  "INT NULL");
    $add('timesheets', 'approved_at',  "DATETIME NULL");
    $add('timesheets', 'updated_at',   "TIMESTAMP NULL DEFAULT NULL");

    $add('audit_log', 'ip_address',   "VARCHAR(64) NULL");

    $add('clients', 'type',           "VARCHAR(30) NULL");
    $add('clients', 'billable',       "TINYINT(1) NOT NULL DEFAULT 1");
    $add('clients', 'active',         "TINYINT(1) NOT NULL DEFAULT 1");
    $add('clients', 'location_id',    "VARCHAR(100) NULL");
    $add('clients', 'ghl_contact_id', "VARCHAR(100) NULL");
    $add('clients', 'plan_type',      "VARCHAR(20) NULL");
    $add('clients', 'plan_label',     "VARCHAR(100) NULL");
    $add('clients', 'monthly_hours',  "DECIMAL(8,2) NULL");

    // Legacy rows: billable=0 with no billing type were non-billable
    if ($hasCol('timesheet_entries', 'billing_type') && $hasCol('timesheet_entries', 'billable')) {
        $exec("UPDATE timesheet_entries SET billing_type = CASE WHEN billable = 0 THEN 'nonbillable' ELSE 'billable' END WHERE billing_type IS NULL");
    }

    // Lines saved with no pay rate (people saving their own timesheet sent 0): use the rate on file
    if ($hasCol('users', 'rate') && $hasCol('timesheet_entries', 'pay_rate')) {
        $exec("UPDATE timesheet_entries te JOIN timesheets t ON t.id = te.timesheet_id JOIN users u ON u.id = t.user_id
               SET te.pay_rate = u.rate WHERE (te.pay_rate IS NULL OR te.pay_rate = 0) AND u.rate > 0");
        $exec("UPDATE timesheets t JOIN users u ON u.id = t.user_id SET t.pay_rate = u.rate WHERE (t.pay_rate IS NULL OR t.pay_rate = 0) AND u.rate > 0");
        $exec("UPDATE timesheets t JOIN (SELECT timesheet_id, SUM(hours * pay_rate) AS p FROM timesheet_entries GROUP BY timesheet_id) x ON x.timesheet_id = t.id
               SET t.total_pay = x.p WHERE x.p > 0");
    }

    try {
        $db->prepare("INSERT INTO settings (`key`, `value`) VALUES ('schema_version', ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)")
           ->execute([SCHEMA_VERSION]);
    } catch (Exception $e) { error_log('schema version: ' . $e->getMessage()); }
}
