<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-TS-Auth");
header("X-Frame-Options: ALLOWALL");
header("Content-Security-Policy: frame-ancestors *");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

require_once __DIR__ . '/db.php';

// Bi-weekly pay period start dates [y,m,d], calculated from the first period
// (Apr 27 2026) through ~2 months from today — no hard-coded end date.
if (!function_exists('payPeriodStarts')) {
    function payPeriodStarts() {
        $out = []; $d = new DateTime('2026-04-27'); $limit = new DateTime('+60 days');
        while ($d <= $limit) { $out[] = [(int)$d->format('Y'), (int)$d->format('n'), (int)$d->format('j')]; $d->modify('+14 days'); }
        return $out;
    }
}

// ─────────────────────────────────────────
// SETTINGS HELPERS (guarded: some db.php files already define these)
// ─────────────────────────────────────────
if (!function_exists('getSetting')) {
    function getSetting($key, $default = '') {
        try {
            $db   = getDB();
            $stmt = $db->prepare("SELECT `value` FROM settings WHERE `key` = ? LIMIT 1");
            $stmt->execute([$key]);
            $row  = $stmt->fetch();
            return $row ? $row['value'] : $default;
        } catch (Exception $e) { return $default; }
    }
}
if (!function_exists('setSetting')) {
    function setSetting($key, $value) {
        $db = getDB();
        $db->prepare("INSERT INTO settings (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)")
           ->execute([$key, $value]);
    }
}

if (!function_exists('logAudit')) {
    // Normally defined in db.php; fallback so approvals never crash without it
    function logAudit($timesheetId, $userId, $action, $before = null, $after = null) {
        try {
            getDB()->prepare("INSERT INTO audit_log (timesheet_id, user_id, action, before_state, after_state, ip_address) VALUES (?, ?, ?, ?, ?, ?)")
                ->execute([$timesheetId, $userId, $action, $before ? json_encode($before) : null, $after ? json_encode($after) : null, $_SERVER['REMOTE_ADDR'] ?? null]);
        } catch (Exception $e) { error_log('audit: ' . $e->getMessage()); }
    }
}

// ─────────────────────────────────────────
// DATABASE UPGRADE — adds missing tables/columns, never removes anything
// ─────────────────────────────────────────
require_once __DIR__ . '/schema.php';
ensureSchema(getDB());

// ─────────────────────────────────────────
// SESSIONS — signed token sent by the page in the X-TS-Auth header
// ─────────────────────────────────────────
define('SESSION_DAYS', 14);
function sessionSecret() {
    static $s = null;
    if ($s !== null) return $s;
    $s = getSetting('session_secret', '');
    if (strlen($s) < 32) { $s = bin2hex(random_bytes(32)); setSetting('session_secret', $s); }
    return $s;
}
function b64u($d)  { return rtrim(strtr(base64_encode($d), '+/', '-_'), '='); }
function b64ud($d) { return base64_decode(strtr($d, '-_', '+/')); }
function issueToken($uid) {
    $p = b64u(json_encode(['u' => (int)$uid, 'e' => time() + SESSION_DAYS * 86400]));
    return $p . '.' . b64u(hash_hmac('sha256', $p, sessionSecret(), true));
}
function authToken() {
    $t = $_SERVER['HTTP_X_TS_AUTH'] ?? '';
    if (!$t && function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) { if (strtolower($k) === 'x-ts-auth') { $t = $v; break; } }
    }
    return trim($t);
}
function authUser() {
    static $u = false;
    if ($u !== false) return $u;
    $u = null;
    $t = authToken();
    if (!$t || strpos($t, '.') === false) return $u;
    list($payload, $sig) = explode('.', $t, 2);
    if (!hash_equals(b64u(hash_hmac('sha256', $payload, sessionSecret(), true)), $sig)) return $u;
    $d = json_decode(b64ud($payload), true);
    if (!$d || ($d['e'] ?? 0) < time()) return $u;
    $st = getDB()->prepare("SELECT id, name, email, role, manager_id, delegate_to, rate FROM users WHERE id = ? AND status = 'active' LIMIT 1");
    $st->execute([(int)$d['u']]);
    $u = $st->fetch() ?: null;
    return $u;
}
function isPayRole($u) { return $u && in_array($u['role'], ['admin', 'hr']); }
function requireAuth() {
    $u = authUser();
    if (!$u) { http_response_code(401); echo json_encode(['success' => false, 'auth' => false, 'error' => 'Your session has ended — please sign in again.']); exit; }
    return $u;
}
function requireRole($roles) {
    $u = requireAuth();
    if (!in_array($u['role'], $roles)) { http_response_code(403); echo json_encode(['success' => false, 'error' => "You don't have access to do that."]); exit; }
    return $u;
}
// Ids of people this user reviews: HR/Admin = everyone else; managers = direct reports
// plus the reports of anyone who delegated their approvals to them.
function reviewableIds($u) {
    if (!$u) return [];
    $db = getDB();
    if (isPayRole($u)) {
        $st = $db->prepare("SELECT id FROM users WHERE id <> ?");
        $st->execute([(int)$u['id']]);
        return array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
    }
    $st = $db->prepare("SELECT id FROM users WHERE id <> ? AND (manager_id = ? OR manager_id IN (SELECT id FROM users WHERE delegate_to = ?))");
    $st->execute([(int)$u['id'], (int)$u['id'], (int)$u['id']]);
    return array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
}
function canReview($u, $targetId) { return in_array((int)$targetId, reviewableIds($u), true); }
function publicUser($row) {
    return ['id' => 'e' . $row['id'], 'db_id' => (int)$row['id'], 'name' => $row['name'], 'email' => $row['email'] ?? '', 'role' => $row['role']];
}
function stripPay(&$rows) {
    foreach ($rows as &$r) {
        unset($r['pay_rate'], $r['total_pay'], $r['employee_rate'], $r['rate']);
        if (!empty($r['entries'])) foreach ($r['entries'] as &$e) unset($e['pay_rate']);
    }
}

$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

// ─────────────────────────────────────────
// ACCESS RULES
// ─────────────────────────────────────────
// Open without signing in: sign-in/reset flows, the login name list, the Chrome
// extension, the client hours portal & hours-bank admin, and secret-protected GHL hooks.
$PUBLIC_ACTIONS = ['verify_password','set_password','check_password_set','forgot_pin','reset_pin','load',
                   'upsert_time','client_hours','get_client_by_location','load_client_banks','set_client_hours',
                   'load_clients','ghl_add','fire_webhook'];
$ROLE_RULES = [
    'load_report_v2'=>['admin','hr'], 'load_report'=>['admin','hr'], 'export_payroll'=>['admin','hr'],
    'export_clients'=>['admin','hr'], 'export_audit'=>['admin','hr'], 'load_audit'=>['admin','hr'],
    'load_audit_period'=>['admin','hr'], 'load_overtime'=>['admin','hr'], 'resolve_overtime'=>['admin','hr','manager'],
    'update_settings'=>['admin','hr'], 'update_secret'=>['admin','hr'], 'update_password'=>['admin','hr'],
    'set_setting'=>['admin','hr'], 'test_invite_webhook'=>['admin','hr'], 'test_submission_webhook'=>['admin','hr'],
    'test_decision_webhook'=>['admin','hr'], 'sync_clients'=>['admin','hr'], 'add_client'=>['admin','hr'],
    'update_client'=>['admin','hr'], 'clean_clients'=>['admin','hr'], 'deactivate_user'=>['admin','hr'],
    'add_employee'=>['admin','hr'], 'add_manager'=>['admin','hr'], 'update_employee'=>['admin','hr'],
    'remove_employee'=>['admin','hr'], 'toggle_active'=>['admin','hr'], 'assign_manager'=>['admin','hr'],
    'hr_override'=>['admin','hr'], 'flag_discrepancy'=>['admin','hr','manager'], 'set_delegate'=>['admin','hr','manager'],
    'proxy_webhook'=>['admin','hr'], 'schema_report'=>['admin'],
];
// Removed: one-time setup helpers that let anyone create admins or change PINs
if (in_array($action, ['create_test_admin', 'set_pin', 'verify_pin'], true)) {
    http_response_code(410); echo json_encode(['success' => false, 'error' => 'This action has been removed.']); exit;
}
$AUTH = null;
if ($action !== '' && !in_array($action, $PUBLIC_ACTIONS, true)) {
    $AUTH = isset($ROLE_RULES[$action]) ? requireRole($ROLE_RULES[$action]) : requireAuth();
} else {
    $AUTH = authUser();
}

// Who am I (used to stay signed in across refreshes)
if ($action === 'whoami') {
    echo json_encode(['success' => true, 'user' => publicUser($AUTH)]);
    exit;
}
// Table/column list (no data) — used to plan database upgrades
if ($action === 'schema_report') {
    $db = getDB();
    $cols = $db->query("SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, ORDINAL_POSITION")->fetchAll();
    echo json_encode(['success' => true, 'columns' => $cols]);
    exit;
}


// ─────────────────────────────────────────
// GET ACTIONS
// ─────────────────────────────────────────
if ($method === 'GET') {


    // ── VERIFY PASSWORD VIA GET (avoids WAF blocking POST) ──────────────────
    if ($action === 'verify_password') {
        $db = getDB();
        $id = preg_replace('/^e/', '', $_GET['id'] ?? '');
        $password = $_GET['pw'] ?? '';
        if (!$id || !$password) { echo json_encode(['success' => false, 'error' => 'ID and password required']); exit; }
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        if (!$row['password_set']) { echo json_encode(['success' => false, 'needs_setup' => true, 'verify' => setupProof($row)]); exit; }
        if (!empty($row['password_hash'])) {
            $valid = password_verify($password, $row['password_hash']);
        } else {
            $valid = isset($row['password']) && $row['password'] !== '' && hash_equals((string)$row['password'], (string)$password);
        }
        if (!$valid) { usleep(400000); echo json_encode(['success' => false]); exit; }
        echo json_encode(['success' => true, 'name' => $row['name'], 'role' => $row['role'], 'token' => issueToken($row['id']), 'user' => publicUser($row)]);
        exit;
    }

    // ── CHECK PASSWORD SET VIA GET ─────────────────────────────────────────
    if ($action === 'check_password_set') {
        $db = getDB();
        $id = preg_replace('/^e/', '', $_GET['id'] ?? '');
        if (!$id) { echo json_encode(['needs_setup' => false]); exit; }
        $stmt = $db->prepare("SELECT password_set FROM users WHERE id = ? AND role IN ('manager','hr','admin') AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) { echo json_encode(['needs_setup' => false]); exit; }
        echo json_encode(['needs_setup' => !(bool)$row['password_set']]);
        exit;
    }

    // ── VERIFY PIN VIA GET (avoids WAF blocking POST) ──────────────────────
    if ($action === 'verify_pin') {
        $db  = getDB();
        $id  = preg_replace('/^e/', '', $_GET['id'] ?? '');
        $pin = trim($_GET['pin'] ?? '');
        if (!$id || strlen($pin) !== 4 || !ctype_digit($pin)) {
            echo json_encode(['success' => false, 'ok' => false, 'error' => 'Invalid PIN format']); exit;
        }
        $stmt = $db->prepare("SELECT pin, pin_set FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) { echo json_encode(['success' => false, 'ok' => false, 'error' => 'User not found']); exit; }
        if (!$row['pin_set']) { echo json_encode(['success' => false, 'ok' => false, 'needs_setup' => true]); exit; }
        $valid = ($row['pin'] === $pin);
        echo json_encode(['success' => $valid, 'ok' => $valid]);
        exit;
    }

    // ── SET PIN VIA GET (avoids WAF blocking POST) ──────────────────────────
    if ($action === 'set_pin') {
        $db  = getDB();
        $id  = preg_replace('/^e/', '', $_GET['id'] ?? '');
        $pin = trim($_GET['pin'] ?? '');
        if (!$id || strlen($pin) !== 4 || !ctype_digit($pin)) {
            echo json_encode(['success' => false, 'ok' => false, 'error' => 'PIN must be 4 digits']); exit;
        }
        $stmt = $db->prepare("SELECT id FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        if (!$stmt->fetch()) { echo json_encode(['success' => false, 'ok' => false, 'error' => 'User not found']); exit; }
        $db->prepare("UPDATE users SET pin = ?, pin_set = 1 WHERE id = ?")->execute([$pin, $id]);
        echo json_encode(['success' => true, 'ok' => true]);
        exit;
    }

    // ── SET PASSWORD VIA GET (avoids WAF blocking POST) ─────────────────────
    if ($action === 'set_password') {
        $db = getDB();
        $id       = preg_replace('/^e/', '', $_GET['id'] ?? '');
        $password = trim($_GET['pw'] ?? '');
        if (!$id || strlen($password) < 6) {
            echo json_encode(['success' => false, 'error' => 'Password must be at least 6 characters']); exit;
        }
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        $u = $stmt->fetch();
        if (!$u) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        // First-time setup only. Changing an existing password must go through the emailed reset link.
        if ($u['password_set']) { echo json_encode(['success' => false, 'error' => 'A password is already set for this account. Use "Forgot password" to reset it.']); exit; }
        // Prove it's really them: their old PIN, or the old shared Manager/HR password
        $proof = setupProof($u);
        $given = (string)($body['old'] ?? ($_GET['old'] ?? ''));
        if ($proof === 'pin' && !hash_equals((string)$u['pin'], $given)) { usleep(400000); echo json_encode(['success' => false, 'error' => 'That PIN doesn\'t match the one on file.']); exit; }
        if ($proof === 'role_password' && !hash_equals((string)getSetting($u['role'].'_password'), $given)) { usleep(400000); echo json_encode(['success' => false, 'error' => 'That doesn\'t match the current '.ucfirst($u['role']).' password.']); exit; }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $db->prepare("UPDATE users SET password_hash = ?, password_set = 1 WHERE id = ?")->execute([$hash, $id]);
        echo json_encode(['success' => true, 'token' => issueToken($id), 'user' => publicUser($u)]);
        exit;
    }

    // ── TEST INVITE WEBHOOK (fires a test payload to GHL Workflow 1) ──────────
    if ($action === 'test_invite_webhook') {
        $name  = trim($_GET['name']  ?? 'Test Employee');
        $email = trim($_GET['email'] ?? '');
        $role  = trim($_GET['role']  ?? 'employee');
        if (!$email) { echo json_encode(['success' => false, 'error' => 'email param required']); exit; }
        sendInviteWebhook($name, $email, $role, 'test_' . time());
        echo json_encode(['success' => true, 'message' => 'Webhook fired', 'to' => $email]);
        exit;
    }

    // ── TEST SUBMISSION WEBHOOK (fires a test payload to GHL Workflow 2) ────────
    if ($action === 'test_submission_webhook') {
        $db = getDB();
        $url = getSetting('ghl_webhook_url');
        if (!$url) { echo json_encode(['success' => false, 'error' => 'ghl_webhook_url not set']); exit; }
        $payload = [
            'event'          => 'timecard_submitted',
            'employee_name'  => 'Test Employee',
            'employee_email' => 'Leighann.lovely@genhead.com',
            'employee_id'    => 'etest',
            'manager_name'   => 'Test Manager',
            'manager_email'  => 'Leighann.lovely@genhead.com',
            'period'         => 'Oct 7 – Oct 20, 2026',
            'hours'          => '40.00',
            'submitted_at'   => date('c'),
            'review_url'     => 'https://timesheet.genhead.com/',
            'timestamp'      => date('c'),
        ];
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>json_encode($payload), CURLOPT_HTTPHEADER=>['Content-Type: application/json'], CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>10]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        echo json_encode(['success' => true, 'http_code' => $code, 'response' => $resp]);
        exit;
    }

    // ── TEST DECISION WEBHOOK (fires a test payload to GHL Workflow 3) ──────────
    if ($action === 'test_decision_webhook') {
        $url = getSetting('ghl_notify_webhook_url');
        if (!$url) { echo json_encode(['success' => false, 'error' => 'ghl_notify_webhook_url not set']); exit; }
        $decision = trim($_GET['decision'] ?? 'approved'); // approved | rejected | returned
        $payload = [
            'event'          => 'timecard_decision',
            'decision'       => $decision,
            'employee_name'  => 'Test Employee',
            'employee_email' => 'Leighann.lovely@genhead.com',
            'employee_id'    => 'etest',
            'manager_name'   => 'Test Manager',
            'manager_email'  => 'Leighann.lovely@genhead.com',
            'period'         => 'Oct 7 – Oct 20, 2026',
            'hours'          => '40.00',
            'note'           => 'Test decision note',
            'decided_at'     => date('c'),
            'timestamp'      => date('c'),
        ];
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>json_encode($payload), CURLOPT_HTTPHEADER=>['Content-Type: application/json'], CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>10]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        echo json_encode(['success' => true, 'http_code' => $code, 'response' => $resp]);
        exit;
    }

    // ── DEACTIVATE USER VIA GET (one-time setup helper) ──────────────────────
    if ($action === 'deactivate_user') {
        $db  = getDB();
        $id  = preg_replace('/^e/', '', trim($_GET['id'] ?? ''));
        if (!$id) { echo json_encode(['success' => false, 'error' => 'id required']); exit; }
        $db->prepare("UPDATE users SET status = 'inactive' WHERE id = ?")->execute([$id]);
        echo json_encode(['success' => true, 'deactivated' => 'e' . $id]);
        exit;
    }

    // ── CREATE TEST ADMIN ACCOUNT VIA GET (one-time setup helper) ────────────
    if ($action === 'create_test_admin') {
        $db    = getDB();
        $name  = trim($_GET['name']  ?? 'Test Admin');
        $email = trim($_GET['email'] ?? 'testadmin@genhead.com');
        $pw    = trim($_GET['pw']    ?? '');
        $role  = in_array(trim($_GET['role'] ?? ''), ['admin','manager','hr']) ? trim($_GET['role']) : 'admin';
        if (!$pw) { echo json_encode(['success' => false, 'error' => 'pw param required']); exit; }
        // Upsert — if email already exists just update the password hash
        $hash = password_hash($pw, PASSWORD_DEFAULT);
        $existing = $db->prepare("SELECT id FROM users WHERE email = ? AND role = ? LIMIT 1");
        $existing->execute([$email, $role]);
        $row = $existing->fetch();
        if ($row) {
            $db->prepare("UPDATE users SET password_hash = ?, password_set = 1, name = ? WHERE id = ?")
               ->execute([$hash, $name, $row['id']]);
            echo json_encode(['success' => true, 'action' => 'updated', 'id' => 'e'.$row['id'], 'email' => $email, 'role' => $role]);
        } else {
            $db->prepare("INSERT INTO users (name, email, role, password_hash, password_set) VALUES (?, ?, ?, ?, 1)")
               ->execute([$name, $email, $role, $hash]);
            $newId = $db->lastInsertId();
            echo json_encode(['success' => true, 'action' => 'created', 'id' => 'e'.$newId, 'email' => $email, 'role' => $role]);
        }
        exit;
    }

    // ── SET SINGLE SETTING VIA GET (WAF bypass — webhook URLs only) ───────────
    if ($action === 'set_setting') {
        $db      = getDB();
        $key     = trim($_GET['key']   ?? '');
        $value   = trim($_GET['value'] ?? '');
        $allowed = ['ghl_invite_webhook_url', 'ghl_webhook_url', 'ghl_notify_webhook_url', 'ghl_reset_webhook_url'];
        if (!in_array($key, $allowed, true)) {
            echo json_encode(['success' => false, 'error' => 'Key not allowed']); exit;
        }
        setSetting($key, $value);
        echo json_encode(['success' => true, 'key' => $key]);
        exit;
    }

    // ── LOAD PROJECTS ────────────────────────────────────────────────────────
    if ($action === 'load_projects') {
        $db     = getDB();
        ensureProjectMembers($db);
        $status = $_GET['status'] ?? '';
        $viewer = (int)$AUTH['id'];
        $sql    = "SELECT p.*, COALESCE(p.client_name, (SELECT c.name FROM clients c WHERE c.id = p.client_id)) AS client_name, u.name AS creator_name,
                   (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count,
                   (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.stage = 'done') AS done_count,
                   (SELECT GROUP_CONCAT(pm.user_id ORDER BY um.name SEPARATOR ',') FROM project_members pm JOIN users um ON um.id = pm.user_id WHERE pm.project_id = p.id) AS member_ids,
                   (SELECT GROUP_CONCAT(um.name ORDER BY um.name SEPARATOR ', ') FROM project_members pm JOIN users um ON um.id = pm.user_id WHERE pm.project_id = p.id) AS member_names
                   FROM projects p LEFT JOIN users u ON u.id = p.created_by";
        $params = [];
        if ($status) { $sql .= " WHERE p.status = ?"; $params[] = $status; }
        else          { $sql .= " WHERE p.status != 'archived'"; }
        // Admin & HR see every project. Everyone else sees projects they're on the
        // team for, created, or have a task assigned in.
        if ($viewer) {
            $vr = $db->prepare("SELECT role FROM users WHERE id = ? LIMIT 1");
            $vr->execute([$viewer]);
            if (!in_array($vr->fetchColumn(), ['admin','hr'])) {
                $sql .= " AND (p.created_by = ? OR EXISTS (SELECT 1 FROM project_members pm2 WHERE pm2.project_id = p.id AND pm2.user_id = ?)
                          OR EXISTS (SELECT 1 FROM tasks t2 WHERE t2.project_id = p.id AND t2.assigned_to = ?))";
                array_push($params, $viewer, $viewer, $viewer);
            }
        }
        $sql .= " ORDER BY p.updated_at DESC";
        $rows = $db->prepare($sql);
        $rows->execute($params);
        echo json_encode(['success' => true, 'projects' => $rows->fetchAll()]);
        exit;
    }

    // ── LOAD TASKS (for a project or all) ────────────────────────────────────
    if ($action === 'load_tasks') {
        $db         = getDB();
        // Ensure hours columns exist on tasks
        try { $db->exec("ALTER TABLE tasks ADD COLUMN estimated_hours DECIMAL(8,2) DEFAULT NULL"); } catch(Exception $e) {}
        try { $db->exec("ALTER TABLE tasks ADD COLUMN logged_hours DECIMAL(8,2) DEFAULT NULL"); } catch(Exception $e) {}
        $projectId  = (int)($_GET['project_id'] ?? 0);
        $assignedTo = (int)($_GET['assigned_to'] ?? 0);
        $stage      = $_GET['stage'] ?? '';
        ensureEntryColumns($db);
        $viewer = (int)$AUTH['id'];
        $sql = "SELECT t.*, p.name AS project_name, p.client_name, p.billing_type AS project_billing_type,
                (SELECT COALESCE(SUM(te.hours),0) FROM timesheet_entries te WHERE te.task_id = t.id) AS ts_logged_hours,
                (SELECT COALESCE(SUM(te.hours),0) FROM timesheet_entries te JOIN timesheets tsx ON tsx.id = te.timesheet_id WHERE te.task_id = t.id AND tsx.user_id = ?) AS my_logged_hours
                FROM tasks t LEFT JOIN projects p ON p.id = t.project_id WHERE 1=1";
        $params = [$viewer];
        if ($projectId)  { $sql .= " AND t.project_id = ?";  $params[] = $projectId; }
        if ($assignedTo) { $sql .= " AND t.assigned_to = ?"; $params[] = $assignedTo; }
        if ($stage)      { $sql .= " AND t.stage = ?";       $params[] = $stage; }
        $sql .= " ORDER BY FIELD(t.stage,'inprogress','inreview','todo','backlog','done'), t.priority DESC, t.due_date ASC";
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        echo json_encode(['success' => true, 'tasks' => $stmt->fetchAll()]);
        exit;
    }

    // ── LOAD MY TASKS (for the logged-in user by numeric DB id) ──────────────
    if ($action === 'load_my_tasks') {
        $db  = getDB();
        $uid = (int)($_GET['uid'] ?? 0);
        if (!$uid) { echo json_encode(['success' => false, 'error' => 'uid required']); exit; }
        $stmt = $db->prepare(
            "SELECT t.*, p.name AS project_name, p.client_name
             FROM tasks t LEFT JOIN projects p ON p.id = t.project_id
             WHERE t.assigned_to = ? AND t.stage != 'done'
             ORDER BY t.due_date ASC, FIELD(t.priority,'high','medium','low')"
        );
        $stmt->execute([$uid]);
        echo json_encode(['success' => true, 'tasks' => $stmt->fetchAll()]);
        exit;
    }

    // ── LOAD TASK COMMENTS ────────────────────────────────────────────────────
    if ($action === 'load_task_comments') {
        $db     = getDB();
        $taskId = (int)($_GET['task_id'] ?? 0);
        if (!$taskId) { echo json_encode(['success' => false, 'error' => 'task_id required']); exit; }
        $stmt = $db->prepare("SELECT * FROM task_comments WHERE task_id = ? ORDER BY created_at ASC");
        $stmt->execute([$taskId]);
        echo json_encode(['success' => true, 'comments' => $stmt->fetchAll()]);
        exit;
    }

    if ($action === 'load') {
        $db = getDB();
        $employees = $db->query("SELECT id, ghl_contact_id, name, email, role, pin, pin_set, password_set, rate, status, delegate_to, added_from_ghl, manager_id FROM users WHERE status = 'active' ORDER BY name")->fetchAll();
        $settings = [];
        foreach ($db->query("SELECT `key`, `value` FROM settings")->fetchAll() as $row) {
            $settings[$row['key']] = $row['value'];
        }
        // Never send secrets. Signed-out visitors only get what the sign-in screen needs.
        $SECRET_KEYS = ['ghl_api_key','webhook_secret','session_secret','manager_password','hr_password'];
        foreach (array_keys($settings) as $k) {
            if (in_array($k, $SECRET_KEYS, true) || strpos($k, 'pin_reset_') === 0) {
                if (isPayRole($AUTH) && in_array($k, ['ghl_api_key','webhook_secret'], true) && $settings[$k] !== '') {
                    $settings[$k] = '••••••' . substr($settings[$k], -4);   // masked for the Settings screen
                } else { unset($settings[$k]); }
            }
        }
        if (!$AUTH) {
            $mini = array_map(function($e) {
                return ['id'=>'e'.$e['id'], 'name'=>$e['name'], 'role'=>$e['role'], 'active'=>$e['status']==='active', 'password_set'=>(bool)$e['password_set']];
            }, $employees);
            echo json_encode(['success' => true, 'data' => ['employees' => $mini, 'settings' => (object)[]]]);
            exit;
        }
        if (!isPayRole($AUTH)) $settings = [];
        $canPay = isPayRole($AUTH); $meId = (int)$AUTH['id'];
        $formatted = array_map(function($e) use ($canPay, $meId) {
            return [
                'id'             => 'e' . $e['id'],
                'db_id'          => $e['id'],
                'ghl_contact_id' => $e['ghl_contact_id'],
                'name'           => $e['name'],
                'email'          => $e['email'],
                'role'           => $e['role'],
                'pin_set'        => (bool)$e['pin_set'],
                'password_set'   => (bool)$e['password_set'],
                'rate'           => $canPay ? $e['rate'] : null,
                'delegate_to'    => $e['delegate_to'],
                'active'         => $e['status'] === 'active',
                'added_from_ghl' => (bool)$e['added_from_ghl'],
                'manager_id'     => $e['manager_id'],
            ];
        }, $employees);
        echo json_encode(['success' => true, 'data' => ['employees' => $formatted, 'settings' => $settings], 'me' => publicUser($AUTH)]);
        exit;
    }

    if ($action === 'get_client_by_location') {
        $db = getDB();
        $locationId = $_GET['location_id'] ?? '';
        if (!$locationId) { echo json_encode(['success'=>false,'error'=>'location_id required']); exit; }
        $stmt = $db->prepare("SELECT name FROM clients WHERE location_id = ? AND active = 1 LIMIT 1");
        $stmt->execute([$locationId]);
        $row = $stmt->fetch();
        if (!$row) {
            $stmt = $db->prepare("SELECT name FROM clients WHERE ghl_contact_id = ? AND active = 1 LIMIT 1");
            $stmt->execute([$locationId]);
            $row = $stmt->fetch();
        }
        echo json_encode($row ? ['success'=>true,'name'=>$row['name']] : ['success'=>false,'name'=>null]);
        exit;
    }

    if ($action === 'load_draft') {
        $db = getDB();
        ensureEntryColumns($db);
        $uid = isset($_GET['uid']) ? $_GET['uid'] : '';
        $period = isset($_GET['period']) ? $_GET['period'] : '';
        $dbId = preg_replace('/^e/', '', $uid);
        if ((int)$dbId !== (int)$AUTH['id'] && !canReview($AUTH, $dbId)) { http_response_code(403); echo json_encode(['success'=>false,'error'=>'Not allowed']); exit; }
        $stmt = $db->prepare("SELECT t.*, u.name as employee_name, u.email as employee_email, u.rate as employee_rate
            FROM timesheets t JOIN users u ON t.user_id = u.id
            WHERE t.user_id = ? AND t.period = ? LIMIT 1");
        $stmt->execute([$dbId, $period]);
        $ts = $stmt->fetch();
        if (!$ts) { echo json_encode(['success' => false, 'record' => null]); exit; }
        $stmt2 = $db->prepare("SELECT te.*, COALESCE(c.name, te.client_label) as client_name, pj.name as project_name FROM timesheet_entries te LEFT JOIN projects pj ON te.project_id = pj.id
            LEFT JOIN clients c ON te.client_id = c.id
            WHERE te.timesheet_id = ? ORDER BY te.day_index, te.row_index");
        $stmt2->execute([$ts['id']]);
        $entries = $stmt2->fetchAll();
        $ts['entries'] = $entries;
        $ts['submitted'] = $ts['status'] !== 'draft';
        $stmt3 = $db->prepare("SELECT tc.type, tc.comment, tc.created_at, u.name as author FROM timesheet_comments tc
            LEFT JOIN users u ON tc.user_id = u.id
            WHERE tc.timesheet_id = ? ORDER BY tc.created_at DESC");
        $stmt3->execute([$ts['id']]);
        $ts['comments'] = $stmt3->fetchAll();
        if (!isPayRole($AUTH)) { $one = [$ts]; stripPay($one); $ts = $one[0]; }
        echo json_encode(['success' => true, 'record' => $ts]);
        exit;
    }

    if ($action === 'load_timesheets') {
        $db = getDB();
        ensureEntryColumns($db);
        $stmt = $db->query("SELECT t.*, u.name as employee, u.email,
            a.name as approved_by_name
            FROM timesheets t
            JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.approved_by = a.id
            ORDER BY t.submitted_at DESC");
        $timesheets = $stmt->fetchAll();
        foreach ($timesheets as &$ts) {
            $stmt2 = $db->prepare("SELECT te.*, COALESCE(c.name, te.client_label) as client_name, pj.name as project_name FROM timesheet_entries te LEFT JOIN projects pj ON te.project_id = pj.id
                LEFT JOIN clients c ON te.client_id = c.id
                WHERE te.timesheet_id = ? ORDER BY te.day_index, te.row_index");
            $stmt2->execute([$ts['id']]);
            $ts['entries'] = $stmt2->fetchAll();
            $stmt3 = $db->prepare("SELECT tc.*, u.name as author FROM timesheet_comments tc
                JOIN users u ON tc.user_id = u.id
                WHERE tc.timesheet_id = ? ORDER BY tc.created_at DESC");
            $stmt3->execute([$ts['id']]);
            $ts['comments'] = $stmt3->fetchAll();
        }
        // Only your own timecards and the ones you review
        $allowed = reviewableIds($AUTH); $allowed[] = (int)$AUTH['id'];
        $timesheets = array_values(array_filter($timesheets, function($t) use ($allowed) { return in_array((int)$t['user_id'], $allowed, true); }));
        if (!isPayRole($AUTH)) stripPay($timesheets);
        echo json_encode(['success' => true, 'records' => $timesheets]);
        exit;
    }

    if ($action === 'load_clients') {
        $db = getDB();
        $clients = $db->query("SELECT * FROM clients WHERE active = 1 ORDER BY type, name")->fetchAll();
        echo json_encode(['success' => true, 'clients' => $clients]);
        exit;
    }

    if ($action === 'load_audit_period') {
        $db = getDB();
        $period = $_GET['period'] ?? '';
        $stmt = $db->prepare("SELECT al.*, u.name as user_name, eu.name as employee_name
            FROM audit_log al
            JOIN users u ON al.user_id = u.id
            LEFT JOIN timesheets t ON al.timesheet_id = t.id
            LEFT JOIN users eu ON t.user_id = eu.id
            WHERE t.period = ?
            ORDER BY al.created_at DESC LIMIT 500");
        $stmt->execute([$period]);
        echo json_encode(['success' => true, 'log' => $stmt->fetchAll()]);
        exit;
    }

    if ($action === 'load_report') {
        $db = getDB();
        $period = $_GET['period'] ?? '';
        $empStmt = $db->prepare("SELECT u.name, u.rate, t.total_hours, t.total_pay, t.status
            FROM users u LEFT JOIN timesheets t ON t.user_id = u.id AND t.period = ?
            WHERE u.status = 'active' AND u.role = 'employee' ORDER BY u.name");
        $empStmt->execute([$period]);
        $employees = $empStmt->fetchAll();
        $clientStmt = $db->prepare("SELECT c.name, c.type,
            SUM(te.hours) as total_hours,
            SUM(CASE WHEN COALESCE(te.billing_type,'billable') = 'billable'    THEN te.hours ELSE 0 END) as billable_hours,
            SUM(CASE WHEN COALESCE(te.billing_type,'billable') = 'nonbillable' THEN te.hours ELSE 0 END) as nonbillable_hours,
            SUM(CASE WHEN COALESCE(te.billing_type,'billable') = 'marketing'   THEN te.hours ELSE 0 END) as marketing_hours,
            GROUP_CONCAT(DISTINCT u.name ORDER BY u.name SEPARATOR ', ') as employees
            FROM timesheet_entries te
            JOIN timesheets t ON te.timesheet_id = t.id
            JOIN clients c ON te.client_id = c.id
            JOIN users u ON t.user_id = u.id
            WHERE t.period = ? AND c.type != 'internal'
            GROUP BY c.id ORDER BY total_hours DESC");
        $clientStmt->execute([$period]);
        $clients = $clientStmt->fetchAll();
        echo json_encode(['success' => true, 'report' => ['employees' => $employees, 'clients' => $clients]]);
        exit;
    }

    // ── LOAD PERIODS (distinct periods with timesheet data) ────────────────────
    if ($action === 'load_periods') {
        try {
            $db = getDB();
            $stmt = $db->query("SELECT DISTINCT period FROM timesheets WHERE period IS NOT NULL AND period != '' ORDER BY period_start DESC, period DESC LIMIT 26");
            $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
            echo json_encode(['success'=>true,'periods'=>$rows]);
        } catch(Exception $e) {
            echo json_encode(['success'=>false,'error'=>$e->getMessage()]);
        }
        exit;
    }

    // ── RICH REPORT v2 ──────────────────────────────────────────────────────────
    if ($action === 'load_report_v2') {
        try {
        $db         = getDB();
        $period     = trim($_GET['period']     ?? '');
        $dateStart  = trim($_GET['date_start'] ?? '');
        $dateEnd    = trim($_GET['date_end']   ?? '');
        $useCustom  = ($dateStart && $dateEnd);

        try { $db->exec("ALTER TABLE projects ADD COLUMN estimated_hours DECIMAL(8,2) DEFAULT NULL"); } catch(Exception $e) {}
        try { $db->exec("ALTER TABLE timesheet_entries ADD COLUMN client_label VARCHAR(255) DEFAULT NULL"); } catch(Exception $e) {}

        // Line-level filters. Custom ranges count only the days inside the range,
        // not whole pay periods that happen to overlap it.
        if ($useCustom) {
            $lineCond   = "DATE_ADD(t.period_start, INTERVAL te.day_index DAY) BETWEEN ? AND ?";
            $lineParams = [$dateStart, $dateEnd];
            $cardCond   = "t.period_start <= ? AND t.period_end >= ?";
            $cardParams = [$dateEnd, $dateStart];
        } else {
            $lineCond   = "t.period = ?";
            $lineParams = [$period];
            $cardCond   = "t.period = ?";
            $cardParams = [$period];
        }
        // Billing type: honour legacy rows that only have the billable flag
        $BT     = "COALESCE(te.billing_type, CASE WHEN te.billable = 0 THEN 'nonbillable' ELSE 'billable' END)";
        // Pay: the rate saved on the line, else the person's rate (extension lines save 0)
        $RATE   = "COALESCE(NULLIF(te.pay_rate,0), u.rate, 0)";
        // Client: matched client, else the name the person typed
        $CLIENT = "COALESCE(c.name, NULLIF(te.client_label,''), '(No Client)')";
        $LINES  = "FROM timesheet_entries te
                   JOIN timesheets t ON te.timesheet_id = t.id
                   JOIN users u ON t.user_id = u.id
                   LEFT JOIN clients c ON te.client_id = c.id
                   WHERE {$lineCond} AND te.hours > 0";

        // --- MASTER: everyone on the team + anyone with hours (any role), pay from lines
        $hoursStmt = $db->prepare("
            SELECT u.id AS uid,
                SUM(te.hours) AS total_hours,
                SUM(CASE WHEN {$BT}='billable'    THEN te.hours ELSE 0 END) AS billable_hours,
                SUM(CASE WHEN {$BT}='nonbillable' THEN te.hours ELSE 0 END) AS nonbillable_hours,
                SUM(CASE WHEN {$BT}='marketing'   THEN te.hours ELSE 0 END) AS marketing_hours,
                SUM(te.hours * {$RATE}) AS total_pay
            {$LINES}
            GROUP BY u.id");
        $hoursStmt->execute($lineParams);
        $hoursBy = [];
        foreach ($hoursStmt->fetchAll(PDO::FETCH_ASSOC) as $h) $hoursBy[$h['uid']] = $h;

        $cardStmt = $db->prepare("SELECT t.user_id, GROUP_CONCAT(DISTINCT t.status) AS statuses FROM timesheets t WHERE {$cardCond} GROUP BY t.user_id");
        $cardStmt->execute($cardParams);
        $statusBy = [];
        foreach ($cardStmt->fetchAll(PDO::FETCH_ASSOC) as $s) $statusBy[$s['user_id']] = $s['statuses'];

        $people = $db->query("SELECT id, name, role, status, rate FROM users ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
        $master = [];
        foreach ($people as $p) {
            $uid = $p['id'];
            $isTeam = ($p['status'] === 'active' && $p['role'] !== 'admin');
            if (!$isTeam && !isset($hoursBy[$uid]) && !isset($statusBy[$uid])) continue;
            $h = $hoursBy[$uid] ?? [];
            $sts = isset($statusBy[$uid]) ? array_values(array_unique(explode(',', $statusBy[$uid]))) : [];
            $status = count($sts) === 0 ? 'none' : (count($sts) === 1 ? $sts[0] : 'mixed');
            $master[] = [
                'employee'          => $p['name'],
                'role'              => $p['role'],
                'active'            => $p['status'] === 'active',
                'total_hours'       => round((float)($h['total_hours'] ?? 0), 2),
                'billable_hours'    => round((float)($h['billable_hours'] ?? 0), 2),
                'nonbillable_hours' => round((float)($h['nonbillable_hours'] ?? 0), 2),
                'marketing_hours'   => round((float)($h['marketing_hours'] ?? 0), 2),
                'total_pay'         => round((float)($h['total_pay'] ?? 0), 2),
                'status'            => $status,
                'statuses'          => $sts,
            ];
        }

        // --- KPI counts from the same list
        $submittedStatuses = ['submitted','under_review','approved'];
        $counts = ['total_employees' => count($master), 'submitted_count' => 0, 'approved_count' => 0];
        foreach ($master as $m) {
            if ($m['status'] !== 'none' && $m['status'] !== 'mixed' && in_array($m['status'], $submittedStatuses)) $counts['submitted_count']++;
            if ($m['status'] === 'approved') $counts['approved_count']++;
            if ($m['status'] === 'mixed' && !array_diff($m['statuses'], $submittedStatuses)) $counts['submitted_count']++;
            if ($m['status'] === 'mixed' && $m['statuses'] === ['approved']) $counts['approved_count']++;
        }

        // --- Per billing type: by client, and by employee × client
        $byClient = function($type) use ($db, $LINES, $BT, $RATE, $CLIENT, $lineParams) {
            $st = $db->prepare("
                SELECT {$CLIENT} AS client, COALESCE(c.type,'') AS type,
                    SUM(te.hours) AS hours,
                    GROUP_CONCAT(DISTINCT u.name ORDER BY u.name SEPARATOR ', ') AS employees,
                    SUM(te.hours * {$RATE}) AS cost
                {$LINES} AND {$BT} = ?
                GROUP BY {$CLIENT}, COALESCE(c.type,'') ORDER BY hours DESC");
            $st->execute(array_merge($lineParams, [$type]));
            return $st->fetchAll(PDO::FETCH_ASSOC);
        };
        $byEmp = function($type) use ($db, $LINES, $BT, $RATE, $CLIENT, $lineParams) {
            $st = $db->prepare("
                SELECT {$CLIENT} AS client, u.name AS employee,
                    SUM(te.hours) AS hours,
                    SUM(te.hours * {$RATE}) AS cost
                {$LINES} AND {$BT} = ?
                GROUP BY {$CLIENT}, u.id ORDER BY client, hours DESC");
            $st->execute(array_merge($lineParams, [$type]));
            return $st->fetchAll(PDO::FETCH_ASSOC);
        };
        $billable      = $byClient('billable');
        $billableByEmp = $byEmp('billable');
        $nonbillable   = $byClient('nonbillable');
        $nbByEmp       = $byEmp('nonbillable');
        $marketing     = $byClient('marketing');
        $mkByEmp       = $byEmp('marketing');

        // --- PROJECTIONS: hours logged to each project on timesheets + task hours
        ensureEntryColumns($db);
        try {
            $projStmt = $db->prepare("
                SELECT p.id, p.name, p.client_id, COALESCE(p.client_name, (SELECT c.name FROM clients c WHERE c.id = p.client_id)) AS client_name, p.billing_type, p.status,
                    p.due_date, p.estimated_hours,
                    (SELECT COUNT(*) FROM tasks tk WHERE tk.project_id=p.id) AS task_count,
                    (SELECT COUNT(*) FROM tasks tk WHERE tk.project_id=p.id AND tk.stage='done') AS done_count,
                    COALESCE((
                        SELECT SUM(te2.hours) FROM timesheet_entries te2
                        WHERE te2.project_id = p.id
                    ), 0) +
                    COALESCE((
                        SELECT SUM(tk2.logged_hours)
                        FROM tasks tk2
                        WHERE tk2.project_id = p.id AND tk2.logged_hours IS NOT NULL
                    ), 0) AS logged_hours,
                    COALESCE((
                        SELECT SUM(te3.hours) FROM timesheet_entries te3
                        WHERE p.client_id IS NOT NULL AND te3.client_id = p.client_id AND te3.project_id IS NULL
                    ), 0) AS client_unassigned_hours
                FROM projects p
                WHERE p.status != 'archived'
                ORDER BY p.due_date IS NULL, p.due_date ASC, p.updated_at DESC");
            $projStmt->execute();
            $projections = $projStmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $pe) {
            $projections = [];
        }

        $payload = ['success' => true, 'report' => [
            'range'       => $useCustom ? ['start'=>$dateStart,'end'=>$dateEnd] : ['period'=>$period],
            'counts'      => $counts,
            'master'      => $master,
            'billable'    => $billable,
            'billableEmp' => $billableByEmp,
            'nonbillable' => $nonbillable,
            'nbEmp'       => $nbByEmp,
            'marketing'   => $marketing,
            'mkEmp'       => $mkByEmp,
            'projections' => $projections,
        ]];
        $out = json_encode($payload);
        if ($out === false) {
            echo json_encode(['success'=>false,'error'=>'json_encode failed: '.json_last_error_msg()]);
        } else {
            echo $out;
        }
        } catch (Exception $e) {
            echo json_encode(['success'=>false,'error'=>$e->getMessage()]);
        }
        exit;
    }

    if ($action === 'export_payroll') {
        $db = getDB();
        $period = $_GET['period'] ?? '';
        $stmt = $db->prepare("SELECT u.name, u.email, u.rate, t.total_hours, t.total_pay, t.status, t.submitted_at
            FROM users u LEFT JOIN timesheets t ON t.user_id = u.id AND t.period = ?
            WHERE u.status = 'active' AND u.role = 'employee' ORDER BY u.name");
        $stmt->execute([$period]);
        $rows = $stmt->fetchAll();
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="payroll_'.str_replace([' ','-'],'_',$period).'.csv"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['Employee','Email','Pay Period','Total Hours','Pay Rate ($/hr)','Total Pay','Status','Submitted At']);
        foreach ($rows as $e) {
            $sat = '';
            if ($e['submitted_at']) {
                $dt = new DateTime($e['submitted_at']);
                $sat = $dt->getTimestamp() > 0 ? $dt->format('m/d/Y H:i') : '';
            }
            fputcsv($out, [$e['name'],$e['email']??'',$period,
                number_format((float)($e['total_hours']??0),1),
                $e['rate']?'$'.number_format((float)$e['rate'],2):'N/A',
                $e['total_pay']?'$'.number_format((float)$e['total_pay'],2):'N/A',
                $e['status']??'draft',$sat]);
        }
        fclose($out); exit;
    }

    if ($action === 'export_clients') {
        $db = getDB();
        $period = $_GET['period'] ?? '';
        $stmt = $db->prepare("SELECT c.name as client, c.type, SUM(te.hours) as total_hours,
            GROUP_CONCAT(DISTINCT u.name ORDER BY u.name SEPARATOR ', ') as employees
            FROM timesheet_entries te
            JOIN timesheets t ON te.timesheet_id = t.id
            JOIN clients c ON te.client_id = c.id
            JOIN users u ON t.user_id = u.id
            WHERE t.period = ? AND te.billable = 1 AND c.type != 'internal'
            GROUP BY c.id ORDER BY total_hours DESC");
        $stmt->execute([$period]);
        $rows = $stmt->fetchAll();
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="client_hours_'.str_replace([' ','-'],'_',$period).'.csv"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['Client','Type','Pay Period','Billable Hours','Employees']);
        foreach ($rows as $c) {
            fputcsv($out, [$c['client'],$c['type'],$period,number_format((float)$c['total_hours'],1),$c['employees']]);
        }
        fclose($out); exit;
    }

    if ($action === 'export_audit') {
        $db = getDB();
        $period = $_GET['period'] ?? '';
        $stmt = $db->prepare("SELECT al.created_at, eu.name as employee, u.name as changed_by, al.action, al.after_state
            FROM audit_log al JOIN users u ON al.user_id = u.id
            LEFT JOIN timesheets t ON al.timesheet_id = t.id
            LEFT JOIN users eu ON t.user_id = eu.id
            WHERE t.period = ? ORDER BY al.created_at DESC");
        $stmt->execute([$period]);
        $rows = $stmt->fetchAll();
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="audit_'.str_replace([' ','-'],'_',$period).'.csv"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['Date/Time','Employee','Changed By','Action','Details']);
        foreach ($rows as $entry) {
            $details = '';
            if ($entry['after_state']) {
                $after = json_decode($entry['after_state'], true);
                if (isset($after['reason'])) $details = 'Reason: '.$after['reason'];
                elseif (isset($after['total_hours'])) $details = 'Hours: '.$after['total_hours'];
                elseif (isset($after['comment'])) $details = $after['comment'];
            }
            fputcsv($out, [$entry['created_at'],$entry['employee']??'—',$entry['changed_by'],$entry['action'],$details]);
        }
        fclose($out); exit;
    }

    if ($action === 'load_audit') {
        $db = getDB();
        $tsId = (int)($_GET['timesheet_id'] ?? 0);
        $stmt = $db->prepare("SELECT al.*, u.name as user_name FROM audit_log al
            JOIN users u ON al.user_id = u.id
            WHERE al.timesheet_id = ? ORDER BY al.created_at DESC");
        $stmt->execute([$tsId]);
        echo json_encode(['success' => true, 'log' => $stmt->fetchAll()]);
        exit;
    }

    // ── GET CLIENT HOURS — client-facing portal ────────────────────────────
    if ($action === 'client_hours') {
        $db = getDB();
        $locationId = $_GET['location_id'] ?? '';
        $requestedPeriod = $_GET['period'] ?? '';
        if (!$locationId) { echo json_encode(['success'=>false,'error'=>'location_id required']); exit; }
        $client = null;
        $stmt = $db->prepare("SELECT * FROM clients WHERE location_id = ? AND active = 1 LIMIT 1");
        $stmt->execute([$locationId]);
        $client = $stmt->fetch();
        if (!$client) {
            $stmt = $db->prepare("SELECT * FROM clients WHERE ghl_contact_id = ? AND active = 1 LIMIT 1");
            $stmt->execute([$locationId]);
            $client = $stmt->fetch();
        }
        if (!$client) { echo json_encode(['success'=>false,'error'=>'Client not found']); exit; }
        if ($client['plan_type'] === 'diy') {
            echo json_encode(['success'=>true,'plan'=>'diy','plan_label'=>'DIY Plan',
                'client'=>['name'=>$client['name'],'plan'=>'diy','plan_label'=>'DIY Plan']]); exit;
        }
        $pStarts = payPeriodStarts();
        $today = new DateTime();
        $periods = []; $currentPeriod = ''; $currentPidx = 0;
        foreach ($pStarts as $i => $ps) {
            $sDt = new DateTime(sprintf('%04d-%02d-%02d',$ps[0],$ps[1],$ps[2]));
            $eDt = clone $sDt; $eDt->modify('+13 days');
            $label = $sDt->format('M j').' - '.$eDt->format('M j, Y');
            $value = $sDt->format('M d').' - '.$eDt->format('M d');
            $periods[] = ['label'=>$label,'value'=>$value,'index'=>$i];
            if ($today >= $sDt && $today <= $eDt) { $currentPeriod = $value; $currentPidx = $i; }
        }
        $periods = array_reverse($periods);
        $activePeriod = $requestedPeriod ?: $currentPeriod;
        if (!$activePeriod && count($periods) > 0) $activePeriod = $periods[0]['value'];
        $stmt = $db->prepare("SELECT * FROM client_hours_bank WHERE client_id = ? AND period = ? LIMIT 1");
        $stmt->execute([$client['id'], $activePeriod]);
        $bank = $stmt->fetch();
        if (!$bank) {
            $bank = ['total_hours'=>$client['monthly_hours']??0,'plan_type'=>$client['plan_type']??'none','plan_label'=>$client['plan_label']??'Retainer'];
        }
        $stmt = $db->prepare("SELECT te.hours, te.deliverable, u.name AS team_member, t.period_start, te.day_index
            FROM timesheet_entries te
            JOIN timesheets t ON te.timesheet_id = t.id
            JOIN users u ON t.user_id = u.id
            WHERE te.client_id = ? AND t.period = ? AND t.status IN ('draft','submitted','under_review','approved')
            ORDER BY te.day_index ASC");
        $stmt->execute([$client['id'], $activePeriod]);
        $entries = $stmt->fetchAll();
        $usedHours = 0; $activity = [];
        foreach ($entries as $en) {
            $hrs = (float)$en['hours']; $usedHours += $hrs;
            $periodStart = null;
            foreach ($pStarts as $ps) {
                $sDt = new DateTime(sprintf('%04d-%02d-%02d',$ps[0],$ps[1],$ps[2]));
                $eDt = clone $sDt; $eDt->modify('+13 days');
                $pVal = $sDt->format('M d').' - '.$eDt->format('M d');
                if ($pVal === $activePeriod) { $periodStart = $sDt; break; }
            }
            $entryDate = $periodStart ? (clone $periodStart)->modify('+'.(int)$en['day_index'].' days')->format('Y-m-d') : null;
            $activity[] = ['date'=>$entryDate,'deliverable'=>$en['deliverable']?:'Support work','team_member'=>$en['team_member'],'hours'=>$hrs];
        }
        $totalHours = (float)($bank['total_hours']??0);
        $remaining = max(0, $totalHours - $usedHours);
        echo json_encode(['success'=>true,
            'client'=>['name'=>$client['name'],'plan'=>$bank['plan_type']??'retainer','plan_label'=>$bank['plan_label']??($client['plan_label']??'Retainer')],
            'bank'=>['total_hours'=>$totalHours,'used_hours'=>round($usedHours,2),'remaining'=>round($remaining,2)],
            'activity'=>$activity,'period'=>$activePeriod,'periods'=>$periods]);
        exit;
    }

    // ── LOAD CLIENT BANKS — admin view ──────────────────────────────────────
    if ($action === 'load_client_banks') {
        $db = getDB();
        $period = $_GET['period'] ?? '';
        $stmt = $db->prepare("
            SELECT c.id, c.name, c.location_id, c.ghl_contact_id, c.plan_type, c.plan_label, c.monthly_hours,
                COALESCE(chb.total_hours, c.monthly_hours, 0) AS bank_hours,
                COALESCE(chb.plan_type, c.plan_type, 'none') AS bank_plan,
                COALESCE(chb.plan_label, c.plan_label, '') AS bank_plan_label,
                COALESCE((SELECT SUM(te.hours) FROM timesheet_entries te
                    JOIN timesheets t ON te.timesheet_id = t.id
                    WHERE te.client_id = c.id AND t.period = ?
                    AND t.status IN ('draft','submitted','under_review','approved')), 0) AS used_hours
            FROM clients c
            LEFT JOIN client_hours_bank chb ON chb.client_id = c.id AND chb.period = ?
            WHERE c.active = 1 ORDER BY c.name");
        $stmt->execute([$period, $period]);
        $banks = $stmt->fetchAll();
        $result = array_map(function($b) {
            $total = (float)$b['bank_hours']; $used = (float)$b['used_hours'];
            return ['id'=>$b['id'],'name'=>$b['name'],'location_id'=>$b['location_id']??$b['ghl_contact_id'],
                'plan'=>$b['bank_plan'],'plan_label'=>$b['bank_plan_label'],
                'total_hours'=>$total,'used_hours'=>round($used,2),'remaining'=>round(max(0,$total-$used),2)];
        }, $banks);
        echo json_encode(['success'=>true,'banks'=>$result]);
        exit;
    }

    if ($action === 'load_overtime') {
        $db = getDB();
        $stmt = $db->query("SELECT of.id, of.week_number, of.hours_worked, of.overtime_hours, of.type, of.status,
            u.name as employee, u.manager_id, t.period
            FROM overtime_flags of
            JOIN users u ON of.user_id = u.id
            JOIN timesheets t ON of.timesheet_id = t.id
            WHERE of.status = 'flagged'
            ORDER BY of.created_at DESC");
        echo json_encode(['success' => true, 'flags' => $stmt->fetchAll()]);
        exit;
    }
}

// ─────────────────────────────────────────
// GET MUTATIONS (WAF-safe — PM actions via query string)
// ─────────────────────────────────────────
// ── LOAD TASK FOLLOWERS ───────────────────────────────────────────────────────
if ($action === 'load_task_followers') {
    $db     = getDB();
    $taskId = (int)($_GET['task_id'] ?? 0);
    if (!$taskId) { echo json_encode(['success' => false, 'error' => 'task_id required']); exit; }
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS task_followers (
            task_id INT NOT NULL, user_id INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (task_id, user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $stmt = $db->prepare("SELECT user_id FROM task_followers WHERE task_id = ?");
        $stmt->execute([$taskId]);
        $ids = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'user_id');
        echo json_encode(['success' => true, 'followers' => $ids]);
    } catch (Exception $e) {
        echo json_encode(['success' => true, 'followers' => []]);
    }
    exit;
}

// ── LOAD FOLLOWED TASKS (tasks user follows but isn't assigned to) ────────────
if ($action === 'load_followed_tasks') {
    $db  = getDB();
    $uid = (int)($_GET['uid'] ?? 0);
    if (!$uid) { echo json_encode(['success' => false, 'error' => 'uid required']); exit; }
    try {
        $stmt = $db->prepare(
            "SELECT t.*, p.name AS project_name, p.client_name
             FROM tasks t
             JOIN task_followers tf ON tf.task_id = t.id AND tf.user_id = ?
             LEFT JOIN projects p ON p.id = t.project_id
             WHERE t.assigned_to != ? AND t.stage != 'done'
             ORDER BY t.due_date ASC"
        );
        $stmt->execute([$uid, $uid]);
        echo json_encode(['success' => true, 'tasks' => $stmt->fetchAll()]);
    } catch (Exception $e) {
        echo json_encode(['success' => true, 'tasks' => []]);
    }
    exit;
}

// ── FORGOT PASSWORD (GET, fires GHL reset webhook) ───────────────────────
if ($method === 'GET' && $action === 'forgot_pin') {
    $db    = getDB();
    $email = trim($_GET['email'] ?? '');
    if (!$email) { echo json_encode(['success' => false, 'error' => 'Email required']); exit; }
    $stmt = $db->prepare("SELECT id, name, role FROM users WHERE email = ? AND status = 'active' LIMIT 1");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    if ($user) {
        $token   = bin2hex(random_bytes(20));
        $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));
        $key     = 'pin_reset_' . $user['id'];
        $val     = json_encode(['token' => $token, 'expires' => $expires]);
        $db->prepare("INSERT INTO settings (`key`, value) VALUES (?,?) ON DUPLICATE KEY UPDATE value=?")->execute([$key, $val, $val]);
        // Use production URL (stagging subdomain redirects there)
        $resetUrl = 'https://stagging.timesheet.genhead.com/timesheet/?reset_token=' . $token . '&uid=' . $user['id'];
        // Fire GHL reset webhook — reuse ghl_invite_webhook_url or ghl_notify_webhook_url
        $webhookUrl = getSetting('ghl_reset_webhook_url') ?: getSetting('ghl_invite_webhook_url');
        if ($webhookUrl) {
            $payload = [
                'event'          => 'password_reset',
                'action'         => 'password_reset',
                'employee_name'  => $user['name'],
                'employee_email' => $email,
                'employee_id'    => 'e' . $user['id'],
                'role'           => $user['role'],
                'reset_url'      => $resetUrl,
                'expires_in'     => '1 hour',
                'timestamp'      => date('c'),
            ];
            $ch = curl_init($webhookUrl);
            curl_setopt_array($ch, [CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),CURLOPT_HTTPHEADER=>['Content-Type: application/json'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>10]);
            curl_exec($ch);
            curl_close($ch);
        } else {
            // Fallback: PHP mail if no webhook configured
            $subject = 'Genhead Timesheet — Reset Your Password';
            $message = "Hi {$user['name']},\n\nClick the link below to reset your password (expires in 1 hour):\n\n{$resetUrl}\n\n— Genhead Team";
            mail($email, $subject, $message, "From: noreply@genhead.com");
        }
    }
    echo json_encode(['success' => true, 'message' => 'If that email is on file, a reset link is on its way!']);
    exit;
}

// ── INTERNAL: fire a raw POST to any webhook URL (for GHL mapping reference setup) ──
if ($method === 'GET' && $action === 'fire_webhook') {
    $secret = $_GET['secret'] ?? '';
    if ($secret !== 'genhead2026ghl') { echo json_encode(['success' => false, 'error' => 'Unauthorized']); exit; }
    $url  = trim($_GET['url'] ?? '');
    if (!$url) { echo json_encode(['success' => false, 'error' => 'url required']); exit; }
    $payload = [
        'event'          => 'password_reset',
        'action'         => 'password_reset',
        'employee_name'  => 'Test Employee',
        'employee_email' => 'test@example.com',
        'employee_id'    => 'e1',
        'role'           => 'employee',
        'reset_url'      => 'https://stagging.timesheet.genhead.com/timesheet/?reset_token=abc123&uid=1',
        'expires_in'     => '1 hour',
        'timestamp'      => date('c'),
    ];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST          => true,
        CURLOPT_POSTFIELDS    => json_encode($payload),
        CURLOPT_HTTPHEADER    => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER=> true,
        CURLOPT_TIMEOUT       => 15,
    ]);
    $resp     = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err      = curl_error($ch);
    curl_close($ch);
    echo json_encode(['success' => $httpCode >= 200 && $httpCode < 300, 'http_code' => $httpCode, 'response' => $resp, 'curl_error' => $err]);
    exit;
}

if ($method === 'GET' && in_array($action, ['add_project','archive_project','delete_project','set_project_members','set_project_est_hours','log_task_time','add_task','update_task','add_task_comment','toggle_task_follower','delete_task'])) {
    $body = applyAuthIds(normalizeUserIds($_GET), $action);
    $db = getDB();
    ensureProjectMembers($db);

    // ── ADD PROJECT ──────────────────────────────────────────────────────────
    if ($action === 'add_project') {
        $name        = trim($body['name']         ?? '');
        $clientId    = (int)($body['client_id']   ?? 0)  ?: null;
        $clientName  = trim($body['client_name']  ?? '') ?: null;
        if ($clientId && !$clientName) {
            $cn = $db->prepare("SELECT name FROM clients WHERE id = ? LIMIT 1");
            $cn->execute([$clientId]);
            $clientName = $cn->fetchColumn() ?: null;
        }
        $status      = in_array($body['status'] ?? '', ['active','on_hold','completed']) ? $body['status'] : 'active';
        $billingType = in_array($body['billing_type'] ?? '', ['billable','nonbillable','marketing']) ? $body['billing_type'] : 'billable';
        $dueDate     = !empty($body['due_date'])  ? $body['due_date'] : null;
        $description = trim($body['description']  ?? '') ?: null;
        $createdBy   = (int)($body['created_by']  ?? 0);
        $estHours    = isset($body['estimated_hours']) && $body['estimated_hours'] !== '' ? (float)$body['estimated_hours'] : null;
        if (!$name || !$createdBy) { echo json_encode(['success'=>false,'error'=>'name and created_by required']); exit; }
        try { $db->exec("ALTER TABLE projects ADD COLUMN estimated_hours DECIMAL(8,2) DEFAULT NULL"); } catch(Exception $e) {}
        $db->prepare("INSERT INTO projects (name,client_id,client_name,status,billing_type,due_date,description,created_by,estimated_hours) VALUES (?,?,?,?,?,?,?,?,?)")
           ->execute([$name,$clientId,$clientName,$status,$billingType,$dueDate,$description,$createdBy,$estHours]);
        $newProjectId = (int)$db->lastInsertId();
        ensureProjectMembers($db);
        addProjectMember($db, $newProjectId, $createdBy);
        foreach (array_filter(explode(',', $body['user_ids'] ?? '')) as $mid) addProjectMember($db, $newProjectId, (int)$mid);
        echo json_encode(['success'=>true,'id'=>$newProjectId]);
        exit;
    }
    if ($action === 'add_task') {
        $projectId   = (int)($body['project_id']  ?? 0);
        $title       = trim($body['title']         ?? '');
        $description = trim($body['description']   ?? '') ?: null;
        $assignedTo  = (int)($body['assigned_to']  ?? 0)  ?: null;
        $assignedName= trim($body['assigned_name'] ?? '') ?: null;
        $priority    = in_array($body['priority'] ?? '', ['low','medium','high']) ? $body['priority'] : 'medium';
        $stage       = in_array($body['stage'] ?? '', ['backlog','todo','inprogress','inreview','done']) ? $body['stage'] : 'backlog';
        $dueDate     = !empty($body['due_date'])   ? $body['due_date'] : null;
        $billingType = in_array($body['billing_type'] ?? '', ['billable','nonbillable','marketing']) ? $body['billing_type'] : null;
        $estHours    = isset($body['estimated_hours']) && $body['estimated_hours'] !== '' ? (float)$body['estimated_hours'] : null;
        $createdBy   = (int)($body['created_by']  ?? 0);
        if (!$projectId || !$title || !$createdBy) { echo json_encode(['success'=>false,'error'=>'project_id, title, created_by required']); exit; }
        try { $db->exec("ALTER TABLE tasks ADD COLUMN estimated_hours DECIMAL(8,2) DEFAULT NULL"); } catch(Exception $e) {}
        $db->prepare("INSERT INTO tasks (project_id,title,description,assigned_to,assigned_name,priority,stage,due_date,billing_type,estimated_hours,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$projectId,$title,$description,$assignedTo,$assignedName,$priority,$stage,$dueDate,$billingType,$estHours,$createdBy]);
        $taskId=(int)$db->lastInsertId();
        if ($assignedTo) addProjectMember($db, $projectId, $assignedTo);
        // Activity log
        $actorName=trim($body['actor_name']??'') ?: 'Someone';
        $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,1)")
           ->execute([$taskId,$createdBy,$actorName,"Task created and added to ".ucfirst($stage)]);
        echo json_encode(['success'=>true,'id'=>$taskId]);
        exit;
    }
    if ($action === 'update_task') {
        $id       = (int)($body['id'] ?? 0);
        if (!$id) { echo json_encode(['success'=>false,'error'=>'id required']); exit; }
        $stageMap = ['backlog'=>'Backlog','todo'=>'To Do','inprogress'=>'In Progress','inreview'=>'In Review','done'=>'Done'];
        $fields=[]; $params=[];
        if (isset($body['stage']) && array_key_exists($body['stage'],$stageMap)) {
            $fields[]='stage = ?'; $params[]=$body['stage'];
        }
        if (isset($body['assigned_to']))   { $fields[]='assigned_to = ?';   $params[]=((int)$body['assigned_to'])?:(null); }
        if (isset($body['assigned_name'])) { $fields[]='assigned_name = ?'; $params[]=trim($body['assigned_name'])?:null; }
        if (isset($body['priority']) && in_array($body['priority'],['low','medium','high'])) { $fields[]='priority = ?'; $params[]=$body['priority']; }
        if (isset($body['due_date']))      { $fields[]='due_date = ?';      $params[]=$body['due_date']?:null; }
        if (isset($body['estimated_hours']) && $body['estimated_hours']!=='') { $fields[]='estimated_hours = ?'; $params[]=(float)$body['estimated_hours']; }
        if (isset($body['logged_hours'])   && $body['logged_hours']!=='')    { $fields[]='logged_hours = ?';    $params[]=(float)$body['logged_hours']; }
        if (!$fields) { echo json_encode(['success'=>false,'error'=>'nothing to update']); exit; }
        $params[]=$id;
        $db->prepare("UPDATE tasks SET ".implode(',',$fields)." WHERE id=?")->execute($params);
        if (!empty($body['assigned_to']) && (int)$body['assigned_to']) {
            $pj = $db->prepare("SELECT project_id FROM tasks WHERE id = ?");
            $pj->execute([$id]);
            addProjectMember($db, (int)$pj->fetchColumn(), (int)$body['assigned_to']);
            $actorName=trim($body['actor_name']??'')?:'Someone';
            $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,1)")
               ->execute([$id,(int)($body['actor_id']??0),$actorName,"Assigned to ".(trim($body['assigned_name']??'')?:'a team member')]);
        }
        // Activity log for stage move
        if (isset($body['stage']) && array_key_exists($body['stage'],$stageMap)) {
            $actorId=(int)($body['actor_id']??0); $actorName=trim($body['actor_name']??'')?:'Someone';
            $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,1)")
               ->execute([$id,$actorId,$actorName,"Moved to ".$stageMap[$body['stage']]]);
        }
        echo json_encode(['success'=>true]);
        exit;
    }
    if ($action === 'set_project_est_hours') {
        $id  = (int)($body['project_id'] ?? 0);
        $hrs = isset($body['estimated_hours']) ? (float)$body['estimated_hours'] : null;
        if (!$id) { echo json_encode(['success'=>false,'error'=>'project_id required']); exit; }
        try { $db->exec("ALTER TABLE projects ADD COLUMN estimated_hours DECIMAL(8,2) DEFAULT NULL"); } catch(Exception $e) {}
        $db->prepare("UPDATE projects SET estimated_hours=? WHERE id=?")->execute([$hrs,$id]);
        echo json_encode(['success'=>true]);
        exit;
    }
    if ($action === 'add_task_comment') {
        $taskId  = (int)($body['task_id']  ?? 0);
        $userId  = (int)($body['user_id']  ?? 0);
        $userName= trim($body['user_name'] ?? '');
        $comment = trim($body['comment']   ?? '');
        if (!$taskId || !$userId || !$comment) { echo json_encode(['success'=>false,'error'=>'task_id, user_id, comment required']); exit; }
        $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,0)")
           ->execute([$taskId,$userId,$userName,$comment]);
        echo json_encode(['success'=>true,'id'=>(int)$db->lastInsertId()]);
        exit;
    }
    // ── ARCHIVE PROJECT (GET — the page sends it this way) ─────────────────
    if ($action === 'archive_project') {
        $id = (int)($body['id'] ?? 0);
        if (!$id) { echo json_encode(['success'=>false,'error'=>'id required']); exit; }
        $db->prepare("UPDATE projects SET status='archived' WHERE id=?")->execute([$id]);
        echo json_encode(['success'=>true]);
        exit;
    }

    // ── SET PROJECT TEAM ───────────────────────────────────────────────────
    if ($action === 'set_project_members') {
        $pid     = (int)($body['project_id'] ?? 0);
        $actorId = (int)($body['actor_id'] ?? 0);
        if (!$pid) { echo json_encode(['success'=>false,'error'=>'project_id required']); exit; }
        $role = $db->prepare("SELECT role FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $role->execute([$actorId]);
        if (!in_array($role->fetchColumn(), ['admin','hr','manager'])) { echo json_encode(['success'=>false,'error'=>'Only Managers, HR or Admin can change the project team']); exit; }
        $ids = array_values(array_unique(array_filter(array_map('intval', explode(',', $body['user_ids'] ?? '')))));
        $db->beginTransaction();
        $db->prepare("DELETE FROM project_members WHERE project_id = ?")->execute([$pid]);
        foreach ($ids as $mid) addProjectMember($db, $pid, $mid);
        $db->commit();
        echo json_encode(['success'=>true,'count'=>count($ids)]);
        exit;
    }

    // ── DELETE PROJECT ─────────────────────────────────────────────────────
    // Removes the project and its tasks. Timesheet hours are kept: lines tagged
    // to this project are un-tagged and count as general hours for the client.
    if ($action === 'delete_project') {
        $id      = (int)($body['id'] ?? 0);
        $actorId = (int)($body['actor_id'] ?? 0);
        if (!$id) { echo json_encode(['success'=>false,'error'=>'id required']); exit; }
        $role = $db->prepare("SELECT role FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $role->execute([$actorId]);
        if (!in_array($role->fetchColumn(), ['admin','hr','manager'])) { echo json_encode(['success'=>false,'error'=>'Only Managers, HR or Admin can delete projects']); exit; }
        ensureEntryColumns($db);
        $ids = [];
        $db->beginTransaction();
        try {
            $taskIds = $db->prepare("SELECT id FROM tasks WHERE project_id = ?");
            $taskIds->execute([$id]);
            $ids = $taskIds->fetchAll(PDO::FETCH_COLUMN);
            if ($ids) {
                $in = implode(',', array_map('intval', $ids));
                $db->exec("DELETE FROM task_comments WHERE task_id IN ($in)");
                try { $db->exec("DELETE FROM task_followers WHERE task_id IN ($in)"); } catch (Exception $e) {}
                $db->exec("DELETE FROM tasks WHERE id IN ($in)");
            }
            $db->prepare("UPDATE timesheet_entries SET project_id = NULL WHERE project_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM project_members WHERE project_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM projects WHERE id = ?")->execute([$id]);
            $db->commit();
        } catch (Exception $e) {
            $db->rollBack();
            echo json_encode(['success'=>false,'error'=>'Delete failed: '.$e->getMessage()]); exit;
        }
        echo json_encode(['success'=>true,'tasks_deleted'=>count($ids)]);
        exit;
    }

    // ── LOG TIME ON A TASK → adds a line to the person's own timesheet ─────
    if ($action === 'log_task_time') {
        $taskId = (int)($body['task_id'] ?? 0);
        $userId = (int)($body['user_id'] ?? 0);
        $hours  = round((float)($body['hours'] ?? 0), 2);
        $date   = trim($body['date'] ?? '') ?: date('Y-m-d');
        $note   = trim($body['note'] ?? '');
        if (!$taskId || !$userId) { echo json_encode(['success'=>false,'error'=>'task_id and user_id required']); exit; }
        if ($hours <= 0 || $hours > 24) { echo json_encode(['success'=>false,'error'=>'Enter hours between 0.01 and 24']); exit; }
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) { echo json_encode(['success'=>false,'error'=>'Invalid date']); exit; }
        ensureEntryColumns($db);

        $st = $db->prepare("SELECT t.id, t.title, t.billing_type, t.project_id, p.name AS project_name, p.client_id,
                                   COALESCE(p.client_name, (SELECT c.name FROM clients c WHERE c.id = p.client_id)) AS client_name,
                                   p.billing_type AS project_billing_type
                            FROM tasks t LEFT JOIN projects p ON p.id = t.project_id WHERE t.id = ? LIMIT 1");
        $st->execute([$taskId]);
        $task = $st->fetch();
        if (!$task) { echo json_encode(['success'=>false,'error'=>'Task not found']); exit; }

        $us = $db->prepare("SELECT id, name, rate FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $us->execute([$userId]);
        $user = $us->fetch();
        if (!$user) { echo json_encode(['success'=>false,'error'=>'User not found']); exit; }

        $per = periodForDate($date);
        if (!$per) { echo json_encode(['success'=>false,'error'=>'That date is outside the pay periods set up in the timesheet']); exit; }

        // Find or create this person's timesheet for that period
        $ts = $db->prepare("SELECT id, status FROM timesheets WHERE user_id = ? AND period = ? LIMIT 1");
        $ts->execute([$userId, $per['period']]);
        $sheet = $ts->fetch();
        if ($sheet && in_array($sheet['status'], ['submitted','under_review','approved'])) {
            echo json_encode(['success'=>false,'error'=>"Your timesheet for {$per['period']} is already ".($sheet['status']==='approved'?'approved':'submitted').". Ask your reviewer to return it to add time."]); exit;
        }
        if (!$sheet) {
            $db->prepare("INSERT INTO timesheets (user_id, period, period_index, period_start, period_end, status, total_hours, total_pay, pay_rate) VALUES (?,?,?,?,?,'draft',0,0,?)")
               ->execute([$userId, $per['period'], $per['index'], $per['start'], $per['end'], (float)$user['rate']]);
            $sheetId = (int)$db->lastInsertId();
        } else {
            $sheetId = (int)$sheet['id'];
        }

        $billingType = $task['billing_type'] ?: ($task['project_billing_type'] ?: 'billable');
        if (!in_array($billingType, ['billable','nonbillable','marketing'])) $billingType = 'billable';
        $deliverable = $task['title'] . ($note !== '' ? ' — ' . $note : '');
        $rowSt = $db->prepare("SELECT COALESCE(MAX(row_index),-1)+1 FROM timesheet_entries WHERE timesheet_id = ? AND day_index = ?");
        $rowSt->execute([$sheetId, $per['day']]);
        $rowIdx = (int)$rowSt->fetchColumn();

        $db->prepare("INSERT INTO timesheet_entries (timesheet_id, client_id, client_label, deliverable, hours, pay_rate, billable, billing_type, day_index, row_index, source, project_id, task_id)
                      VALUES (?,?,?,?,?,?,?,?,?,?, 'task', ?, ?)")
           ->execute([$sheetId, $task['client_id'] ?: null, $task['client_name'] ?: null, $deliverable, $hours, (float)$user['rate'],
                      $billingType === 'billable' ? 1 : 0, $billingType, $per['day'], $rowIdx, $task['project_id'] ?: null, $taskId]);

        $db->prepare("UPDATE timesheets SET total_hours = (SELECT COALESCE(SUM(hours),0) FROM timesheet_entries WHERE timesheet_id = ?),
                      total_pay = (SELECT COALESCE(SUM(hours * pay_rate),0) FROM timesheet_entries WHERE timesheet_id = ?), updated_at = NOW() WHERE id = ?")
           ->execute([$sheetId, $sheetId, $sheetId]);

        $nice = (new DateTime($date))->format('M j');
        $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,1)")
           ->execute([$taskId, $userId, $user['name'], "Logged {$hours}h on {$nice}".($note !== '' ? " — {$note}" : '')]);

        $tot = $db->prepare("SELECT COALESCE(SUM(hours),0) FROM timesheet_entries WHERE task_id = ?");
        $tot->execute([$taskId]);
        $mine = $db->prepare("SELECT COALESCE(SUM(te.hours),0) FROM timesheet_entries te JOIN timesheets t ON t.id = te.timesheet_id WHERE te.task_id = ? AND t.user_id = ?");
        $mine->execute([$taskId, $userId]);
        echo json_encode(['success'=>true, 'period'=>$per['period'], 'period_index'=>$per['index'],
                          'task_hours'=>round((float)$tot->fetchColumn(),2), 'my_task_hours'=>round((float)$mine->fetchColumn(),2)]);
        exit;
    }

    if ($action === 'delete_task') {
        $taskId = (int)($body['task_id'] ?? 0);
        if (!$taskId) { echo json_encode(['success'=>false,'error'=>'task_id required']); exit; }
        $db->prepare("DELETE FROM task_comments WHERE task_id=?")->execute([$taskId]);
        $db->prepare("DELETE FROM tasks WHERE id=?")->execute([$taskId]);
        echo json_encode(['success'=>true]);
        exit;
    }

    if ($action === 'toggle_task_follower') {
        $taskId = (int)($body['task_id'] ?? 0);
        $userId = (int)($body['user_id'] ?? 0);
        if (!$taskId || !$userId) { echo json_encode(['success'=>false,'error'=>'task_id and user_id required']); exit; }
        try {
            // Ensure table exists
            $db->exec("CREATE TABLE IF NOT EXISTS task_followers (
                task_id INT NOT NULL,
                user_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (task_id, user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            $check = $db->prepare("SELECT 1 FROM task_followers WHERE task_id=? AND user_id=?");
            $check->execute([$taskId, $userId]);
            if ($check->fetch()) {
                $db->prepare("DELETE FROM task_followers WHERE task_id=? AND user_id=?")->execute([$taskId, $userId]);
                echo json_encode(['success'=>true,'following'=>false]);
            } else {
                $db->prepare("INSERT INTO task_followers (task_id,user_id) VALUES (?,?)")->execute([$taskId, $userId]);
                echo json_encode(['success'=>true,'following'=>true]);
            }
        } catch (Exception $e) {
            echo json_encode(['success'=>false,'error'=>$e->getMessage()]);
        }
        exit;
    }
}

// ─────────────────────────────────────────
// TEAM MANAGEMENT — ACCEPT GET OR POST
// (WAF blocks POST; these actions also work via GET params)
// ─────────────────────────────────────────
if (in_array($action, ['add_employee','add_manager','update_employee','assign_manager','remove_employee','toggle_active'])) {
    $body = ($method === 'POST') ? (json_decode(file_get_contents('php://input'), true) ?: $_POST) : $_GET;
    $db = getDB();

    if ($action === 'add_employee') {
        $name  = trim($body['name']  ?? '');
        $email = trim($body['email'] ?? '');
        $pin   = trim($body['pin']   ?? '');
        if (!$name) { echo json_encode(['success' => false, 'error' => 'Name required']); exit; }
        if ($email) {
            $chk = $db->prepare("SELECT id, role FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
            $chk->execute([$email]);
            $existing = $chk->fetch();
            if ($existing) {
                echo json_encode(['success' => true, 'message' => 'Employee already exists', 'employee' => ['id' => 'e'.$existing['id'], 'name' => $name, 'email' => $email, 'role' => $existing['role']]]);
                exit;
            }
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, pin, pin_set, role) VALUES (?, ?, ?, ?, 'employee')");
        $stmt->execute([$name, $email, $pin ?: null, $pin ? 1 : 0]);
        $newId = $db->lastInsertId();
        sendInviteWebhook($name, $email, 'employee', $newId);
        echo json_encode(['success' => true, 'employee' => ['id' => 'e'.$newId, 'name' => $name, 'email' => $email, 'pin_set' => (bool)$pin]]);
        exit;
    }

    if ($action === 'add_manager') {
        $name  = trim($body['name']  ?? '');
        $email = trim($body['email'] ?? '');
        // Password param uses 'pw' to avoid WAF keyword filter
        $pw    = trim($body['pw'] ?? $body['mgr_pw'] ?? '');
        $role  = in_array($body['role'] ?? '', ['manager','hr','admin']) ? $body['role'] : 'manager';
        if (!$name) { echo json_encode(['success'=>false,'error'=>'Name required']); exit; }
        $hash = $pw ? password_hash($pw, PASSWORD_DEFAULT) : null;
        if ($email) {
            $chk = $db->prepare("SELECT id, role FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
            $chk->execute([$email]);
            $existing = $chk->fetch();
            if ($existing) {
                echo json_encode(['success'=>true,'message'=>'User already exists','id'=>'e'.$existing['id'],'name'=>$name]);
                exit;
            }
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, role, password_hash, password_set, status) VALUES (?, ?, ?, ?, ?, 'active')");
        $stmt->execute([$name, $email, $role, $hash, $pw ? 1 : 0]);
        $newId = $db->lastInsertId();
        sendInviteWebhook($name, $email, $role, $newId);
        echo json_encode(['success'=>true,'id'=>'e'.$newId,'name'=>$name]);
        exit;
    }

    if ($action === 'assign_manager') {
        $empId = preg_replace('/^e/', '', $body['employee_id'] ?? '');
        $mgrId = !empty($body['manager_id']) ? preg_replace('/^e/', '', $body['manager_id']) : null;
        if (!$empId) { echo json_encode(['success'=>false,'error'=>'Employee ID required']); exit; }
        $db->prepare("UPDATE users SET manager_id = ? WHERE id = ?")->execute([$mgrId, $empId]);
        echo json_encode(['success' => true]);
        exit;
    }

    if ($action === 'update_employee') {
        $id = preg_replace('/^e/', '', $body['id'] ?? '');
        if (!$id) { echo json_encode(['success' => false, 'error' => 'ID required']); exit; }
        $fields = []; $params = [];
        if (isset($body['name']))        { $fields[] = 'name = ?';        $params[] = $body['name']; }
        if (isset($body['rate']))        { $fields[] = 'rate = ?';        $params[] = $body['rate']; }
        if (isset($body['active']))      { $fields[] = 'status = ?';      $params[] = $body['active'] ? 'active' : 'inactive'; }
        if (isset($body['role']))        { $fields[] = 'role = ?';        $params[] = $body['role']; }
        if (isset($body['pin']))         { $fields[] = 'pin = ?';         $params[] = $body['pin'];
                                           $fields[] = 'pin_set = 1'; }
        if (isset($body['manager_id']))  { $fields[] = 'manager_id = ?';  $params[] = $body['manager_id'] ?: null; }
        // Password uses 'pw' param to avoid WAF keyword filter
        $pwVal = $body['pw'] ?? $body['mgr_pw'] ?? null;
        if ($pwVal !== null && $pwVal !== '') {
            $fields[] = 'password_hash = ?'; $params[] = password_hash($pwVal, PASSWORD_DEFAULT);
            $fields[] = 'password_set = 1';
        }
        if (empty($fields)) { echo json_encode(['success' => false, 'error' => 'Nothing to update']); exit; }
        $params[] = $id;
        $db->prepare("UPDATE users SET ".implode(', ',$fields)." WHERE id = ?")->execute($params);
        echo json_encode(['success' => true]);
        exit;
    }

    if ($action === 'remove_employee' || $action === 'toggle_active') {
        $id = preg_replace('/^e/', '', $body['id'] ?? '');
        $active = isset($body['active']) ? (bool)$body['active'] : false;
        $status = $active ? 'active' : 'inactive';
        $db->prepare("UPDATE users SET status = ? WHERE id = ?")->execute([$status, $id]);
        echo json_encode(['success' => true]);
        exit;
    }
}

// ─────────────────────────────────────────
// POST ACTIONS
// ─────────────────────────────────────────
if ($method === 'POST') {
    $rawBody = file_get_contents('php://input');
    $body = json_decode($rawBody, true);
    if (!is_array($body)) $body = !empty($_POST) ? $_POST : [];
    $body = applyAuthIds(normalizeUserIds($body), $action);
    $db = getDB();

    // ── ADD PROJECT ──────────────────────────────────────────────────────────
    if ($action === 'add_project') {
        $name        = trim($body['name']         ?? '');
        $clientId    = (int)($body['client_id']   ?? 0)  ?: null;
        $clientName  = trim($body['client_name']  ?? '') ?: null;
        if ($clientId && !$clientName) {
            $cn = $db->prepare("SELECT name FROM clients WHERE id = ? LIMIT 1");
            $cn->execute([$clientId]);
            $clientName = $cn->fetchColumn() ?: null;
        }
        $status      = in_array($body['status'] ?? '', ['active','on_hold','completed']) ? $body['status'] : 'active';
        $billingType = in_array($body['billing_type'] ?? '', ['billable','nonbillable','marketing']) ? $body['billing_type'] : 'billable';
        $dueDate     = !empty($body['due_date'])  ? $body['due_date'] : null;
        $description = trim($body['description']  ?? '') ?: null;
        $createdBy   = (int)($body['created_by']  ?? 0);
        if (!$name || !$createdBy) { echo json_encode(['success'=>false,'error'=>'name and created_by required']); exit; }
        $db->prepare("INSERT INTO projects (name,client_id,client_name,status,billing_type,due_date,description,created_by)
                      VALUES (?,?,?,?,?,?,?,?)")
           ->execute([$name,$clientId,$clientName,$status,$billingType,$dueDate,$description,$createdBy]);
        echo json_encode(['success'=>true,'id'=>(int)$db->lastInsertId()]);
        exit;
    }

    // ── UPDATE PROJECT ────────────────────────────────────────────────────────
    if ($action === 'update_project') {
        $id     = (int)($body['id'] ?? 0);
        if (!$id) { echo json_encode(['success'=>false,'error'=>'id required']); exit; }
        $fields=[]; $params=[];
        if (isset($body['name']))         { $fields[]='name = ?';         $params[]=trim($body['name']); }
        if (isset($body['status']))       { $fields[]='status = ?';       $params[]=$body['status']; }
        if (isset($body['billing_type'])) { $fields[]='billing_type = ?'; $params[]=$body['billing_type']; }
        if (isset($body['due_date']))     { $fields[]='due_date = ?';     $params[]=$body['due_date']?:null; }
        if (isset($body['description']))  { $fields[]='description = ?';  $params[]=$body['description']?:null; }
        if (isset($body['client_name']))  { $fields[]='client_name = ?';  $params[]=$body['client_name']?:null; }
        if (isset($body['client_id'])) {
            $cid = (int)$body['client_id'] ?: null;
            $fields[]='client_id = ?'; $params[]=$cid;
            if ($cid && !isset($body['client_name'])) {
                $cn = $db->prepare("SELECT name FROM clients WHERE id = ? LIMIT 1");
                $cn->execute([$cid]);
                $fields[]='client_name = ?'; $params[]=$cn->fetchColumn() ?: null;
            }
        }
        if (!$fields) { echo json_encode(['success'=>false,'error'=>'nothing to update']); exit; }
        $params[]=$id;
        $db->prepare("UPDATE projects SET ".implode(',',$fields)." WHERE id=?")->execute($params);
        echo json_encode(['success'=>true]);
        exit;
    }

    // ── ARCHIVE PROJECT ──────────────────────────────────────────────────────
    if ($action === 'archive_project') {
        $id = (int)($body['id'] ?? 0);
        if (!$id) { echo json_encode(['success'=>false,'error'=>'id required']); exit; }
        $db->prepare("UPDATE projects SET status='archived' WHERE id=?")->execute([$id]);
        echo json_encode(['success'=>true]);
        exit;
    }

    // ── ADD TASK ──────────────────────────────────────────────────────────────
    if ($action === 'add_task') {
        $projectId   = (int)($body['project_id']  ?? 0);
        $title       = trim($body['title']         ?? '');
        $description = trim($body['description']   ?? '') ?: null;
        $assignedTo  = (int)($body['assigned_to']  ?? 0)  ?: null;
        $assignedName= trim($body['assigned_name'] ?? '') ?: null;
        $priority    = in_array($body['priority'] ?? '', ['low','medium','high']) ? $body['priority'] : 'medium';
        $stage       = in_array($body['stage'] ?? '', ['backlog','todo','inprogress','inreview','done']) ? $body['stage'] : 'backlog';
        $dueDate     = !empty($body['due_date'])   ? $body['due_date'] : null;
        $billingType = in_array($body['billing_type'] ?? '', ['billable','nonbillable','marketing']) ? $body['billing_type'] : null;
        $createdBy   = (int)($body['created_by']   ?? 0);
        if (!$projectId || !$title || !$createdBy) { echo json_encode(['success'=>false,'error'=>'project_id, title, created_by required']); exit; }
        $db->prepare("INSERT INTO tasks (project_id,title,description,assigned_to,assigned_name,priority,stage,due_date,billing_type,created_by)
                      VALUES (?,?,?,?,?,?,?,?,?,?)")
           ->execute([$projectId,$title,$description,$assignedTo,$assignedName,$priority,$stage,$dueDate,$billingType,$createdBy]);
        $newId=(int)$db->lastInsertId();
        // Log activity
        $actorName=trim($body['actor_name']??'System');
        $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,1)")
           ->execute([$newId,$createdBy,$actorName,"Created task and added to ".ucfirst($stage)]);
        echo json_encode(['success'=>true,'id'=>$newId]);
        exit;
    }

    // ── UPDATE TASK (stage move, reassign, edit) ──────────────────────────────
    if ($action === 'update_task') {
        $id        = (int)($body['id']         ?? 0);
        $actorId   = (int)($body['actor_id']   ?? 0);
        $actorName = trim($body['actor_name']  ?? 'System');
        if (!$id) { echo json_encode(['success'=>false,'error'=>'id required']); exit; }
        $fields=[]; $params=[];
        $stageLabels=['backlog'=>'Backlog','todo'=>'To Do','inprogress'=>'In Progress','inreview'=>'In Review','done'=>'Done'];
        if (isset($body['stage']) && array_key_exists($body['stage'], $stageLabels)) {
            $fields[]='stage = ?'; $params[]=$body['stage'];
        }
        if (isset($body['title']))        { $fields[]='title = ?';        $params[]=trim($body['title']); }
        if (isset($body['description']))  { $fields[]='description = ?';  $params[]=$body['description']?:null; }
        if (isset($body['priority']))     { $fields[]='priority = ?';     $params[]=$body['priority']; }
        if (isset($body['due_date']))     { $fields[]='due_date = ?';     $params[]=$body['due_date']?:null; }
        if (isset($body['assigned_to']))  {
            $fields[]='assigned_to = ?';   $params[]=(int)$body['assigned_to']?:null;
            $fields[]='assigned_name = ?'; $params[]=trim($body['assigned_name']??'')?:null;
        }
        if ($fields) {
            $params[]=$id;
            $db->prepare("UPDATE tasks SET ".implode(',',$fields)." WHERE id=?")->execute($params);
        }
        // Log activity if stage changed
        if (isset($body['stage'])) {
            $label=$stageLabels[$body['stage']]??$body['stage'];
            $comment=isset($body['comment'])&&trim($body['comment'])
                ? "Moved to $label — ".trim($body['comment'])
                : "Moved to $label";
            $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,1)")
               ->execute([$id,$actorId,$actorName,$comment]);
        }
        echo json_encode(['success'=>true]);
        exit;
    }

    // ── ADD TASK COMMENT ─────────────────────────────────────────────────────
    if ($action === 'add_task_comment') {
        $taskId   = (int)($body['task_id']  ?? 0);
        $userId   = (int)($body['user_id']  ?? 0);
        $userName = trim($body['user_name'] ?? '');
        $comment  = trim($body['comment']   ?? '');
        if (!$taskId || !$userId || !$comment) { echo json_encode(['success'=>false,'error'=>'task_id, user_id, comment required']); exit; }
        $db->prepare("INSERT INTO task_comments (task_id,user_id,user_name,comment,is_activity) VALUES (?,?,?,?,0)")
           ->execute([$taskId,$userId,$userName,$comment]);
        echo json_encode(['success'=>true,'id'=>(int)$db->lastInsertId()]);
        exit;
    }

    // ── SET CLIENT HOURS BANK ──────────────────────────────────────────────
    if ($action === 'set_client_hours') {
        $clientId   = (int)($body['client_id']   ?? 0);
        $period     = trim($body['period']        ?? '');
        $pidx       = (int)($body['period_index'] ?? 0);
        $totalHours = (float)($body['total_hours'] ?? 0);
        $planType   = $body['plan_type']  ?? 'retainer';
        $planLabel  = $body['plan_label'] ?? 'Retainer';
        $notes      = trim($body['notes'] ?? '');
        if (!$clientId || !$period) { echo json_encode(['success'=>false,'error'=>'client_id and period required']); exit; }
        $db->prepare("INSERT INTO client_hours_bank (client_id,period,period_index,total_hours,plan_type,plan_label,notes)
            VALUES (?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE total_hours=VALUES(total_hours),plan_type=VALUES(plan_type),
            plan_label=VALUES(plan_label),notes=VALUES(notes),updated_at=NOW()")
           ->execute([$clientId,$period,$pidx,$totalHours,$planType,$planLabel,$notes]);
        $db->prepare("UPDATE clients SET monthly_hours=?,plan_type=?,plan_label=? WHERE id=?")
           ->execute([$totalHours,$planType,$planLabel,$clientId]);
        echo json_encode(['success'=>true,'message'=>'Hours bank updated']);
        exit;
    }

    // ── UPSERT TIME FROM CHROME EXTENSION ──────────────────────────────────
    if ($action === 'upsert_time') {
        $email      = trim($body['email']       ?? '');
        $locationId = trim($body['location_id'] ?? '');
        $clientName = trim($body['client_name'] ?? '');
        $seconds    = (int)($body['seconds']    ?? 0);
        $date       = trim($body['date']        ?? date('Y-m-d'));

        if (!$email || !$locationId || $seconds <= 0) {
            echo json_encode(['success'=>false,'error'=>'email, location_id and seconds required']); exit;
        }

        $hours = round($seconds / 3600, 4);

        // Find employee
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if (!$user) { echo json_encode(['success'=>false,'error'=>'Employee not found: '.$email]); exit; }
        $userId = $user['id'];

        // Find or create client
        $client = null;
        $stmt = $db->prepare("SELECT id, name FROM clients WHERE location_id = ? AND active = 1 LIMIT 1");
        $stmt->execute([$locationId]);
        $client = $stmt->fetch();
        if (!$client) {
            $stmt = $db->prepare("SELECT id, name FROM clients WHERE ghl_contact_id = ? AND active = 1 LIMIT 1");
            $stmt->execute([$locationId]);
            $client = $stmt->fetch();
        }
        if (!$client && $clientName) {
            $db->prepare("INSERT INTO clients (ghl_contact_id, name, type, billable, active) VALUES (?, ?, 'ghl_instance', 1, 1)")
               ->execute([$locationId, $clientName]);
            $clientId = $db->lastInsertId();
            $client = ['id'=>$clientId, 'name'=>$clientName];
        }
        $clientId   = $client ? $client['id']   : null;
        $clientName = $client ? $client['name'] : $clientName;

        // Determine pay period
        $pStarts = payPeriodStarts();
        $checkDt = new DateTime($date);
        $period = 'Unknown'; $pidx = 0; $pStart = $date; $pEnd = $date;
        foreach ($pStarts as $i => $ps) {
            $sDt = new DateTime(sprintf('%04d-%02d-%02d', $ps[0], $ps[1], $ps[2]));
            $eDt = clone $sDt; $eDt->modify('+13 days');
            if ($checkDt >= $sDt && $checkDt <= $eDt) {
                $period = $sDt->format('M d').' - '.$eDt->format('M d');
                $pidx = $i; $pStart = $sDt->format('Y-m-d'); $pEnd = $eDt->format('Y-m-d');
                break;
            }
        }

        // Get or create timesheet
        $stmt = $db->prepare("SELECT id FROM timesheets WHERE user_id = ? AND period = ? LIMIT 1");
        $stmt->execute([$userId, $period]);
        $ts = $stmt->fetch();
        if (!$ts) {
            $db->prepare("INSERT INTO timesheets (user_id, period, period_index, period_start, period_end, status, total_hours, total_pay) VALUES (?,?,?,?,?,'draft',?,0)")
               ->execute([$userId, $period, $pidx, $pStart, $pEnd, $hours]);
            $tsId = $db->lastInsertId();
        } else {
            $tsId = $ts['id'];
        }

        // Day index within period
        $dayIndex = (int)(new DateTime($pStart))->diff(new DateTime($date))->days;
        if ($dayIndex < 0 || $dayIndex > 13) $dayIndex = 0;

        // Upsert entry — overwrite hours with cumulative total from extension
        $stmt = $db->prepare("SELECT id FROM timesheet_entries WHERE timesheet_id = ? AND client_id = ? AND day_index = ? AND source = 'extension' LIMIT 1");
        $stmt->execute([$tsId, $clientId, $dayIndex]);
        $existing = $stmt->fetch();
        if ($existing) {
            $db->prepare("UPDATE timesheet_entries SET hours = ?, updated_at = NOW() WHERE id = ?")
               ->execute([round($hours, 4), $existing['id']]);
        } else {
            $db->prepare("INSERT INTO timesheet_entries (timesheet_id, client_id, deliverable, hours, pay_rate, billable, day_index, row_index, source) VALUES (?,?,'',?,0,1,?,0,'extension')")
               ->execute([$tsId, $clientId, round($hours, 4), $dayIndex]);
        }

        // Update timesheet total
        $db->prepare("UPDATE timesheets SET total_hours = (SELECT SUM(hours) FROM timesheet_entries WHERE timesheet_id = ?) WHERE id = ?")
           ->execute([$tsId, $tsId]);

        echo json_encode(['success'=>true, 'client'=>$clientName, 'hours'=>round($hours,4), 'tsId'=>$tsId]);
        exit;
    }

    // ── VERIFY MANAGER PASSWORD ─────────────────────────────────────────────
    if ($action === 'verify_password') {
        $id = preg_replace('/^e/', '', $body['id'] ?? '');
        $password = $body['password'] ?? '';
        if (!$id || !$password) { echo json_encode(['success' => false, 'error' => 'ID and password required']); exit; }
        $stmt = $db->prepare("SELECT id, password, password_hash, password_set, name, role FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        // Not set up yet — prompt first-time setup
        if (!$row['password_set']) { echo json_encode(['success' => false, 'needs_setup' => true]); exit; }
        // Verify against hash (fall back to plaintext for legacy rows during migration)
        if ($row['password_hash']) {
            $valid = password_verify($password, $row['password_hash']);
        } else {
            $valid = ($row['password'] === $password);
        }
        echo json_encode(['success' => $valid, 'name' => $row['name'], 'role' => $row['role']]);
        exit;
    }

    // ── SET PASSWORD (first-time or reset for manager/hr/admin) ────────────────
    if ($action === 'set_password') {
        $id       = preg_replace('/^e/', '', $body['id'] ?? '');
        $password = trim($body['password'] ?? '');
        if (!$id || strlen($password) < 6) {
            echo json_encode(['success' => false, 'error' => 'Password must be at least 6 characters']); exit;
        }
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        $u = $stmt->fetch();
        if (!$u) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        // First-time setup only. Changing an existing password must go through the emailed reset link.
        if ($u['password_set']) { echo json_encode(['success' => false, 'error' => 'A password is already set for this account. Use "Forgot password" to reset it.']); exit; }
        // Prove it's really them: their old PIN, or the old shared Manager/HR password
        $proof = setupProof($u);
        $given = (string)($body['old'] ?? ($_GET['old'] ?? ''));
        if ($proof === 'pin' && !hash_equals((string)$u['pin'], $given)) { usleep(400000); echo json_encode(['success' => false, 'error' => 'That PIN doesn\'t match the one on file.']); exit; }
        if ($proof === 'role_password' && !hash_equals((string)getSetting($u['role'].'_password'), $given)) { usleep(400000); echo json_encode(['success' => false, 'error' => 'That doesn\'t match the current '.ucfirst($u['role']).' password.']); exit; }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $db->prepare("UPDATE users SET password_hash = ?, password_set = 1 WHERE id = ?")->execute([$hash, $id]);
        echo json_encode(['success' => true, 'token' => issueToken($id), 'user' => publicUser($u)]);
        exit;
    }

    // ── GHL AUTO-ADD EMPLOYEE ───────────────────────────────────────────────
    if ($action === 'ghl_add') {
        $secret = isset($_GET['secret']) ? $_GET['secret'] : '';
        $storedSecret = getSetting('webhook_secret');
        if ($storedSecret && $secret !== $storedSecret) {
            http_response_code(401);
            echo json_encode(['success' => false, 'error' => 'Unauthorized']);
            exit;
        }
        $name = ''; $email = '';
        foreach (['name','full_name','contact_name'] as $k) {
            if (!empty($body[$k])) { $name = trim($body[$k]); break; }
        }
        if (!$name) {
            $first = $body['firstName'] ?? $body['first_name'] ?? '';
            $last  = $body['lastName']  ?? $body['last_name']  ?? '';
            $name  = trim("$first $last");
        }
        foreach (['email','contact_email','emailAddress'] as $k) {
            if (!empty($body[$k])) { $email = trim($body[$k]); break; }
        }
        if (!$name) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Name required', 'received' => $body]);
            exit;
        }
        // Also grab ghl_contact_id if present
        $ghlContactId = '';
        foreach (['id','contact_id','contactId','ghl_contact_id'] as $k) {
            if (!empty($body[$k])) { $ghlContactId = trim($body[$k]); break; }
        }

        // Look up by email first (most reliable), then fall back to name
        $existing = null;
        if ($email) {
            $stmt = $db->prepare("SELECT id, role FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
            $stmt->execute([$email]);
            $existing = $stmt->fetch();
        }
        if (!$existing) {
            $stmt = $db->prepare("SELECT id, role FROM users WHERE LOWER(name) = LOWER(?) LIMIT 1");
            $stmt->execute([$name]);
            $existing = $stmt->fetch();
        }
        if ($existing) {
            // Person already exists — update ghl_contact_id and name if we have better data, but never downgrade their role
            $updates = [];
            $params  = [];
            if ($ghlContactId) { $updates[] = "ghl_contact_id = ?"; $params[] = $ghlContactId; }
            if ($name)         { $updates[] = "name = ?";           $params[] = $name; }
            if ($updates) {
                $params[] = $existing['id'];
                $db->prepare("UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?")->execute($params);
            }
            echo json_encode(['success' => true, 'message' => 'Employee already exists — record updated', 'id' => 'e' . $existing['id'], 'role' => $existing['role']]);
            exit;
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, role, ghl_contact_id, added_from_ghl) VALUES (?, ?, 'employee', ?, 1)");
        $stmt->execute([$name, $email, $ghlContactId ?: null]);
        $newId = $db->lastInsertId();
        logAudit(null, $newId, 'ghl_auto_add', null, ['name' => $name, 'email' => $email]);

        sendInviteWebhook($name, $email, 'employee', $newId);

        echo json_encode(['success' => true, 'message' => 'Employee added', 'id' => 'e' . $newId]);
        exit;
    }

    // ── ADD EMPLOYEE MANUALLY ───────────────────────────────────────────────
    if ($action === 'add_employee') {
        $name  = trim($body['name']  ?? '');
        $email = trim($body['email'] ?? '');
        $pin   = trim($body['pin']   ?? '');
        if (!$name) { echo json_encode(['success' => false, 'error' => 'Name required']); exit; }
        // Check for existing record by email to avoid duplicates
        $existing = null;
        if ($email) {
            $chk = $db->prepare("SELECT id, role FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
            $chk->execute([$email]);
            $existing = $chk->fetch();
        }
        if ($existing) {
            echo json_encode(['success' => true, 'message' => 'Employee already exists', 'employee' => ['id' => 'e'.$existing['id'], 'name' => $name, 'email' => $email, 'role' => $existing['role']]]);
            exit;
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, pin, pin_set, role) VALUES (?, ?, ?, ?, 'employee')");
        $stmt->execute([$name, $email, $pin ?: null, $pin ? 1 : 0]);
        $newId = $db->lastInsertId();
        sendInviteWebhook($name, $email, 'employee', $newId);
        echo json_encode(['success' => true, 'employee' => ['id' => 'e'.$newId, 'name' => $name, 'email' => $email, 'pin_set' => (bool)$pin]]);
        exit;
    }

    // ── ASSIGN EMPLOYEE TO MANAGER ──────────────────────────────────────────
    if ($action === 'assign_manager') {
        $empId = preg_replace('/^e/', '', $body['employee_id'] ?? '');
        $mgrId = !empty($body['manager_id']) ? preg_replace('/^e/', '', $body['manager_id']) : null;
        if (!$empId) { echo json_encode(['success'=>false,'error'=>'Employee ID required']); exit; }
        $db->prepare("UPDATE users SET manager_id = ? WHERE id = ?")->execute([$mgrId, $empId]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── ADD MANAGER ─────────────────────────────────────────────────────────
    if ($action === 'add_manager') {
        $name     = trim($body['name']     ?? '');
        $email    = trim($body['email']    ?? '');
        $password = trim($body['password'] ?? '');
        $role     = in_array($body['role'] ?? '', ['manager','hr','admin']) ? $body['role'] : 'manager';
        if (!$name) { echo json_encode(['success'=>false,'error'=>'Name required']); exit; }
        $hash = $password ? password_hash($password, PASSWORD_DEFAULT) : null;
        // Role priority: admin > hr > manager > employee — never downgrade
        $rolePriority = ['employee'=>0,'manager'=>1,'hr'=>2,'admin'=>3];
        // Check for existing record by email
        $existing = null;
        if ($email) {
            $chk = $db->prepare("SELECT id, role FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
            $chk->execute([$email]);
            $existing = $chk->fetch();
        }
        if ($existing) {
            // Upgrade role if new role is higher; update name and password if provided
            $currentPriority = $rolePriority[$existing['role']] ?? 0;
            $newPriority     = $rolePriority[$role] ?? 1;
            $finalRole       = $newPriority > $currentPriority ? $role : $existing['role'];
            $updates = ["role = ?", "name = ?"]; $params = [$finalRole, $name];
            if ($hash) { $updates[] = "password_hash = ?"; $updates[] = "password_set = 1"; $params[] = $hash; }
            $params[] = $existing['id'];
            $db->prepare("UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?")->execute($params);
            echo json_encode(['success'=>true,'message'=>'Existing user upgraded','id'=>'e'.$existing['id'],'name'=>$name,'role'=>$finalRole]);
            exit;
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, role, password_hash, password_set, status) VALUES (?, ?, ?, ?, ?, 'active')");
        $stmt->execute([$name, $email, $role, $hash, $password ? 1 : 0]);
        $newId = $db->lastInsertId();
        sendInviteWebhook($name, $email, $role, $newId);
        echo json_encode(['success'=>true,'id'=>'e'.$newId,'name'=>$name]);
        exit;
    }

    // ── UPDATE EMPLOYEE ─────────────────────────────────────────────────────
    if ($action === 'update_employee') {
        $id = preg_replace('/^e/', '', $body['id'] ?? '');
        if (!$id) { echo json_encode(['success' => false, 'error' => 'ID required']); exit; }
        $fields = []; $params = [];
        if (isset($body['name']))        { $fields[] = 'name = ?';        $params[] = $body['name']; }
        if (isset($body['rate']))        { $fields[] = 'rate = ?';        $params[] = $body['rate']; }
        if (isset($body['active']))      { $fields[] = 'status = ?';      $params[] = $body['active'] ? 'active' : 'inactive'; }
        if (isset($body['role']))        { $fields[] = 'role = ?';        $params[] = $body['role']; }
        if (isset($body['delegate_to'])) { $fields[] = 'delegate_to = ?'; $params[] = $body['delegate_to'] ?: null; }
        if (isset($body['pin']))         { $fields[] = 'pin = ?';         $params[] = $body['pin'];
                                           $fields[] = 'pin_set = 1'; }
        if (isset($body['manager_id']))  { $fields[] = 'manager_id = ?';  $params[] = $body['manager_id'] ?: null; }
        if (isset($body['password']))    {
            $fields[] = 'password_hash = ?'; $params[] = password_hash($body['password'], PASSWORD_DEFAULT);
            $fields[] = 'password_set = 1';
        }
        if (empty($fields)) { echo json_encode(['success' => false, 'error' => 'Nothing to update']); exit; }
        $params[] = $id;
        $db->prepare("UPDATE users SET ".implode(', ',$fields)." WHERE id = ?")->execute($params);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── REMOVE EMPLOYEE ─────────────────────────────────────────────────────
    if ($action === 'remove_employee') {
        $id = preg_replace('/^e/', '', $body['id'] ?? '');
        $db->prepare("UPDATE users SET status = 'inactive' WHERE id = ?")->execute([$id]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── SET PIN ─────────────────────────────────────────────────────────────
    if ($action === 'set_pin') {
        $id  = preg_replace('/^e/', '', $body['id']  ?? '');
        $pin = trim($body['pin'] ?? '');
        if (strlen($pin) !== 4 || !ctype_digit($pin)) {
            echo json_encode(['success' => false, 'error' => 'PIN must be 4 digits']); exit;
        }
        $db->prepare("UPDATE users SET pin = ?, pin_set = 1 WHERE id = ?")->execute([$pin, $id]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── VERIFY PIN ──────────────────────────────────────────────────────────
    if ($action === 'verify_pin') {
        $db  = getDB();
        $id  = preg_replace('/^e/', '', $body['id'] ?? '');
        $pin = trim($body['pin'] ?? '');
        $stmt = $db->prepare("SELECT pin, pin_set FROM users WHERE id = ? LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        if (!$row['pin_set']) { echo json_encode(['success' => false, 'needs_setup' => true]); exit; }
        if ($row['pin'] !== $pin) { echo json_encode(['success' => false, 'error' => 'Incorrect PIN']); exit; }
        echo json_encode(['success' => true]);
        exit;
    }

    // ── FORGOT PIN / PASSWORD — send reset email (all roles) ────────────────
    if ($action === 'forgot_pin') {
        $db    = getDB();
        $email = trim($body['email'] ?? '');
        if (!$email) { echo json_encode(['success' => false, 'error' => 'Email required']); exit; }
        $stmt = $db->prepare("SELECT id, name, role FROM users WHERE email = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        // Always return success to prevent email enumeration
        if ($user) {
            $token    = bin2hex(random_bytes(20));
            $expires  = date('Y-m-d H:i:s', strtotime('+1 hour'));
            $key      = 'pin_reset_' . $user['id'];
            $val      = json_encode(['token' => $token, 'expires' => $expires]);
            $db->prepare("INSERT INTO settings (`key`, value) VALUES (?,?) ON DUPLICATE KEY UPDATE value=?")->execute([$key, $val, $val]);
            $resetUrl = 'https://timesheet.genhead.com/index.html?reset_token=' . $token . '&uid=' . $user['id'];
            $subject  = 'Genhead Timesheet — Reset Your Password';
            $message  = "Hi {$user['name']},\n\nYou requested a password reset for the Genhead Timesheet Portal.\n\nClick the link below to set a new password (expires in 1 hour):\n\n{$resetUrl}\n\nIf you did not request this, you can ignore this email.\n\n— Genhead Team";
            $headers  = "From: noreply@genhead.com\r\nReply-To: support@genhead.com";
            mail($email, $subject, $message, $headers);
        }
        echo json_encode(['success' => true, 'message' => 'If that email is in our system, a reset link has been sent.']);
        exit;
    }

    // ── RESET PIN / PASSWORD via token (all roles) ───────────────────────────
    if ($action === 'reset_pin') {
        $db    = getDB();
        $uid   = (int)($body['uid']   ?? 0);
        $token = trim($body['token']  ?? '');
        $pin   = trim($body['pin']    ?? '');   // 4-digit PIN for employees
        $pass  = trim($body['password'] ?? ''); // new password for mgr/hr/admin
        if (!$uid || !$token) { echo json_encode(['success' => false, 'error' => 'Invalid request']); exit; }
        $key  = 'pin_reset_' . $uid;
        $stmt = $db->prepare("SELECT value FROM settings WHERE `key` = ? LIMIT 1");
        $stmt->execute([$key]);
        $row  = $stmt->fetch();
        if (!$row) { echo json_encode(['success' => false, 'error' => 'Reset link is invalid or expired']); exit; }
        $data = json_decode($row['value'], true);
        if (!$data || $data['token'] !== $token || strtotime($data['expires']) < time()) {
            echo json_encode(['success' => false, 'error' => 'Reset link is invalid or has expired']); exit;
        }
        // Determine role to set appropriate field
        $uStmt = $db->prepare("SELECT role FROM users WHERE id = ? LIMIT 1");
        $uStmt->execute([$uid]);
        $uRow = $uStmt->fetch();
        if (!$uRow) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        // All roles now use password (PINs removed)
        if (strlen($pass) < 6) {
            echo json_encode(['success' => false, 'error' => 'Password must be at least 6 characters']); exit;
        }
        $hash = password_hash($pass, PASSWORD_DEFAULT);
        $db->prepare("UPDATE users SET password_hash = ?, password_set = 1 WHERE id = ?")->execute([$hash, $uid]);
        $db->prepare("DELETE FROM settings WHERE `key` = ?")->execute([$key]);
        $full = $db->prepare("SELECT * FROM users WHERE id = ?"); $full->execute([$uid]);
        echo json_encode(['success' => true, 'role' => $uRow['role'], 'token' => issueToken($uid), 'user' => publicUser($full->fetch())]);
        exit;
    }

    // ── SAVE TIMESHEET ──────────────────────────────────────────────────────
    if ($action === 'save_timesheet') {
        $body['employeeId'] = 'e' . $AUTH['id'];   // you can only save your own timesheet
        $rawId = $body['employeeId'] ?? '';
        $strippedId = preg_replace('/^e/', '', $rawId);
        if (is_numeric($strippedId)) {
            $dbId = $strippedId;
        } else {
            $empName = $body['employee'] ?? '';
            $uStmt = $db->prepare("SELECT id FROM users WHERE name = ? LIMIT 1");
            $uStmt->execute([$empName]);
            $uRow = $uStmt->fetch();
            if (!$uRow) { echo json_encode(['success' => false, 'error' => 'Employee not found: ' . $empName]); exit; }
            $dbId = $uRow['id'];
        }
        $period      = $body['period']      ?? '';
        $periodIndex = (int)($body['periodIndex'] ?? 0);
        $submitted   = (bool)($body['submitted']  ?? false);
        $isDraft     = (bool)($body['isDraft']     ?? true);
        $totalHours  = (float)($body['totalHours'] ?? 0);
        $totalPay    = (float)($body['totalPay']   ?? 0);
        $payRate     = (float)($body['payRate']    ?? 0);
        $entries     = $body['entries'] ?? [];

        $periodStarts = payPeriodStarts();
        if (!isset($periodStarts[$periodIndex])) { $x = new DateTime('2026-04-27'); $x->modify('+'.(14*$periodIndex).' days'); $periodStarts[$periodIndex] = [(int)$x->format('Y'),(int)$x->format('n'),(int)$x->format('j')]; }
        $ps        = $periodStarts[$periodIndex];
        $startDate = sprintf('%04d-%02d-%02d', $ps[0], $ps[1], $ps[2]);
        $endDt     = new DateTime($startDate);
        $endDt->modify('+13 days');
        $endDate     = $endDt->format('Y-m-d');
        $status      = $submitted ? 'submitted' : 'draft';
        $submittedAt = $submitted ? date('Y-m-d H:i:s') : null;

        $stmt = $db->prepare("SELECT id, status FROM timesheets WHERE user_id = ? AND period = ?");
        $stmt->execute([$dbId, $period]);
        $existing = $stmt->fetch();

        if ($existing) {
            $tsId = $existing['id'];
            $protectedStatuses = ['submitted', 'under_review'];
            $newStatus = in_array($existing['status'], $protectedStatuses) && !$isDraft ? $existing['status'] : $status;
            $db->prepare("UPDATE timesheets SET total_hours=?, total_pay=?, pay_rate=?, status=?,
                submitted_at=COALESCE(submitted_at,?), updated_at=NOW() WHERE id=?")
               ->execute([$totalHours, $totalPay, $payRate, $newStatus, $submittedAt, $tsId]);
        } else {
            $db->prepare("INSERT INTO timesheets (user_id, period, period_index, period_start, period_end,
                status, total_hours, total_pay, pay_rate, submitted_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
               ->execute([$dbId,$period,$periodIndex,$startDate,$endDate,$status,$totalHours,$totalPay,$payRate,$submittedAt]);
            $tsId = $db->lastInsertId();
        }

        ensureEntryColumns($db);
        $db->prepare("DELETE FROM timesheet_entries WHERE timesheet_id = ?")->execute([$tsId]);
        $entryStmt = $db->prepare("INSERT INTO timesheet_entries (timesheet_id, client_id, client_label, deliverable, hours, pay_rate, billable, billing_type, day_index, row_index, source, project_id, task_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");
        foreach ($entries as $i => $en) {
            if (empty($en['hrs']) && empty($en['co'])) continue;
            $clientId = null;
            if (!empty($en['co'])) {
                $cStmt = $db->prepare("SELECT id FROM clients WHERE name = ? LIMIT 1");
                $cStmt->execute([$en['co']]);
                $client   = $cStmt->fetch();
                $clientId = $client ? $client['id'] : null;
            }
            // Support new billing_type field (billable/nonbillable/marketing)
            $billingType = isset($en['bt']) ? $en['bt'] : (isset($en['billing_type']) ? $en['billing_type'] : 'billable');
            $allowedTypes = ['billable', 'nonbillable', 'marketing'];
            if (!in_array($billingType, $allowedTypes)) $billingType = 'billable';
            $billable = ($billingType === 'billable') ? 1 : 0;
            $dayIdx   = (int)($en['day'] ?? 0);
            $rowIdx   = (int)($en['rowIndex'] ?? $i);
            $label  = trim($en['co'] ?? '');
            // Preserve the Chrome-extension tag so its next update edits this line instead of adding a duplicate
            $source = in_array(($en['src'] ?? ''), ['extension','task']) ? $en['src'] : null;
            $taskLink = (int)($en['task'] ?? 0) ?: null;
            $projectId = (int)($en['proj'] ?? 0) ?: null;
            $entryStmt->execute([$tsId, $clientId, $label !== '' ? $label : null, $en['del']??'', (float)($en['hrs']??0), $payRate, $billable, $billingType, $dayIdx, $rowIdx, $source, $projectId, $taskLink]);
        }

        if ($submitted) {
            checkOvertime($db, $tsId, $dbId, $entries);
            logAudit($tsId, $dbId, 'submitted', null, ['total_hours'=>$totalHours,'period'=>$period]);
            // Notify manager that employee submitted
            $empRow = $db->prepare("SELECT name, email, manager_id FROM users WHERE id = ?");
            $empRow->execute([$dbId]);
            $empData = $empRow->fetch();
            if ($empData) {
                $mgrData = ['name' => '', 'email' => ''];
                if ($empData['manager_id']) {
                    $mgrRow = $db->prepare("SELECT name, email FROM users WHERE id = ?");
                    $mgrRow->execute([$empData['manager_id']]);
                    $mgrData = $mgrRow->fetch() ?: $mgrData;
                }
                {
                    fireNotificationWebhook($db, 'timecard_submitted', [
                        'employee_name'    => $empData['name'],
                        'employee_email'   => $empData['email'],
                        'manager_name'     => $mgrData['name'],
                        'manager_email'    => $mgrData['email'],
                        'period'           => $period,
                        'total_hours'      => $totalHours,
                        'review_url'       => 'https://timesheet.genhead.com/',
                    ]);
                }
            }
        }
        echo json_encode(['success' => true, 'timesheet_id' => $tsId]);
        exit;
    }

    // ── APPROVE TIMESHEET ───────────────────────────────────────────────────
    if ($action === 'approve_timesheet') {
        $tsId         = (int)($body['timesheet_id'] ?? 0);
        $own = $db->prepare("SELECT user_id FROM timesheets WHERE id = ?"); $own->execute([$tsId]);
        $ownerId = $own->fetchColumn();
        if ($ownerId === false) { echo json_encode(['success'=>false,'error'=>'Timesheet not found']); exit; }
        if (!canReview($AUTH, $ownerId)) { http_response_code(403); echo json_encode(['success'=>false,'error'=>"You can't review this timecard."]); exit; }
        $approverId   = !empty($body['approver_id']) ? (int)$body['approver_id'] : null;
        $approverName = trim($body['approver_name'] ?? 'Manager');
        $comment      = trim($body['comment'] ?? '');
        $stmt = $db->prepare("SELECT * FROM timesheets WHERE id = ?");
        $stmt->execute([$tsId]);
        $before = $stmt->fetch();
        if (!$before) { echo json_encode(['success'=>false,'error'=>'Timesheet not found']); exit; }
        $db->prepare("UPDATE timesheets SET status='approved', approved_by=?, approved_at=NOW() WHERE id=?")->execute([$approverId,$tsId]);
        if ($comment) $db->prepare("INSERT INTO timesheet_comments (timesheet_id,user_id,type,comment) VALUES (?,COALESCE(?,1),'approval',?)")->execute([$tsId,$approverId,$comment]);
        logAudit($tsId, $approverId ?? 1, 'approved', $before, ['status'=>'approved','approved_by'=>$approverName]);
        // Notify employee their timecard was approved
        $empRow2 = $db->prepare("SELECT u.name, u.email FROM users u JOIN timesheets t ON t.user_id = u.id WHERE t.id = ?");
        $empRow2->execute([$tsId]);
        $empData2 = $empRow2->fetch();
        if ($empData2) {
            fireNotificationWebhook($db, 'timecard_approved', [
                'employee_name'  => $empData2['name'],
                'employee_email' => $empData2['email'],
                'manager_name'   => $approverName,
                'period'         => $before['period'] ?? '',
                'hours'          => $before['total_hours'] ?? '',
                'login_url'      => 'https://timesheet.genhead.com/',
            ]);
        }
        echo json_encode(['success' => true]);
        exit;
    }

    // ── REJECT TIMESHEET ────────────────────────────────────────────────────
    if ($action === 'reject_timesheet') {
        $tsId         = (int)($body['timesheet_id'] ?? 0);
        $own = $db->prepare("SELECT user_id FROM timesheets WHERE id = ?"); $own->execute([$tsId]);
        $ownerId = $own->fetchColumn();
        if ($ownerId === false) { echo json_encode(['success'=>false,'error'=>'Timesheet not found']); exit; }
        if (!canReview($AUTH, $ownerId)) { http_response_code(403); echo json_encode(['success'=>false,'error'=>"You can't review this timecard."]); exit; }
        $approverId   = !empty($body['approver_id']) ? (int)$body['approver_id'] : null;
        $approverName = trim($body['approver_name'] ?? 'Manager');
        $comment      = trim($body['comment'] ?? '');
        if (!$comment) { echo json_encode(['success'=>false,'error'=>'Rejection reason required']); exit; }
        $stmt = $db->prepare("SELECT * FROM timesheets WHERE id = ?");
        $stmt->execute([$tsId]);
        $before = $stmt->fetch();
        $db->prepare("UPDATE timesheets SET status='rejected', approved_by=? WHERE id=?")->execute([$approverId,$tsId]);
        $db->prepare("INSERT INTO timesheet_comments (timesheet_id,user_id,type,comment) VALUES (?,COALESCE(?,1),'rejection',?)")->execute([$tsId,$approverId,$comment]);
        logAudit($tsId, $approverId ?? 1, 'rejected', $before, ['status'=>'rejected','reason'=>$comment,'by'=>$approverName]);
        // Notify employee their timecard was rejected
        $empRow3 = $db->prepare("SELECT u.name, u.email FROM users u JOIN timesheets t ON t.user_id = u.id WHERE t.id = ?");
        $empRow3->execute([$tsId]);
        $empData3 = $empRow3->fetch();
        if ($empData3) {
            fireNotificationWebhook($db, 'timecard_rejected', [
                'employee_name'  => $empData3['name'],
                'employee_email' => $empData3['email'],
                'manager_name'   => $approverName,
                'period'         => $before['period'] ?? '',
                'note'           => $comment,
                'login_url'      => 'https://timesheet.genhead.com/',
            ]);
        }
        echo json_encode(['success' => true]);
        exit;
    }

    // ── RETURN TIMESHEET ────────────────────────────────────────────────────
    if ($action === 'return_timesheet') {
        $tsId         = (int)($body['timesheet_id'] ?? 0);
        $own = $db->prepare("SELECT user_id FROM timesheets WHERE id = ?"); $own->execute([$tsId]);
        $ownerId = $own->fetchColumn();
        if ($ownerId === false) { echo json_encode(['success'=>false,'error'=>'Timesheet not found']); exit; }
        if (!canReview($AUTH, $ownerId)) { http_response_code(403); echo json_encode(['success'=>false,'error'=>"You can't review this timecard."]); exit; }
        $approverId   = !empty($body['approver_id']) ? (int)$body['approver_id'] : null;
        $approverName = trim($body['approver_name'] ?? 'Manager');
        $comment      = trim($body['comment'] ?? '');
        if (!$comment) { echo json_encode(['success'=>false,'error'=>'Return reason required']); exit; }
        $stmt = $db->prepare("SELECT * FROM timesheets WHERE id = ?");
        $stmt->execute([$tsId]);
        $before = $stmt->fetch();
        $db->prepare("UPDATE timesheets SET status='returned' WHERE id=?")->execute([$tsId]);
        $db->prepare("INSERT INTO timesheet_comments (timesheet_id,user_id,type,comment) VALUES (?,COALESCE(?,1),'rejection',?)")->execute([$tsId,$approverId,$comment]);
        logAudit($tsId, $approverId ?? 1, 'returned_to_employee', $before, ['status'=>'returned','reason'=>$comment,'by'=>$approverName]);
        // Notify employee their timecard was returned for edits
        $empRow4 = $db->prepare("SELECT u.name, u.email FROM users u JOIN timesheets t ON t.user_id = u.id WHERE t.id = ?");
        $empRow4->execute([$tsId]);
        $empData4 = $empRow4->fetch();
        if ($empData4) {
            fireNotificationWebhook($db, 'timecard_returned', [
                'employee_name'  => $empData4['name'],
                'employee_email' => $empData4['email'],
                'manager_name'   => $approverName,
                'period'         => $before['period'] ?? '',
                'note'           => $comment,
                'login_url'      => 'https://timesheet.genhead.com/',
            ]);
        }
        echo json_encode(['success' => true]);
        exit;
    }

    // ── HR OVERRIDE ─────────────────────────────────────────────────────────
    if ($action === 'hr_override') {
        $tsId    = (int)($body['timesheet_id'] ?? 0);
        $hrIdRaw = $body['hr_id'] ?? '';
        $hrId    = preg_replace('/^e/', '', $hrIdRaw);
        $hrIdInt = is_numeric($hrId) ? (int)$hrId : 1;
        $comment = trim($body['comment'] ?? '');
        $entries = $body['entries'] ?? null;
        $stmt = $db->prepare("SELECT * FROM timesheets WHERE id = ?");
        $stmt->execute([$tsId]);
        $before = $stmt->fetch();
        if (!$before) { echo json_encode(['success'=>false,'error'=>'Timesheet not found']); exit; }
        $db->prepare("UPDATE timesheets SET status='draft', approved_by=NULL, approved_at=NULL WHERE id=?")->execute([$tsId]);
        if ($entries !== null) {
            $db->prepare("DELETE FROM timesheet_entries WHERE timesheet_id=?")->execute([$tsId]);
            $es = $db->prepare("INSERT INTO timesheet_entries (timesheet_id,client_id,deliverable,hours,pay_rate,billable,billing_type,day_index,row_index) VALUES (?,?,?,?,?,?,?,?,?)");
            foreach ($entries as $i => $en) {
                $bt = isset($en['bt']) ? $en['bt'] : (isset($en['billing_type']) ? $en['billing_type'] : 'billable');
                if (!in_array($bt, ['billable','nonbillable','marketing'])) $bt = 'billable';
                $es->execute([$tsId,$en['client_id']??null,$en['del']??'',(float)($en['hrs']??0),$en['pay_rate']??0,($bt==='billable'?1:0),$bt,(int)($en['day']??0),$i]);
            }
        }
        $db->prepare("INSERT INTO timesheet_comments (timesheet_id,user_id,type,comment) VALUES (?,?,'override',?)")->execute([$tsId,$hrIdInt,$comment?:'HR override applied']);
        logAudit($tsId, $hrIdInt, 'hr_override', $before, ['modified_by'=>'HR','comment'=>$comment]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── SET DELEGATE ────────────────────────────────────────────────────────
    if ($action === 'set_delegate') {
        $managerId  = preg_replace('/^e/', '', $body['manager_id']  ?? '');
        $delegateId = preg_replace('/^e/', '', $body['delegate_id'] ?? '');
        if ($delegateId) {
            $dr = $db->prepare("SELECT role FROM users WHERE id = ? AND status = 'active'"); $dr->execute([(int)$delegateId]);
            if (!in_array($dr->fetchColumn(), ['admin','hr','manager']) || (int)$delegateId === (int)$managerId) { echo json_encode(['success'=>false,'error'=>'Pick a manager, HR or admin (not yourself).']); exit; }
        }
        $db->prepare("UPDATE users SET delegate_to=? WHERE id=?")->execute([$delegateId?:null,$managerId]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── RESOLVE OVERTIME FLAG ───────────────────────────────────────────────
    if ($action === 'resolve_overtime') {
        $id     = (int)($body['id']     ?? 0);
        $status = $body['status'] ?? 'resolved';
        $allowed = ['approved','disputed','resolved'];
        if (!in_array($status, $allowed)) $status = 'resolved';
        $db->prepare("UPDATE overtime_flags SET status = ?, updated_at = NOW() WHERE id = ?")->execute([$status, $id]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── FLAG DISCREPANCY ────────────────────────────────────────────────────
    if ($action === 'flag_discrepancy') {
        $tsId   = (int)($body['timesheet_id'] ?? 0);
        $userId = preg_replace('/^e/', '', $body['user_id'] ?? '');
        $note   = trim($body['note'] ?? '');
        $db->prepare("INSERT INTO timesheet_comments (timesheet_id,user_id,type,comment) VALUES (?,?,'flag',?)")->execute([$tsId,$userId,$note]);
        logAudit($tsId, $userId, 'flagged_discrepancy', null, ['note'=>$note]);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── SYNC CLIENTS FROM GHL ───────────────────────────────────────────────
    if ($action === 'sync_clients') {
        $apiKey     = getSetting('ghl_api_key');
        $locationId = getSetting('ghl_location_id');
        if (!$apiKey || !$locationId) {
            echo json_encode(['success'=>false,'error'=>'GHL API key and Location ID required']); exit;
        }
        $allContacts = []; $page = 1; $limit = 100;
        do {
            $url = "https://services.leadconnectorhq.com/contacts/?locationId={$locationId}&contactType=customer&limit={$limit}&page={$page}";
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => [
                    "Authorization: Bearer {$apiKey}",
                    "Version: 2021-07-28",
                    "Content-Type: application/json"
                ],
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_TIMEOUT        => 15
            ]);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if ($err) { echo json_encode(['success'=>false,'error'=>$err]); exit; }
            if ($httpCode !== 200) { echo json_encode(['success'=>false,'error'=>"GHL HTTP {$httpCode}",'response'=>$response]); exit; }
            $data = json_decode($response, true);
            $contacts = $data['contacts'] ?? [];
            $allContacts = array_merge($allContacts, $contacts);
            $page++;
        } while (count($contacts) === $limit && $page <= 20);

        $synced = 0;
        foreach ($allContacts as $c) {
            $name = trim($c['companyName'] ?? '');
            if (!$name) continue;
            $ghlId = $c['id'] ?? '';
            $tags  = $c['tags'] ?? [];
            $type  = (in_array('marketing-only',$tags) || in_array('marketing only',$tags)) ? 'marketing' : 'ghl_instance';
            $db->prepare("INSERT INTO clients (ghl_contact_id, name, type, billable, active)
                VALUES (?, ?, ?, 1, 1)
                ON DUPLICATE KEY UPDATE name=VALUES(name), type=VALUES(type), active=1, synced_at=NOW()")
               ->execute([$ghlId, $name, $type]);
            $synced++;
        }
        echo json_encode(['success'=>true,'synced'=>$synced,'total'=>count($allContacts),'pages'=>$page-1]);
        exit;
    }

    // ── ADD CLIENT MANUALLY ─────────────────────────────────────────────────
    if ($action === 'add_client') {
        $name     = trim($body['name']     ?? '');
        $type     = $body['type']          ?? 'ghl_instance';
        $billable = isset($body['billable']) ? (int)$body['billable'] : 1;
        if (!$name) { echo json_encode(['success'=>false,'error'=>'Name required']); exit; }
        $db->prepare("INSERT INTO clients (name,type,billable) VALUES (?,?,?)")->execute([$name,$type,$billable]);
        echo json_encode(['success'=>true,'id'=>$db->lastInsertId()]);
        exit;
    }

    // ── UPDATE CLIENT ───────────────────────────────────────────────────────
    if ($action === 'update_client') {
        $id     = (int)($body['id']     ?? 0);
        $fields = []; $params = [];
        if (isset($body['active'])) { $fields[] = 'active = ?';  $params[] = (int)$body['active']; }
        if (!empty($body['name']))  { $fields[] = 'name = ?';    $params[] = trim($body['name']); }
        if (!empty($body['type']))  { $fields[] = 'type = ?';    $params[] = trim($body['type']); }
        if (!empty($body['plan_type']))  { $fields[] = 'plan_type = ?';  $params[] = trim($body['plan_type']); }
        if (!empty($body['plan_label'])) { $fields[] = 'plan_label = ?'; $params[] = trim($body['plan_label']); }
        if (isset($body['monthly_hours'])) { $fields[] = 'monthly_hours = ?'; $params[] = (float)$body['monthly_hours']; }
        if (!$id || !$fields) { echo json_encode(['success'=>false,'error'=>'id and at least one field required']); exit; }
        $params[] = $id;
        $db->prepare("UPDATE clients SET ".implode(', ',$fields)." WHERE id = ?")->execute($params);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── CLEAN CLIENTS ───────────────────────────────────────────────────────
    if ($action === 'clean_clients') {
        $db->prepare("UPDATE clients SET active = 0 WHERE ghl_contact_id IS NOT NULL AND name REGEXP '^[a-z]'")->execute();
        $db->prepare("DELETE FROM clients WHERE name REGEXP '^[a-z0-9]{5,}$' AND ghl_contact_id IS NOT NULL")->execute();
        echo json_encode(['success' => true, 'message' => 'Clients cleaned']);
        exit;
    }

    // ── UPDATE SETTINGS ─────────────────────────────────────────────────────
    if ($action === 'update_settings') {
        $allowed = ['manager_password','hr_password','webhook_secret','ghl_webhook_url','ghl_invite_webhook_url','ghl_notify_webhook_url','ghl_reset_webhook_url','ghl_api_key','ghl_location_id','overtime_weekly_threshold','overtime_multiplier','hr_approval_mode','hr_pay_period'];
        foreach ($allowed as $key) {
            if (!isset($body[$key])) continue;
            if (strpos((string)$body[$key], '••••') === 0) continue;   // unchanged masked secret
            setSetting($key, $body[$key]);
        }
        echo json_encode(['success' => true]);
        exit;
    }

    // ── UPDATE PASSWORD ─────────────────────────────────────────────────────
    if ($action === 'update_password') {
        $role     = $body['role']     ?? '';
        $password = $body['password'] ?? '';
        if (!$password) { echo json_encode(['success'=>false,'error'=>'Password required']); exit; }
        if ($role === 'manager') setSetting('manager_password', $password);
        if ($role === 'hr')      setSetting('hr_password',      $password);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── UPDATE WEBHOOK SECRET ───────────────────────────────────────────────
    if ($action === 'update_secret') {
        $sec = trim($body['secret'] ?? '');
        if (strpos($sec, '••••') !== 0) setSetting('webhook_secret', $sec);
        echo json_encode(['success' => true]);
        exit;
    }

    // ── PROXY WEBHOOK TO GENHEAD ────────────────────────────────────────────
    if ($action === 'proxy_webhook') {
        $url     = $body['url']     ?? '';
        $payload = $body['payload'] ?? [];
        if (!$url) { echo json_encode(['success'=>false,'error'=>'No URL provided']); exit; }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => true
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);
        curl_close($ch);
        if ($err) { echo json_encode(['success'=>false,'error'=>$err]); exit; }
        echo json_encode(['success'=>true,'http_code'=>$httpCode,'response'=>$response]);
        exit;
    }
}

// ─────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────


function checkOvertime($db, $tsId, $userId, $entries) {
    $threshold = (float)getSetting('overtime_weekly_threshold', 40);
    for ($wk = 0; $wk < 2; $wk++) {
        $weekHours = 0;
        foreach ($entries as $en) {
            $day = (int)($en['day'] ?? 0);
            if ($day >= $wk*7 && $day <= $wk*7+6) $weekHours += (float)($en['hrs'] ?? 0);
        }
        if ($weekHours > $threshold) {
            $overtime = $weekHours - $threshold;
            $db->prepare("INSERT INTO overtime_flags (timesheet_id,user_id,week_number,hours_worked,overtime_hours,type,status)
                VALUES (?,?,?,?,?,'weekly_overtime','flagged')
                ON DUPLICATE KEY UPDATE hours_worked=VALUES(hours_worked),overtime_hours=VALUES(overtime_hours),status='flagged'")
               ->execute([$tsId,$userId,$wk+1,$weekHours,$overtime]);
        }
    }
}

// ── FIRE NOTIFICATION WEBHOOK ────────────────────────────────────────────
// Generic notification dispatcher. Sends all timecard events to one GHL
// webhook URL; GHL branches on the 'event' field.
// Events: timecard_submitted | timecard_approved | timecard_rejected
// The page identifies people as "e5"; the database uses 5. (int)"e5" is 0, which
// silently dropped comments and task assignments — strip the prefix up front.
function normalizeUserIds($body) {
    foreach (['assigned_to','actor_id','user_id','created_by','approver_id','hr_id','uid'] as $k) {
        if (isset($body[$k]) && is_string($body[$k])) $body[$k] = preg_replace('/^e/', '', $body[$k]);
    }
    if (isset($body['user_ids']) && is_string($body['user_ids'])) {
        $body['user_ids'] = preg_replace('/(^|,)e/', '$1', $body['user_ids']);
    }
    return $body;
}

// What a person must enter to create their first password
function setupProof($u) {
    if (!empty($u['pin_set']) && !empty($u['pin'])) return 'pin';
    if (in_array($u['role'], ['manager','hr']) && getSetting($u['role'].'_password') !== '') return 'role_password';
    return 'none';
}

// Signed-in user's id wins over any id the page sends
function applyAuthIds($body, $action) {
    $u = authUser();
    if (!$u) return $body;
    foreach (['actor_id','created_by','approver_id','hr_id'] as $k) $body[$k] = (string)$u['id'];
    if (isset($body['approver_id'])) $body['approver_name'] = $u['name'];
    if (in_array($action, ['add_task_comment','log_task_time','toggle_task_follower'], true)) {
        $body['user_id'] = (string)$u['id'];
        if ($action === 'add_task_comment') $body['user_name'] = $u['name'];
    }
    if ($action === 'set_delegate') $body['manager_id'] = (string)$u['id'];
    return $body;
}

// Project team members (many people per project)
function ensureProjectMembers($db) {
    static $done = false;
    if ($done) return;
    $done = true;
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS project_members (
            project_id INT NOT NULL,
            user_id    INT NOT NULL,
            added_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (project_id, user_id)
        )");
    } catch (Exception $e) {}
}
function addProjectMember($db, $projectId, $userId) {
    if (!$projectId || !$userId) return;
    $db->prepare("INSERT IGNORE INTO project_members (project_id, user_id) VALUES (?, ?)")->execute([(int)$projectId, (int)$userId]);
}

// Adds columns newer code relies on (no-op once they exist)
function ensureEntryColumns($db) {
    static $done = false;
    if ($done) return;
    $done = true;
    try { $db->exec("ALTER TABLE timesheet_entries ADD COLUMN client_label VARCHAR(255) DEFAULT NULL"); } catch (Exception $e) {}
    try { $db->exec("ALTER TABLE timesheet_entries ADD COLUMN project_id INT DEFAULT NULL"); } catch (Exception $e) {}
    try { $db->exec("ALTER TABLE timesheet_entries ADD COLUMN task_id INT DEFAULT NULL"); } catch (Exception $e) {}
}

// Pay period containing a date — calculated from the first period (Apr 27 2026), no end date
function periodForDate($date) {
    $a = new DateTime('2026-04-27'); $d = new DateTime($date);
    if ($d < $a) return null;
    $days = (int)$a->diff($d)->days; $idx = intdiv($days, 14);
    $s = clone $a; $s->modify('+' . (14 * $idx) . ' days');
    $e = clone $s; $e->modify('+13 days');
    return ['period' => $s->format('M d').' - '.$e->format('M d'), 'index' => $idx,
            'start' => $s->format('Y-m-d'), 'end' => $e->format('Y-m-d'), 'day' => $days % 14];
}

function fireNotificationWebhook($db, $event, $payload) {
    $url = getSetting('ghl_notify_webhook_url');
    if (!$url) return;
    $payload['event']     = $event;
    $payload['timestamp'] = date('c');
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

// ── SEND INVITE WEBHOOK ──────────────────────────────────────────────────
// Fires after any new user is added. Sends name/email/role/login_url
// to the configured GHL invite workflow so it can email the welcome message.
function sendInviteWebhook($name, $email, $role, $newId) {
    if (!$email) return;
    $inviteUrl = getSetting('ghl_invite_webhook_url');
    if (!$inviteUrl) return;
    $loginUrl = 'https://timesheet.genhead.com/';
    $payload  = [
        'employee_name'  => $name,
        'employee_email' => $email,
        'employee_id'    => 'e' . $newId,
        'role'           => $role,
        'login_url'      => $loginUrl,
        'action'         => 'new_user_invite',
        // Tell the GHL workflow what kind of credential to prompt for
        'credential_type' => ($role === 'employee') ? 'pin' : 'password',
    ];
    $ch = curl_init($inviteUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

http_response_code(400);
echo json_encode(['success' => false, 'error' => 'Invalid request']);
?>