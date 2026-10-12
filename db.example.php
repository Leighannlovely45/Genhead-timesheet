<?php
// db.php — Database connection
// Local development settings — change for production

define('DB_HOST', 'localhost');
define('DB_NAME', 'Stagging');
define('DB_USER', 'Staginguser');
define('DB_PASS', '123Staging123!');
define('DB_CHARSET', 'utf8mb4');

function getDB() {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Database connection failed: ' . $e->getMessage()]);
            exit;
        }
    }
    return $pdo;
}

function getSetting($key, $default = '') {
    $db = getDB();
    $stmt = $db->prepare("SELECT value FROM settings WHERE key = ?");
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return $row ? $row['value'] : $default;
}

function setSetting($key, $value) {
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?");
    $stmt->execute([$key, $value, $value]);
}

function logAudit($timesheetId, $userId, $action, $before = null, $after = null) {
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO audit_log (timesheet_id, user_id, action, before_state, after_state, ip_address) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([
        $timesheetId,
        $userId,
        $action,
        $before ? json_encode($before) : null,
        $after ? json_encode($after) : null,
        $_SERVER['REMOTE_ADDR'] ?? null
    ]);
}
?>
