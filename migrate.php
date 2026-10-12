<?php
// migrate.php — Run once to move JSON data into MySQL
// Access at: http://localhost/timesheet/migrate.php
// DELETE THIS FILE after migration is complete

require_once __DIR__ . '/db.php';

$db = getDB();
$results = [];

// ── MIGRATE EMPLOYEES FROM employees.json ──
$empFile = __DIR__ . '/employees.json';
if (file_exists($empFile)) {
    $json = json_decode(file_get_contents($empFile), true);
    $employees = $json['employees'] ?? [];
    $migrated = 0;
    foreach ($employees as $emp) {
        $name  = $emp['name']  ?? '';
        $email = $emp['email'] ?? '';
        $pin   = $emp['pin']   ?? null;
        $pinSet = (int)($emp['pin_set'] ?? 0);
        $rate  = $emp['rate']  ?? null;
        $active = (int)($emp['active'] ?? 1);
        $fromGHL = (int)($emp['added_from_ghl'] ?? 0);
        if (!$name || in_array($name, ['Manager', 'HR'])) continue;
        // Check not already migrated
        $check = $db->prepare("SELECT id FROM users WHERE name = ? LIMIT 1");
        $check->execute([$name]);
        if ($check->fetch()) {
            $results[] = "⚠️ Skipped (exists): $name";
            continue;
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, pin, pin_set, rate, status, added_from_ghl, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'employee')");
        $stmt->execute([$name, $email, $pin, $pinSet, $rate, $active ? 'active' : 'inactive', $fromGHL]);
        $migrated++;
        $results[] = "✅ Migrated employee: $name";
    }
    // Migrate settings
    $settings = $json['settings'] ?? [];
    if (!empty($settings['manager_password'])) { setSetting('manager_password', $settings['manager_password']); $results[] = "✅ Migrated manager password"; }
    if (!empty($settings['hr_password']))      { setSetting('hr_password',      $settings['hr_password']);      $results[] = "✅ Migrated HR password"; }
    if (!empty($settings['webhook_secret']))   { setSetting('webhook_secret',   $settings['webhook_secret']);   $results[] = "✅ Migrated webhook secret"; }
    $results[] = "📊 Total employees migrated: $migrated";
} else {
    $results[] = "⚠️ employees.json not found — skipping";
}

// ── MIGRATE TIMESHEETS FROM timesheets.json ──
$tsFile = __DIR__ . '/timesheets.json';
if (file_exists($tsFile)) {
    $timesheets = json_decode(file_get_contents($tsFile), true);
    if (!is_array($timesheets)) $timesheets = [];
    $migrated = 0;
    $skipped  = 0;
    $periodStarts = [
        [2026,3,27],[2026,4,11],[2026,4,25],[2026,5,8],[2026,5,22],[2026,6,6],
        [2026,6,20],[2026,7,3],[2026,7,17],[2026,7,31],[2026,8,14],[2026,8,28],
        [2026,9,12],[2026,9,26],[2026,10,9],[2026,10,23],[2026,11,7],[2026,11,21]
    ];
    foreach ($timesheets as $ts) {
        $empName    = $ts['employee']    ?? '';
        $period     = $ts['period']      ?? '';
        $periodIdx  = (int)($ts['periodIndex'] ?? 0);
        $totalHours = (float)($ts['totalHours'] ?? 0);
        $totalPay   = (float)($ts['totalPay']   ?? 0);
        $payRate    = (float)($ts['payRate']     ?? 0);
        $isDraft    = (bool)($ts['isDraft']      ?? true);
        $submitted  = (bool)($ts['submitted']    ?? false);
        $submittedAt = $ts['submittedAt'] ?? null;
        if (!$empName || !$period) { $skipped++; continue; }

        // Find user
        $uStmt = $db->prepare("SELECT id FROM users WHERE name = ? LIMIT 1");
        $uStmt->execute([$empName]);
        $user = $uStmt->fetch();
        if (!$user) { $results[] = "⚠️ User not found for timesheet: $empName"; $skipped++; continue; }
        $userId = $user['id'];

        // Check duplicate
        $cStmt = $db->prepare("SELECT id FROM timesheets WHERE user_id = ? AND period = ? LIMIT 1");
        $cStmt->execute([$userId, $period]);
        if ($cStmt->fetch()) { $results[] = "⚠️ Timesheet exists, skipping: $empName / $period"; $skipped++; continue; }

        // Period dates
        $ps = $periodStarts[$periodIdx] ?? [2026,3,27];
        $startDate = sprintf('%04d-%02d-%02d', $ps[0], $ps[1], $ps[2]);
        $endDt = new DateTime($startDate);
        $endDt->modify('+13 days');
        $endDate = $endDt->format('Y-m-d');
        $status = $submitted ? 'submitted' : 'draft';

        // Parse submittedAt
        $submittedAtSQL = null;
        if ($submittedAt && $submittedAt !== 'null') {
            try {
                $dt = new DateTime($submittedAt);
                // Fix epoch date bug — if year is 1969/1970, use NULL
                if ($dt->format('Y') < 2020) {
                    $submittedAtSQL = null;
                } else {
                    $submittedAtSQL = $dt->format('Y-m-d H:i:s');
                }
            } catch (Exception $e) { $submittedAtSQL = null; }
        }

        $db->prepare("INSERT INTO timesheets (user_id, period, period_index, period_start, period_end,
            status, total_hours, total_pay, pay_rate, submitted_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)")
           ->execute([$userId,$period,$periodIdx,$startDate,$endDate,$status,$totalHours,$totalPay,$payRate,$submittedAtSQL]);
        $tsId = $db->lastInsertId();

        // Migrate entries
        $entries = $ts['entries'] ?? [];
        $entryStmt = $db->prepare("INSERT INTO timesheet_entries
            (timesheet_id, client_id, deliverable, hours, pay_rate, billable, day_index, row_index)
            VALUES (?,?,?,?,?,?,?,?)");
        foreach ($entries as $i => $en) {
            $coName  = $en['co']  ?? '';
            $delName = $en['del'] ?? '';
            $hrs     = (float)($en['hrs'] ?? 0);
            $dayIdx  = (int)($en['day']   ?? 0);
            $billable = 1;
            // Resolve client
            $clientId = null;
            if ($coName) {
                $cStmt2 = $db->prepare("SELECT id FROM clients WHERE name = ? LIMIT 1");
                $cStmt2->execute([$coName]);
                $client = $cStmt2->fetch();
                if ($client) {
                    $clientId = $client['id'];
                } else {
                    // Auto-create client
                    $db->prepare("INSERT INTO clients (name, type, billable) VALUES (?, 'ghl_instance', 1)")->execute([$coName]);
                    $clientId = $db->lastInsertId();
                }
                // Genhead = non-billable
                if (strtolower($coName) === 'genhead') $billable = 0;
            }
            $entryStmt->execute([$tsId, $clientId, $delName, $hrs, $payRate, $billable, $dayIdx, $i]);
        }
        $migrated++;
        $results[] = "✅ Migrated timesheet: $empName / $period ($totalHours hrs)";
    }
    $results[] = "📊 Timesheets migrated: $migrated | Skipped: $skipped";
} else {
    $results[] = "⚠️ timesheets.json not found — skipping";
}

// Output results
header('Content-Type: text/html');
echo '<!DOCTYPE html><html><head><title>Migration</title>';
echo '<style>body{font-family:monospace;padding:2rem;background:#0f172a;color:#e2e8f0}';
echo '.ok{color:#10b981}.warn{color:#f59e0b}.err{color:#ef4444}';
echo 'h1{color:#03AD8F}div{padding:.2rem 0;font-size:.9rem}</style></head><body>';
echo '<h1>Genhead Timesheet — Migration Complete</h1>';
foreach ($results as $r) {
    $cls = str_starts_with($r,'✅') ? 'ok' : (str_starts_with($r,'⚠️') ? 'warn' : '');
    echo "<div class='$cls'>$r</div>";
}
echo '<br><div style="color:#ef4444;font-weight:bold">⚠️ DELETE migrate.php from your server now that migration is complete!</div>';
echo '</body></html>';
?>
