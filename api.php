<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("X-Frame-Options: ALLOWALL");
header("Content-Security-Policy: frame-ancestors *");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

require_once __DIR__ . '/db.php';

$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

// ─────────────────────────────────────────
// GET ACTIONS
// ─────────────────────────────────────────
if ($method === 'GET') {

    if ($action === 'load') {
        $db = getDB();
        $employees = $db->query("SELECT id, ghl_contact_id, name, email, role, pin, pin_set, password_set, rate, status, delegate_to, added_from_ghl, manager_id FROM users WHERE status = 'active' ORDER BY name")->fetchAll();
        $settings = [];
        foreach ($db->query("SELECT `key`, `value` FROM settings")->fetchAll() as $row) {
            $settings[$row['key']] = $row['value'];
        }
        $formatted = array_map(function($e) {
            return [
                'id'             => 'e' . $e['id'],
                'db_id'          => $e['id'],
                'ghl_contact_id' => $e['ghl_contact_id'],
                'name'           => $e['name'],
                'email'          => $e['email'],
                'role'           => $e['role'],
                'pin'            => $e['pin'],
                'pin_set'        => (bool)$e['pin_set'],
                'password_set'   => (bool)$e['password_set'],
                'rate'           => $e['rate'],
                'active'         => $e['status'] === 'active',
                'added_from_ghl' => (bool)$e['added_from_ghl'],
                'manager_id'     => $e['manager_id'],
            ];
        }, $employees);
        echo json_encode(['success' => true, 'data' => ['employees' => $formatted, 'settings' => $settings]]);
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
        $uid = isset($_GET['uid']) ? $_GET['uid'] : '';
        $period = isset($_GET['period']) ? $_GET['period'] : '';
        $dbId = preg_replace('/^e/', '', $uid);
        $stmt = $db->prepare("SELECT t.*, u.name as employee_name, u.email as employee_email, u.rate as employee_rate
            FROM timesheets t JOIN users u ON t.user_id = u.id
            WHERE t.user_id = ? AND t.period = ? LIMIT 1");
        $stmt->execute([$dbId, $period]);
        $ts = $stmt->fetch();
        if (!$ts) { echo json_encode(['success' => false, 'record' => null]); exit; }
        $stmt2 = $db->prepare("SELECT te.*, c.name as client_name FROM timesheet_entries te
            LEFT JOIN clients c ON te.client_id = c.id
            WHERE te.timesheet_id = ? ORDER BY te.day_index, te.row_index");
        $stmt2->execute([$ts['id']]);
        $entries = $stmt2->fetchAll();
        $ts['entries'] = $entries;
        $ts['submitted'] = $ts['status'] !== 'draft';
        echo json_encode(['success' => true, 'record' => $ts]);
        exit;
    }

    if ($action === 'load_timesheets') {
        $db = getDB();
        $stmt = $db->query("SELECT t.*, u.name as employee, u.email,
            a.name as approved_by_name
            FROM timesheets t
            JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.approved_by = a.id
            ORDER BY t.submitted_at DESC");
        $timesheets = $stmt->fetchAll();
        foreach ($timesheets as &$ts) {
            $stmt2 = $db->prepare("SELECT te.*, c.name as client_name FROM timesheet_entries te
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
        $pStarts = [[2026,4,27],[2026,5,11],[2026,5,25],[2026,6,8],[2026,6,22],[2026,7,6],
            [2026,7,20],[2026,8,3],[2026,8,17],[2026,8,31],[2026,9,14],[2026,9,28],
            [2026,10,12],[2026,10,26],[2026,11,9],[2026,11,23],[2026,12,7],[2026,12,21]];
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
// POST ACTIONS
// ─────────────────────────────────────────
if ($method === 'POST') {
    $rawBody = file_get_contents('php://input');
    $body = json_decode($rawBody, true);
    if (!is_array($body)) $body = [];
    $db = getDB();

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
        $pStarts = [
            [2026,4,27],[2026,5,11],[2026,5,25],[2026,6,8],[2026,6,22],[2026,7,6],
            [2026,7,20],[2026,8,3],[2026,8,17],[2026,8,31],[2026,9,14],[2026,9,28],
            [2026,10,12],[2026,10,26],[2026,11,9],[2026,11,23],[2026,12,7],[2026,12,21]
        ];
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
        $stmt = $db->prepare("SELECT id, password, password_hash, password_set, name, role FROM users WHERE id = ? AND role IN ('manager','hr','admin') AND status = 'active' LIMIT 1");
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
        $stmt = $db->prepare("SELECT id, role FROM users WHERE id = ? AND role IN ('manager','hr','admin') AND status = 'active' LIMIT 1");
        $stmt->execute([$id]);
        if (!$stmt->fetch()) { echo json_encode(['success' => false, 'error' => 'User not found']); exit; }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $db->prepare("UPDATE users SET password_hash = ?, password_set = 1 WHERE id = ?")->execute([$hash, $id]);
        echo json_encode(['success' => true]);
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

        $stmt = $db->prepare("SELECT id FROM users WHERE LOWER(name) = LOWER(?) LIMIT 1");
        $stmt->execute([$name]);
        $existing = $stmt->fetch();
        if ($existing) {
            // Update ghl_contact_id if we now have it
            if ($ghlContactId) {
                $db->prepare("UPDATE users SET ghl_contact_id = ? WHERE id = ?")->execute([$ghlContactId, $existing['id']]);
            }
            echo json_encode(['success' => true, 'message' => 'Employee already exists', 'id' => 'e' . $existing['id']]);
            exit;
        }
        $stmt = $db->prepare("INSERT INTO users (name, email, role, ghl_contact_id, added_from_ghl) VALUES (?, ?, 'employee', ?, 1)");
        $stmt->execute([$name, $email, $ghlContactId ?: null]);
        $newId = $db->lastInsertId();
        logAudit(null, $newId, 'ghl_auto_add', null, ['name' => $name, 'email' => $email]);

        // ── SEND INVITE WEBHOOK BACK TO GHL ─────────────────────────────────
        // Fires a GHL workflow webhook so GHL can email the employee their
        // login link + prompt them to set their PIN on first sign-in.
        if ($email) {
            $inviteUrl = getSetting('ghl_invite_webhook_url');
            if ($inviteUrl) {
                $loginUrl = 'https://timesheet.genhead.com/';
                $payload  = [
                    'employee_name'  => $name,
                    'employee_email' => $email,
                    'employee_id'    => 'e' . $newId,
                    'login_url'      => $loginUrl,
                    'action'         => 'new_employee_invite',
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
        }

        echo json_encode(['success' => true, 'message' => 'Employee added', 'id' => 'e' . $newId]);
        exit;
    }

    // ── ADD EMPLOYEE MANUALLY ───────────────────────────────────────────────
    if ($action === 'add_employee') {
        $name  = trim($body['name']  ?? '');
        $email = trim($body['email'] ?? '');
        $pin   = trim($body['pin']   ?? '');
        if (!$name) { echo json_encode(['success' => false, 'error' => 'Name required']); exit; }
        $stmt = $db->prepare("INSERT INTO users (name, email, pin, pin_set, role) VALUES (?, ?, ?, ?, 'employee')");
        $stmt->execute([$name, $email, $pin ?: null, $pin ? 1 : 0]);
        $newId = $db->lastInsertId();
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
        $stmt = $db->prepare("INSERT INTO users (name, email, role, password_hash, password_set, status) VALUES (?, ?, ?, ?, ?, 'active')");
        $stmt->execute([$name, $email, $role, $hash, $password ? 1 : 0]);
        $newId = $db->lastInsertId();
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
            $db->prepare("INSERT INTO settings (key_name, value) VALUES (?,?) ON DUPLICATE KEY UPDATE value=?")->execute([$key, $val, $val]);
            $resetUrl = 'https://timesheet.genhead.com/index.html?reset_token=' . $token . '&uid=' . $user['id'];
            $isPin    = $user['role'] === 'employee';
            $subject  = 'Genhead Timesheet — Reset Your ' . ($isPin ? 'PIN' : 'Password');
            $thing    = $isPin ? 'PIN' : 'password';
            $message  = "Hi {$user['name']},\n\nYou requested a {$thing} reset for the Genhead Timesheet Portal.\n\nClick the link below to set a new {$thing} (expires in 1 hour):\n\n{$resetUrl}\n\nIf you did not request this, you can ignore this email.\n\n— Genhead Team";
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
        $stmt = $db->prepare("SELECT value FROM settings WHERE key_name = ? LIMIT 1");
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
        if ($uRow['role'] === 'employee') {
            if (strlen($pin) !== 4 || !ctype_digit($pin)) {
                echo json_encode(['success' => false, 'error' => 'PIN must be 4 digits']); exit;
            }
            $db->prepare("UPDATE users SET pin = ?, pin_set = 1 WHERE id = ?")->execute([$pin, $uid]);
        } else {
            if (strlen($pass) < 6) {
                echo json_encode(['success' => false, 'error' => 'Password must be at least 6 characters']); exit;
            }
            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $db->prepare("UPDATE users SET password_hash = ?, password_set = 1 WHERE id = ?")->execute([$hash, $uid]);
        }
        $db->prepare("DELETE FROM settings WHERE key_name = ?")->execute([$key]);
        echo json_encode(['success' => true, 'role' => $uRow['role']]);
        exit;
    }

    // ── SAVE TIMESHEET ──────────────────────────────────────────────────────
    if ($action === 'save_timesheet') {
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

        $periodStarts = [
            [2026,4,27],[2026,5,11],[2026,5,25],[2026,6,8],[2026,6,22],[2026,7,6],
            [2026,7,20],[2026,8,3],[2026,8,17],[2026,8,31],[2026,9,14],[2026,9,28],
            [2026,10,12],[2026,10,26],[2026,11,9],[2026,11,23],[2026,12,7],[2026,12,21]
        ];
        $ps        = $periodStarts[$periodIndex] ?? [2026,3,27];
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

        $db->prepare("DELETE FROM timesheet_entries WHERE timesheet_id = ?")->execute([$tsId]);
        $entryStmt = $db->prepare("INSERT INTO timesheet_entries (timesheet_id, client_id, deliverable, hours, pay_rate, billable, billing_type, day_index, row_index) VALUES (?,?,?,?,?,?,?,?,?)");
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
            $entryStmt->execute([$tsId, $clientId, $en['del']??'', (float)($en['hrs']??0), $payRate, $billable, $billingType, $dayIdx, $rowIdx]);
        }

        if ($submitted) {
            checkOvertime($db, $tsId, $dbId, $entries);
            logAudit($tsId, $dbId, 'submitted', null, ['total_hours'=>$totalHours,'period'=>$period]);
        }
        echo json_encode(['success' => true, 'timesheet_id' => $tsId]);
        exit;
    }

    // ── APPROVE TIMESHEET ───────────────────────────────────────────────────
    if ($action === 'approve_timesheet') {
        $tsId         = (int)($body['timesheet_id'] ?? 0);
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
        echo json_encode(['success' => true]);
        exit;
    }

    // ── REJECT TIMESHEET ────────────────────────────────────────────────────
    if ($action === 'reject_timesheet') {
        $tsId         = (int)($body['timesheet_id'] ?? 0);
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
        echo json_encode(['success' => true]);
        exit;
    }

    // ── RETURN TIMESHEET ────────────────────────────────────────────────────
    if ($action === 'return_timesheet') {
        $tsId         = (int)($body['timesheet_id'] ?? 0);
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
        $active = isset($body['active']) ? (int)$body['active'] : 1;
        $db->prepare("UPDATE clients SET active = ? WHERE id = ?")->execute([$active, $id]);
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
        $allowed = ['manager_password','hr_password','webhook_secret','ghl_webhook_url','ghl_invite_webhook_url','ghl_api_key','ghl_location_id','overtime_weekly_threshold','overtime_multiplier'];
        foreach ($allowed as $key) { if (isset($body[$key])) setSetting($key, $body[$key]); }
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
        setSetting('webhook_secret', trim($body['secret'] ?? ''));
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

http_response_code(400);
echo json_encode(['success' => false, 'error' => 'Invalid request']);
?>