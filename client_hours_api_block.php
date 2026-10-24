    // ── GET CLIENT HOURS — used by client-facing portal ─────────────────────
    if ($action === 'client_hours') {
        $db = getDB();
        $locationId = $_GET['location_id'] ?? '';
        $requestedPeriod = $_GET['period'] ?? '';

        if (!$locationId) {
            echo json_encode(['success'=>false,'error'=>'location_id required']); exit;
        }

        // Find client by location_id or ghl_contact_id
        $client = null;
        $stmt = $db->prepare("SELECT * FROM clients WHERE location_id = ? AND active = 1 LIMIT 1");
        $stmt->execute([$locationId]);
        $client = $stmt->fetch();
        if (!$client) {
            $stmt = $db->prepare("SELECT * FROM clients WHERE ghl_contact_id = ? AND active = 1 LIMIT 1");
            $stmt->execute([$locationId]);
            $client = $stmt->fetch();
        }
        if (!$client) {
            echo json_encode(['success'=>false,'error'=>'Client not found']); exit;
        }

        // DIY clients — return early with plan info
        if ($client['plan_type'] === 'diy') {
            echo json_encode([
                'success'    => true,
                'plan'       => 'diy',
                'plan_label' => 'DIY Plan',
                'client'     => ['name' => $client['name'], 'plan' => 'diy', 'plan_label' => 'DIY Plan']
            ]); exit;
        }

        // Build period list
        $pStarts = payPeriodStarts();
        $today = new DateTime();
        $periods = [];
        $currentPeriod = '';
        $currentPidx = 0;
        foreach ($pStarts as $i => $ps) {
            $sDt = new DateTime(sprintf('%04d-%02d-%02d', $ps[0], $ps[1], $ps[2]));
            $eDt = clone $sDt; $eDt->modify('+13 days');
            $label = $sDt->format('M j').' - '.$eDt->format('M j, Y');
            $value = $sDt->format('M j').' - '.$eDt->format('M j');
            $periods[] = ['label' => $label, 'value' => $value, 'index' => $i];
            if ($today >= $sDt && $today <= $eDt) {
                $currentPeriod = $value;
                $currentPidx   = $i;
            }
        }
        // Reverse so newest is first
        $periods = array_reverse($periods);

        // Use requested period or current
        $activePeriod = $requestedPeriod ?: $currentPeriod;
        if (!$activePeriod && count($periods) > 0) {
            $activePeriod = $periods[0]['value'];
        }

        // Get hours bank for this client + period
        $stmt = $db->prepare("SELECT * FROM client_hours_bank WHERE client_id = ? AND period = ? LIMIT 1");
        $stmt->execute([$client['id'], $activePeriod]);
        $bank = $stmt->fetch();

        // If no bank record yet — use client's monthly_hours as default
        if (!$bank) {
            $bank = [
                'total_hours' => $client['monthly_hours'] ?? 0,
                'plan_type'   => $client['plan_type']     ?? 'none',
                'plan_label'  => $client['plan_label']    ?? 'Retainer',
            ];
        }

        // Get hours used this period from timesheet_entries
        $stmt = $db->prepare("
            SELECT
                te.hours,
                te.deliverable,
                t.period,
                u.name AS team_member,
                t.start_date,
                te.day_index
            FROM timesheet_entries te
            JOIN timesheets t ON te.timesheet_id = t.id
            JOIN users u ON t.user_id = u.id
            WHERE te.client_id = ?
              AND t.period = ?
              AND t.status IN ('submitted','under_review','approved')
            ORDER BY te.day_index ASC
        ");
        $stmt->execute([$client['id'], $activePeriod]);
        $entries = $stmt->fetchAll();

        // Calculate used hours and build activity log
        $usedHours = 0;
        $activity  = [];
        foreach ($entries as $en) {
            $hrs = (float)$en['hours'];
            $usedHours += $hrs;

            // Calculate actual date from period start + day_index
            $periodStart = null;
            foreach ($pStarts as $ps) {
                $sDt = new DateTime(sprintf('%04d-%02d-%02d', $ps[0], $ps[1], $ps[2]));
                $eDt = clone $sDt; $eDt->modify('+13 days');
                $pVal = $sDt->format('M j').' - '.$eDt->format('M j');
                if ($pVal === $activePeriod) { $periodStart = $sDt; break; }
            }
            $entryDate = $periodStart
                ? (clone $periodStart)->modify('+' . (int)$en['day_index'] . ' days')->format('Y-m-d')
                : null;

            $activity[] = [
                'date'        => $entryDate,
                'deliverable' => $en['deliverable'] ?: 'Support work',
                'team_member' => $en['team_member'],
                'hours'       => $hrs,
            ];
        }

        $totalHours = (float)($bank['total_hours'] ?? 0);
        $remaining  = max(0, $totalHours - $usedHours);

        echo json_encode([
            'success' => true,
            'client'  => [
                'name'       => $client['name'],
                'plan'       => $bank['plan_type']  ?? 'retainer',
                'plan_label' => $bank['plan_label'] ?? ($client['plan_label'] ?? 'Retainer'),
            ],
            'bank' => [
                'total_hours' => $totalHours,
                'used_hours'  => round($usedHours, 2),
                'remaining'   => round($remaining, 2),
            ],
            'activity' => $activity,
            'period'   => $activePeriod,
            'periods'  => $periods,
        ]);
        exit;
    }

    // ── SET CLIENT HOURS BANK — Genhead team sets/refills hours ─────────────
    if ($action === 'set_client_hours') {
        $db = getDB();
        $clientId   = (int)($body['client_id']   ?? 0);
        $period     = trim($body['period']        ?? '');
        $pidx       = (int)($body['period_index'] ?? 0);
        $totalHours = (float)($body['total_hours'] ?? 0);
        $planType   = $body['plan_type']  ?? 'retainer';
        $planLabel  = $body['plan_label'] ?? 'Retainer';
        $notes      = trim($body['notes'] ?? '');

        if (!$clientId || !$period) {
            echo json_encode(['success'=>false,'error'=>'client_id and period required']); exit;
        }

        $db->prepare("INSERT INTO client_hours_bank
            (client_id, period, period_index, total_hours, plan_type, plan_label, notes)
            VALUES (?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE
                total_hours  = VALUES(total_hours),
                plan_type    = VALUES(plan_type),
                plan_label   = VALUES(plan_label),
                notes        = VALUES(notes),
                updated_at   = NOW()")
           ->execute([$clientId, $period, $pidx, $totalHours, $planType, $planLabel, $notes]);

        // Also update client's monthly_hours and plan for future periods
        $db->prepare("UPDATE clients SET monthly_hours=?, plan_type=?, plan_label=? WHERE id=?")
           ->execute([$totalHours, $planType, $planLabel, $clientId]);

        echo json_encode(['success'=>true,'message'=>'Hours bank updated']);
        exit;
    }

    // ── GET ALL CLIENT BANKS — Genhead admin view ───────────────────────────
    if ($action === 'load_client_banks') {
        $db = getDB();
        $period = $_GET['period'] ?? '';

        $stmt = $db->prepare("
            SELECT
                c.id,
                c.name,
                c.location_id,
                c.ghl_contact_id,
                c.plan_type,
                c.plan_label,
                c.monthly_hours,
                COALESCE(chb.total_hours, c.monthly_hours, 0) AS bank_hours,
                COALESCE(chb.plan_type,   c.plan_type, 'none') AS bank_plan,
                COALESCE(chb.plan_label,  c.plan_label, '')    AS bank_plan_label,
                COALESCE((
                    SELECT SUM(te.hours)
                    FROM timesheet_entries te
                    JOIN timesheets t ON te.timesheet_id = t.id
                    WHERE te.client_id = c.id
                      AND t.period = ?
                      AND t.status IN ('submitted','under_review','approved')
                ), 0) AS used_hours
            FROM clients c
            LEFT JOIN client_hours_bank chb ON chb.client_id = c.id AND chb.period = ?
            WHERE c.active = 1
              AND c.plan_type IN ('retainer','diy')
            ORDER BY c.name
        ");
        $stmt->execute([$period, $period]);
        $banks = $stmt->fetchAll();

        $result = array_map(function($b) {
            $total     = (float)$b['bank_hours'];
            $used      = (float)$b['used_hours'];
            $remaining = max(0, $total - $used);
            return [
                'id'          => $b['id'],
                'name'        => $b['name'],
                'location_id' => $b['location_id'] ?? $b['ghl_contact_id'],
                'plan'        => $b['bank_plan'],
                'plan_label'  => $b['bank_plan_label'],
                'total_hours' => $total,
                'used_hours'  => round($used, 2),
                'remaining'   => round($remaining, 2),
            ];
        }, $banks);

        echo json_encode(['success'=>true,'banks'=>$result]);
        exit;
    }
