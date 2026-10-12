<?php
$apiFile = __DIR__ . '/api.php';
$content = file_get_contents($apiFile);

// Include draft timesheets in client hours display
$old = "AND t.status IN ('submitted','under_review','approved')";
$new = "AND t.status IN ('draft','submitted','under_review','approved')";

$count = substr_count($content, $old);
echo "Found: " . $count . " occurrences<br>";
$content = str_replace($old, $new, $content);
file_put_contents($apiFile, $content);
echo "Fixed! Clients now see hours in real time including draft timesheets.";
?>