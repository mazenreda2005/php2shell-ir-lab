<?php
// PUBLIC health check — intentionally discloses NO version information (§5).
// Vulnerability detection uses the authenticated /mgmt/version.php instead.
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo json_encode(['status' => 'ok']);
