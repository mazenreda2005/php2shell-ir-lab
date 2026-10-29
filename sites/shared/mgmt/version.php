<?php
// Restricted management endpoint — deployed to every node at /mgmt/version.php.
// Returns the ACTUAL running PHP version, but only to an authenticated caller.
// This keeps real version info OUT of public pages/health checks (hardening §5),
// and is the trusted source the fleet detector / dashboard use.
//
// Auth: caller must present header  X-Mgmt-Token: <token>  matching the
// MGMT_TOKEN environment variable injected into the container at deploy time.

header('Content-Type: application/json');
header('Cache-Control: no-store');

$expected = getenv('MGMT_TOKEN') ?: '';
$provided = $_SERVER['HTTP_X_MGMT_TOKEN'] ?? '';

if ($expected === '' || !hash_equals($expected, $provided)) {
  http_response_code(403);
  echo json_encode(['error' => 'forbidden']);
  exit;
}

echo json_encode([
  'php'       => phpversion(),
  'host'      => gethostname(),
  'checked_at'=> gmdate('c'),
], JSON_PRETTY_PRINT);
