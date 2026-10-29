<?php
// Fictional service-status data for NovaEdge (web-03).
return [
  'services' => [
    ['name' => 'Corporate Website',   'state' => 'operational', 'uptime' => '99.98%'],
    ['name' => 'Customer Portal',      'state' => 'operational', 'uptime' => '99.95%'],
    ['name' => 'API Gateway',          'state' => 'operational', 'uptime' => '99.99%'],
    ['name' => 'Object Storage',       'state' => 'operational', 'uptime' => '100.0%'],
    ['name' => 'Email Delivery',       'state' => 'degraded',    'uptime' => '99.21%'],
  ],
  'maintenance' => [
    ['date' => '2026-11-02 02:00 UTC', 'title' => 'Scheduled database failover test', 'window' => '30 min'],
  ],
  'incidents' => [
    ['date' => '2026-10-21', 'title' => 'Emergency PHP patch rollout (php2shell)', 'impact' => 'none',
     'resolved' => true,
     'note' => 'Patched builds deployed across hosted apps via automated response. No customer-facing downtime; one node isolated and remediated.'],
    ['date' => '2026-09-18', 'title' => 'Elevated latency in eu-north-1', 'impact' => 'minor',
     'resolved' => true,
     'note' => 'A 12-minute latency spike affecting the portal. Traced to a noisy neighbor; capacity rebalanced.'],
    ['date' => '2026-08-05', 'title' => 'Email delivery delays', 'impact' => 'minor',
     'resolved' => true,
     'note' => 'Outbound email queued for ~40 minutes due to an upstream provider issue. All messages delivered.'],
  ],
];
