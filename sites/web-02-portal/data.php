<?php
// Fictional portal data. Passwords are hashes of the demo password "novaedge".
// NOTHING here is real customer data.
return [
  'users' => [
    'ava@contoso.example' => [
      'name' => 'Ava Mitchell', 'company' => 'Contoso Retail', 'plan' => 'Business',
      // bcrypt hash of the demo password "novaedge"
      'pass' => '$2b$10$sYB3D6hUPWEH.NhfJ2KAJe105u2qO3CReCvOk27PN1vqvQDCBhd1W',
    ],
    'sam@globex.example' => [
      'name' => 'Sam Okoro', 'company' => 'Globex Media', 'plan' => 'Starter',
      'pass' => '$2b$10$sYB3D6hUPWEH.NhfJ2KAJe105u2qO3CReCvOk27PN1vqvQDCBhd1W',
    ],
  ],
  'tickets' => [
    ['id' => 'TCK-4021', 'subject' => 'Increase storage quota on prod bucket', 'status' => 'Open',     'updated' => '2026-10-27'],
    ['id' => 'TCK-3987', 'subject' => 'TLS certificate renewal for portal domain', 'status' => 'Resolved',  'updated' => '2026-10-19'],
    ['id' => 'TCK-3955', 'subject' => 'Question about October invoice',           'status' => 'Waiting',   'updated' => '2026-10-15'],
  ],
  'history' => [
    ['date' => '2026-10-21', 'event' => 'Emergency PHP patch applied to hosted apps', 'kind' => 'ok'],
    ['date' => '2026-10-01', 'event' => 'Monthly backup verified (restore test passed)', 'kind' => 'ok'],
    ['date' => '2026-09-18', 'event' => 'Brief latency spike in eu-north-1 (12 min)', 'kind' => 'warn'],
  ],
  'usage' => ['compute' => 68, 'storage' => 41, 'bandwidth' => 55],
];
