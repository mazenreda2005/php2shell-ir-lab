<?php
function portal_header(string $title, ?array $user = null, string $active = ''): void {
  ?><!doctype html><html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= htmlspecialchars($title) ?> · NovaEdge Portal</title>
  <link rel="stylesheet" href="/assets/theme.css">
  </head><body>
  <header class="nav"><div class="container">
    <a class="brand" href="/"><span class="logo">N</span><span>NovaEdge<small>CUSTOMER PORTAL</small></span></a>
    <nav>
    <?php if ($user): ?>
      <a href="/dashboard.php"<?= $active==='Dashboard'?' class="active"':'' ?>>Dashboard</a>
      <a href="/tickets.php"<?= $active==='Tickets'?' class="active"':'' ?>>Tickets</a>
      <a href="/requests.php"<?= $active==='Requests'?' class="active"':'' ?>>Requests</a>
      <a href="/logout.php">Sign out (<?= htmlspecialchars($user['name']) ?>)</a>
    <?php else: ?>
      <a href="/" class="active">Sign in</a>
    <?php endif; ?>
    </nav>
  </div></header><main><?php
}
function portal_footer(): void { ?>
  </main>
  <footer><div class="container">
    <div>© <?= date('Y') ?> NovaEdge Cloud Services — fictional customer portal (security lab).</div>
    <div>Status: <a href="#">status.novaedge.example</a></div>
  </div></footer>
  </body></html><?php
}
