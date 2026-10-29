<?php
function status_header(string $title, string $active=''): void { ?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($title) ?> · NovaEdge Status</title>
<link rel="stylesheet" href="/assets/theme.css"></head><body>
<header class="nav"><div class="container">
  <a class="brand" href="/"><span class="logo">N</span><span>NovaEdge<small>SERVICE STATUS</small></span></a>
  <nav>
    <a href="/"<?= $active==='Status'?' class="active"':'' ?>>Current status</a>
    <a href="/incidents.php"<?= $active==='Incidents'?' class="active"':'' ?>>Incident history</a>
  </nav>
</div></header><main><?php }
function status_footer(): void { ?></main>
<footer><div class="container">
  <div>© <?= date('Y') ?> NovaEdge Cloud Services — fictional status page (security lab).</div>
  <div>Subscribe to updates · RSS</div>
</div></footer></body></html><?php }
