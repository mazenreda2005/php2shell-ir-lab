<?php
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
$impactPill = ['none' => 'ok', 'minor' => 'warn', 'major' => 'bad'];
status_header('Incident history', 'Incidents');
?>
<section class="hero container" style="padding-bottom:10px">
  <span class="badge">Incident history</span>
  <h1>Past <span class="grad">incidents</span></h1>
  <p class="lead">A transparent record of past events and how we responded.</p>
</section>
<section class="container">
  <div class="grid">
    <?php foreach ($data['incidents'] as $i): ?>
      <article class="card">
        <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
          <span style="color:var(--muted);font-size:13px"><?= htmlspecialchars($i['date']) ?></span>
          <span class="pill <?= $impactPill[$i['impact']] ?? 'warn' ?>"><span class="dot"></span>Impact: <?= htmlspecialchars($i['impact']) ?></span>
          <?php if ($i['resolved']): ?><span class="pill ok"><span class="dot"></span>Resolved</span><?php endif; ?>
        </div>
        <h3 style="font-size:19px"><?= htmlspecialchars($i['title']) ?></h3>
        <p><?= htmlspecialchars($i['note']) ?></p>
      </article>
    <?php endforeach; ?>
  </div>
</section>
<?php status_footer();
