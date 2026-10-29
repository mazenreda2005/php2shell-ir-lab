<?php
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
$map = ['operational' => ['ok','Operational'], 'degraded' => ['warn','Degraded'], 'outage' => ['bad','Outage']];
$allOk = !array_filter($data['services'], fn($s) => $s['state'] !== 'operational');
status_header('Current status', 'Status');
?>
<section class="hero container" style="padding-bottom:18px">
  <span class="badge">System Status</span>
  <h1><?= $allOk ? 'All systems <span class="grad">operational</span>.' : 'Some systems <span class="grad">degraded</span>.' ?></h1>
  <p class="lead">Live availability of NovaEdge services. Updated continuously.</p>
</section>
<section class="container">
  <div class="card">
    <table>
      <tr><th>Service</th><th>Status</th><th>30-day uptime</th></tr>
      <?php foreach ($data['services'] as $s): [$cls,$lbl] = $map[$s['state']]; ?>
        <tr>
          <td style="font-weight:600"><?= htmlspecialchars($s['name']) ?></td>
          <td><span class="pill <?= $cls ?>"><span class="dot"></span><?= $lbl ?></span></td>
          <td style="color:var(--muted)"><?= htmlspecialchars($s['uptime']) ?></td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>
</section>
<?php if ($data['maintenance']): ?>
<section class="container">
  <h2 class="section-title" style="font-size:22px">Scheduled maintenance</h2>
  <?php foreach ($data['maintenance'] as $m): ?>
    <div class="card" style="margin-top:12px">
      <strong><?= htmlspecialchars($m['title']) ?></strong>
      <div style="color:var(--muted);font-size:14px;margin-top:4px"><?= htmlspecialchars($m['date']) ?> · window <?= htmlspecialchars($m['window']) ?></div>
    </div>
  <?php endforeach; ?>
</section>
<?php endif; ?>
<?php status_footer();
