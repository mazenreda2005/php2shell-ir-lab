<?php
require __DIR__ . '/_guard.php';
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
portal_header('Dashboard', $user, 'Dashboard');
?>
<section class="container" style="padding-top:34px">
  <h2 class="section-title">Hi <?= htmlspecialchars($user['name']) ?> 👋</h2>
  <p class="section-sub"><?= htmlspecialchars($user['company']) ?> · <?= htmlspecialchars($user['plan']) ?> plan</p>

  <div class="grid cols-3" style="margin-bottom:22px">
    <?php foreach ($data['usage'] as $label => $pct): ?>
      <div class="card">
        <h3 style="text-transform:capitalize;font-size:15px;color:var(--muted)"><?= htmlspecialchars($label) ?></h3>
        <div style="font-size:30px;font-weight:800"><?= (int)$pct ?>%</div>
        <div style="height:8px;background:var(--bg-elev);border-radius:999px;overflow:hidden;margin-top:8px">
          <div style="height:100%;width:<?= (int)$pct ?>%;background:linear-gradient(90deg,var(--brand),var(--brand-2))"></div>
        </div>
      </div>
    <?php endforeach; ?>
  </div>

  <div class="grid cols-2">
    <div class="card">
      <h3>Recent account activity</h3>
      <table>
        <?php foreach ($data['history'] as $h): ?>
          <tr>
            <td style="white-space:nowrap;color:var(--muted)"><?= htmlspecialchars($h['date']) ?></td>
            <td><?= htmlspecialchars($h['event']) ?></td>
            <td><span class="pill <?= $h['kind'] ?>"><span class="dot"></span><?= $h['kind']==='ok'?'OK':'Notice' ?></span></td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
    <div class="card">
      <h3>Open tickets</h3>
      <table>
        <?php foreach ($data['tickets'] as $t): if ($t['status'] === 'Resolved') continue; ?>
          <tr>
            <td style="color:var(--muted)"><?= htmlspecialchars($t['id']) ?></td>
            <td><?= htmlspecialchars($t['subject']) ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
      <p style="margin-top:14px"><a class="btn ghost" href="/tickets.php">View all tickets</a></p>
    </div>
  </div>
</section>
<?php portal_footer();
