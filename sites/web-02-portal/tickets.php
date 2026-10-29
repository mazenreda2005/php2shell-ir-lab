<?php
require __DIR__ . '/_guard.php';
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
$statusPill = ['Open' => 'warn', 'Waiting' => 'warn', 'Resolved' => 'ok'];
portal_header('Tickets', $user, 'Tickets');
?>
<section class="container" style="padding-top:34px">
  <h2 class="section-title">Support tickets</h2>
  <p class="section-sub">All requests for <?= htmlspecialchars($user['company']) ?></p>
  <div class="card">
    <table>
      <tr><th>ID</th><th>Subject</th><th>Status</th><th>Updated</th></tr>
      <?php foreach ($data['tickets'] as $t): ?>
        <tr>
          <td style="color:var(--muted)"><?= htmlspecialchars($t['id']) ?></td>
          <td><?= htmlspecialchars($t['subject']) ?></td>
          <td><span class="pill <?= $statusPill[$t['status']] ?? 'warn' ?>"><span class="dot"></span><?= htmlspecialchars($t['status']) ?></span></td>
          <td style="color:var(--muted)"><?= htmlspecialchars($t['updated']) ?></td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>
</section>
<?php portal_footer();
