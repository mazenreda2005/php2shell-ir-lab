<?php
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
layout_header('Services', 'Services');
?>
<section class="hero container" style="padding-bottom:10px">
  <span class="badge">Services</span>
  <h1>Everything to run a platform <span class="grad">well</span>.</h1>
  <p class="lead">From the first deploy to the 3am page, NovaEdge covers the operational and security surface so your engineers can ship.</p>
</section>
<section class="container">
  <div class="grid cols-2">
    <?php foreach ($data['services'] as $s): ?>
      <div class="card">
        <div class="icon"><?= $s['icon'] ?></div>
        <h3><?= htmlspecialchars($s['title']) ?></h3>
        <p><?= htmlspecialchars($s['desc']) ?></p>
      </div>
    <?php endforeach; ?>
  </div>
</section>
<section class="container">
  <div class="card" style="text-align:center">
    <h2 class="section-title" style="justify-self:center">Not sure where to start?</h2>
    <p class="section-sub">Tell us about your stack and we'll map a plan.</p>
    <a class="btn primary" href="/contact.php">Request a consultation</a>
  </div>
</section>
<?php layout_footer();
