<?php
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
layout_header('Home', 'Home');
?>
<section class="hero container">
  <span class="badge">Cloud · Security · Reliability</span>
  <h1>Infrastructure your team can <span class="grad">trust under pressure</span>.</h1>
  <p class="lead">NovaEdge runs, secures, and monitors cloud platforms for growing companies — so when an incident hits at 7am, there's already a plan running.</p>
  <p style="margin-top:26px">
    <a class="btn primary" href="/services.php">Explore services</a>
    <a class="btn ghost" href="/contact.php">Talk to us</a>
  </p>
</section>

<section class="container">
  <h2 class="section-title">What we do</h2>
  <p class="section-sub">Six core services, one accountable team.</p>
  <div class="grid cols-3">
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
  <div class="card" style="display:flex;gap:28px;align-items:center;flex-wrap:wrap">
    <div style="flex:1;min-width:260px">
      <h2 class="section-title">Latest from NovaEdge</h2>
      <p class="section-sub" style="margin:0"><?= htmlspecialchars($data['news'][0]['title']) ?></p>
    </div>
    <a class="btn ghost" href="/news.php">Read the newsroom</a>
  </div>
</section>
<?php layout_footer();
