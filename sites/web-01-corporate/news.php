<?php
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';
layout_header('News', 'News');
?>
<section class="hero container" style="padding-bottom:10px">
  <span class="badge">Newsroom</span>
  <h1>What's happening at <span class="grad">NovaEdge</span></h1>
</section>
<section class="container">
  <div class="grid">
    <?php foreach ($data['news'] as $n): ?>
      <article class="card">
        <div style="display:flex;gap:12px;align-items:center;margin-bottom:10px">
          <span class="pill ok"><span class="dot"></span><?= htmlspecialchars($n['tag']) ?></span>
          <span style="color:var(--muted);font-size:13px"><?= htmlspecialchars($n['date']) ?></span>
        </div>
        <h3 style="font-size:20px"><?= htmlspecialchars($n['title']) ?></h3>
        <p><?= htmlspecialchars($n['body']) ?></p>
      </article>
    <?php endforeach; ?>
  </div>
</section>
<?php layout_footer();
