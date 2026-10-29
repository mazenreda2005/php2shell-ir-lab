<?php
// Shared layout for the NovaEdge corporate site (web-01).
// $page_title and $active are set by each page before including this.
function layout_header(string $title, string $active = ''): void {
  $nav = ['/' => 'Home', '/services.php' => 'Services', '/news.php' => 'News', '/contact.php' => 'Contact'];
  ?><!doctype html><html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= htmlspecialchars($title) ?> · NovaEdge</title>
  <link rel="stylesheet" href="/assets/theme.css">
  </head><body>
  <header class="nav"><div class="container">
    <a class="brand" href="/"><span class="logo">N</span><span>NovaEdge<small>CLOUD SERVICES</small></span></a>
    <nav>
    <?php foreach ($nav as $href => $label): ?>
      <a href="<?= $href ?>"<?= $active === $label ? ' class="active"' : '' ?>><?= $label ?></a>
    <?php endforeach; ?>
    </nav>
  </div></header><main><?php
}
function layout_footer(): void { ?>
  </main>
  <footer><div class="container">
    <div>© <?= date('Y') ?> NovaEdge Cloud Services — a fictional company for a security lab.</div>
    <div>Frankfurt · London · Cairo</div>
  </div></footer>
  </body></html><?php
}
