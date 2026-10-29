<?php
// Contact page with real server-side handling + validation + CSRF protection.
session_start();
require __DIR__ . '/_layout.php';

if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

$errors = [];
$sent = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // CSRF check
  if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
    $errors[] = 'Your session expired. Please try again.';
  }
  $name    = trim($_POST['name'] ?? '');
  $email   = trim($_POST['email'] ?? '');
  $company = trim($_POST['company'] ?? '');
  $message = trim($_POST['message'] ?? '');

  if ($name === '' || mb_strlen($name) > 80)        $errors[] = 'Please enter your name (under 80 characters).';
  if (!filter_var($email, FILTER_VALIDATE_EMAIL))    $errors[] = 'Please enter a valid email address.';
  if ($message === '' || mb_strlen($message) > 2000) $errors[] = 'Please enter a message (under 2000 characters).';

  if (!$errors) {
    // Persist to a local, non-public inbox file (fictional lab — no real email sent).
    $record = [
      'ts'      => gmdate('c'),
      'name'    => $name,
      'email'   => $email,
      'company' => $company,
      'message' => $message,
      'ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
    ];
    $inbox = '/var/www/private/contact_inbox.jsonl'; // outside web root
    @mkdir(dirname($inbox), 0750, true);
    @file_put_contents($inbox, json_encode($record) . "\n", FILE_APPEND | LOCK_EX);
    $sent = true;
    // Rotate CSRF token after a successful submit.
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
  }
}

layout_header('Contact', 'Contact');
?>
<section class="hero container" style="padding-bottom:10px">
  <span class="badge">Contact</span>
  <h1>Let's talk about your <span class="grad">infrastructure</span>.</h1>
  <p class="lead">Send us a note and a NovaEdge engineer will get back to you.</p>
</section>
<section class="container" style="max-width:680px">
  <?php if ($sent): ?>
    <div class="notice ok">✓ Thanks, <?= htmlspecialchars($name) ?> — your message was received. We'll be in touch at <?= htmlspecialchars($email) ?>.</div>
  <?php endif; ?>
  <?php foreach ($errors as $e): ?>
    <div class="notice bad"><?= htmlspecialchars($e) ?></div>
  <?php endforeach; ?>

  <form method="post" class="card" novalidate>
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
    <div class="field"><label>Name</label>
      <input name="name" maxlength="80" value="<?= htmlspecialchars($_POST['name'] ?? '') ?>" required></div>
    <div class="field"><label>Work email</label>
      <input name="email" type="email" value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required></div>
    <div class="field"><label>Company (optional)</label>
      <input name="company" maxlength="120" value="<?= htmlspecialchars($_POST['company'] ?? '') ?>"></div>
    <div class="field"><label>How can we help?</label>
      <textarea name="message" rows="5" maxlength="2000" required><?= htmlspecialchars($_POST['message'] ?? '') ?></textarea></div>
    <button class="btn primary" type="submit">Send message</button>
  </form>
</section>
<?php layout_footer();
