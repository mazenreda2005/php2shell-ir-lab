<?php
// Login page + session auth for the NovaEdge customer portal.
session_start();
require __DIR__ . '/_layout.php';
$data = require __DIR__ . '/data.php';

if (!empty($_SESSION['user'])) { header('Location: /dashboard.php'); exit; }

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
    $error = 'Session expired, please try again.';
  } else {
    $email = strtolower(trim($_POST['email'] ?? ''));
    $pass  = $_POST['password'] ?? '';
    $u = $data['users'][$email] ?? null;
    if ($u && password_verify($pass, $u['pass'])) {
      session_regenerate_id(true);
      $_SESSION['user'] = ['email' => $email, 'name' => $u['name'], 'company' => $u['company'], 'plan' => $u['plan']];
      header('Location: /dashboard.php'); exit;
    }
    $error = 'Invalid email or password.';
  }
}

portal_header('Sign in');
?>
<section class="hero container" style="max-width:460px">
  <span class="badge">Customer Portal</span>
  <h1>Welcome <span class="grad">back</span>.</h1>
  <?php if ($error): ?><div class="notice bad"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <form method="post" class="card">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
    <div class="field"><label>Email</label><input name="email" type="email" required></div>
    <div class="field"><label>Password</label><input name="password" type="password" required></div>
    <button class="btn primary" type="submit">Sign in</button>
  </form>
  <p style="color:var(--muted);font-size:13px;margin-top:14px">
    Demo account: <strong>ava@contoso.example</strong> / <strong>novaedge</strong>
  </p>
</section>
<?php portal_footer();
