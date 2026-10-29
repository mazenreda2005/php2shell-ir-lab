<?php
// Service requests page — submit a new request (server-side validated + CSRF).
require __DIR__ . '/_guard.php';
require __DIR__ . '/_layout.php';

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$ok = false; $errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) $errors[] = 'Session expired.';
  $type = $_POST['type'] ?? '';
  $detail = trim($_POST['detail'] ?? '');
  $allowed = ['Scale compute', 'Add storage', 'New environment', 'Other'];
  if (!in_array($type, $allowed, true)) $errors[] = 'Please choose a valid request type.';
  if ($detail === '' || mb_strlen($detail) > 1000) $errors[] = 'Please add detail (under 1000 chars).';
  if (!$errors) {
    $rec = ['ts'=>gmdate('c'),'user'=>$user['email'],'type'=>$type,'detail'=>$detail];
    @mkdir('/var/www/private', 0750, true);
    @file_put_contents('/var/www/private/service_requests.jsonl', json_encode($rec)."\n", FILE_APPEND|LOCK_EX);
    $ok = true; $_SESSION['csrf'] = bin2hex(random_bytes(16));
  }
}
portal_header('Requests', $user, 'Requests');
?>
<section class="container" style="padding-top:34px;max-width:640px">
  <h2 class="section-title">New service request</h2>
  <p class="section-sub">Ask our team to make a change to your environment.</p>
  <?php if ($ok): ?><div class="notice ok">✓ Request submitted. Our team will review it shortly.</div><?php endif; ?>
  <?php foreach ($errors as $e): ?><div class="notice bad"><?= htmlspecialchars($e) ?></div><?php endforeach; ?>
  <form method="post" class="card">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
    <div class="field"><label>Request type</label>
      <select name="type">
        <option>Scale compute</option><option>Add storage</option>
        <option>New environment</option><option>Other</option>
      </select></div>
    <div class="field"><label>Details</label><textarea name="detail" rows="4" maxlength="1000" required></textarea></div>
    <button class="btn primary" type="submit">Submit request</button>
  </form>
</section>
<?php portal_footer();
