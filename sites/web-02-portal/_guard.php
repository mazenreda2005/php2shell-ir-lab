<?php
// Require an authenticated session. Included at the top of every protected page.
session_start();
if (empty($_SESSION['user'])) { header('Location: /'); exit; }
$user = $_SESSION['user'];
