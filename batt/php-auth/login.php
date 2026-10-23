<?php

require __DIR__ . '/db.php';
require __DIR__ . '/validate.php';
require __DIR__ . '/jwt.php';
require __DIR__ . '/cookie.php';

$body = json_decode(file_get_contents('php://input'), true) ?: [];
$username = (string) ($body['username'] ?? '');
$password = (string) ($body['password'] ?? '');

if (!is_allowed_username($username)) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    return;
}

$pdo = auth_db();
$stmt = $pdo->prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
$stmt->execute([$username]);
$row = $stmt->fetch();

if (!$row || !is_allowed_username($row['username']) || !password_verify($password, $row['password_hash'])) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    return;
}

$userId = (int) $row['id'];

$rememberCode = remember_new_code($userId);
remember_create($pdo, $userId, $rememberCode);
set_remember_cookie($rememberCode);

$jwt = mint_session($userId);
set_session_cookie($jwt);

echo json_encode(['id' => (int) remember_obfuscate_id($userId), 'username' => $row['username']]);
