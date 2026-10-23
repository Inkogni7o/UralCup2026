<?php

require __DIR__ . '/../remember.php';
require __DIR__ . '/../jwt.php';

function check($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

final class FakeStatement
{
    public $value;
    public $type;
    public $row;

    public function __construct($row = false)
    {
        $this->row = $row;
    }

    public function bindValue($position, $value, $type)
    {
        $this->value = $value;
        $this->type = $type;
    }

    public function execute()
    {
        return true;
    }

    public function fetch()
    {
        return $this->row;
    }
}

final class FakePdo
{
    public $prepareCount = 0;
    public $statement;

    public function __construct($row = false)
    {
        $this->statement = new FakeStatement($row);
    }

    public function prepare($query)
    {
        $this->prepareCount++;
        return $this->statement;
    }
}

$numericCookie = base64_encode(json_encode(['code' => 123456]));
$pdo = new FakePdo(['user_id' => 99]);
check(remember_find_active($pdo, $numericCookie) === null, 'numeric remember code accepted');
check($pdo->prepareCount === 0, 'database queried for invalid remember code');

$code = '123456' . str_repeat('A', REMEMBER_SECRET_LEN);
$pdo = new FakePdo(['user_id' => 99]);
check(remember_find_active($pdo, remember_encode_cookie($code)) === 99, 'valid remember code rejected');
check($pdo->statement->value === $code, 'remember code changed before lookup');
check($pdo->statement->type === PDO::PARAM_STR, 'remember code was not bound as a string');

$keyDir = sys_get_temp_dir() . '/batt-session-' . bin2hex(random_bytes(8));
putenv('SESSION_KEYS_DIR=' . $keyDir);
$session = mint_session(99);
[$header, $payload, $signature] = explode('.', $session);
check(jwt_header_alg($session) === 'RS256', 'session token did not use RS256');
check(
    openssl_verify(
        $header . '.' . $payload,
        jwt_base64url_decode($signature),
        session_public_key(),
        OPENSSL_ALGO_SHA256
    ) === 1,
    'session token signature is invalid'
);
check(is_file($keyDir . '/session-key.json'), 'session key was not persisted');

$forgedHeader = jwt_base64url_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
$forgedPayload = jwt_base64url_encode(json_encode(['game_id' => 1]));
$forgedInput = $forgedHeader . '.' . $forgedPayload;
$forgedToken = $forgedInput . '.' . jwt_base64url_encode(
    hash_hmac('sha256', $forgedInput, GOVERNMENT_PUBLIC_KEY, true)
);
$rejected = false;
try {
    verify_government_token($forgedToken);
} catch (UnexpectedValueException $e) {
    $rejected = true;
}
check($rejected, 'HS256 government token was accepted');

@unlink($keyDir . '/session-key.json');
@unlink($keyDir . '/session-key.lock');
@rmdir($keyDir);

echo "security tests: OK\n";
