<?php

const SESSION_TTL_SECONDS = 15 * 60;

const GOVERNMENT_PUBLIC_KEY = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuZ+vYwfxM2pPIok7LQlf
mLeUQR1jvZa2E5N+O1Qswo6CC2OXLv//AJYQXNkupMJDetelzxG0LuJIY0CAmLtE
dqZ4jWKbVk1om5/dctMe03zlgMw/K1Xvh7Rl88tVt0UnOWbD21Yro/wxZ9zAhrVL
jz5qOCm6AkECIH8C2ZXgYZkLnPbAjoJvrj2bCS/EefsFIz/wwjMltgipVzU9IcC1
/dq5d9vWBkAMMsMkuFmP7Vc/L8Xkh5VVOyoPxtXvK9Gncr0OTsRqLwCPEm0rY7sG
tg3WKIqtDvC3/SYoFDaG2gaDpHX8ZK4WKTylikZh3V5SM8eZguWhehGm3iUnQUGI
qwIDAQAB
-----END PUBLIC KEY-----
PEM;

function jwt_base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function jwt_base64url_decode($data)
{
    if (!is_string($data) || !preg_match('/^[A-Za-z0-9_-]*$/D', $data)) {
        return false;
    }

    $remainder = strlen($data) % 4;
    if ($remainder === 1) {
        return false;
    }
    if ($remainder !== 0) {
        $data .= str_repeat('=', 4 - $remainder);
    }

    return base64_decode(strtr($data, '-_', '+/'), true);
}

function jwt_header_alg($jwt)
{
    if (!is_string($jwt)) {
        return null;
    }
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return null;
    }
    $json = jwt_base64url_decode($parts[0]);
    if ($json === false) {
        return null;
    }
    $header = json_decode($json, true);
    return is_array($header) && is_string($header['alg'] ?? null)
        ? $header['alg']
        : null;
}

function session_keys_dir()
{
    return getenv('SESSION_KEYS_DIR') ?: '/data/session-keys';
}

function read_session_key_pair($path)
{
    $raw = @file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException('cannot read the session signing key');
    }

    $pair = json_decode($raw, true);
    if (!is_array($pair) || !is_string($pair['private'] ?? null)
        || !is_string($pair['public'] ?? null)) {
        throw new RuntimeException('invalid session signing key file');
    }

    $privateKey = openssl_pkey_get_private($pair['private']);
    $details = $privateKey === false ? false : openssl_pkey_get_details($privateKey);
    if ($details === false || !isset($details['key'])
        || !hash_equals($details['key'], $pair['public'])) {
        throw new RuntimeException('session signing key pair does not match');
    }

    return $pair;
}

function generate_session_key_pair()
{
    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    if ($key === false || !openssl_pkey_export($key, $privateKey)) {
        throw new RuntimeException('cannot generate the session signing key');
    }
    $details = openssl_pkey_get_details($key);
    if ($details === false || !isset($details['key'])) {
        throw new RuntimeException('cannot export the session public key');
    }

    return ['private' => $privateKey, 'public' => $details['key']];
}

function session_key_pair()
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }

    $dir = session_keys_dir();
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('cannot create the session key directory');
    }

    $path = $dir . '/session-key.json';
    $lock = @fopen($dir . '/session-key.lock', 'c+');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        if (is_resource($lock)) {
            fclose($lock);
        }
        throw new RuntimeException('cannot lock the session signing key');
    }

    try {
        if (is_file($path)) {
            $cached = read_session_key_pair($path);
            return $cached;
        }

        $pair = generate_session_key_pair();
        $encoded = json_encode($pair, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $tmpPath = $dir . '/session-key.' . bin2hex(random_bytes(8)) . '.tmp';
        try {
            $written = @file_put_contents($tmpPath, $encoded, LOCK_EX);
            if ($written !== strlen($encoded) || !@chmod($tmpPath, 0600)
                || !@rename($tmpPath, $path)) {
                throw new RuntimeException('cannot persist the session signing key');
            }
        } finally {
            if (is_file($tmpPath)) {
                @unlink($tmpPath);
            }
        }
        $cached = $pair;
        return $cached;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function session_public_key()
{
    return session_key_pair()['public'];
}

function mint_session($userId)
{
    $now = time();
    $header = jwt_base64url_encode(json_encode(
        ['typ' => 'JWT', 'alg' => 'RS256'],
        JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    ));
    $payload = jwt_base64url_encode(json_encode([
        'sub' => (string) $userId,
        'iat' => $now,
        'exp' => $now + SESSION_TTL_SECONDS,
    ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    $signingInput = $header . '.' . $payload;
    if (!openssl_sign(
        $signingInput,
        $signature,
        session_key_pair()['private'],
        OPENSSL_ALGO_SHA256
    )) {
        throw new RuntimeException('cannot sign the session token');
    }

    return $signingInput . '.' . jwt_base64url_encode($signature);
}

function verify_government_token($jwt)
{
    if (!is_string($jwt) || jwt_header_alg($jwt) !== 'RS256') {
        throw new UnexpectedValueException('government token must use RS256');
    }

    [$header, $payload, $encodedSignature] = explode('.', $jwt);
    $payloadJson = jwt_base64url_decode($payload);
    $signature = jwt_base64url_decode($encodedSignature);
    if ($payloadJson === false || $signature === false) {
        throw new UnexpectedValueException('invalid government token encoding');
    }

    $verified = openssl_verify(
        $header . '.' . $payload,
        $signature,
        GOVERNMENT_PUBLIC_KEY,
        OPENSSL_ALGO_SHA256
    );
    if ($verified !== 1) {
        throw new UnexpectedValueException('government token signature verification failed');
    }

    $claims = json_decode($payloadJson, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($claims)) {
        throw new UnexpectedValueException('government token payload must be an object');
    }

    $now = time();
    if (isset($claims['exp']) && (!is_int($claims['exp']) || $claims['exp'] < $now)) {
        throw new UnexpectedValueException('government token is expired');
    }
    if (isset($claims['nbf']) && (!is_int($claims['nbf']) || $claims['nbf'] > $now)) {
        throw new UnexpectedValueException('government token is not active');
    }

    return $claims;
}
