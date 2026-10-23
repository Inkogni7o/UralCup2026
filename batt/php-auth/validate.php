<?php
function is_allowed_username($username)
{
    return preg_match('/\Abutt_[abcde0-9]{16}\z/', $username) === 1;
}

function validate_credentials($username, $password)
{
    if (!is_allowed_username($username)) {
        return 'username must be 3-32 chars: letters, digits, underscore';
    }

    $passLen = strlen($password);
    if ($passLen < 8 || $passLen > 128) {
        return 'password must be 8-128 chars';
    }

    return null;
}
