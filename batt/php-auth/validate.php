<?php
function is_allowed_username($username)
{
    $userLen = strlen($username);
    if ($userLen < 3 || $userLen > 32) {
        return false;
    }
    return true;
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
