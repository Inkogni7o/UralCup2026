<?php

require __DIR__ . '/jwt.php';

header('Content-Type: text/plain');
echo session_public_key();
