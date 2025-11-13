<?php
// PART OF THE ANTI-BOT IMPLEMENTATION FOR TM


/*CONFIG*/
// difficulty:
// ~ 16^$difficulty attempts average 
$difficulty = 4;        //WHEN UPDATING THIS, DO SO AS WELL FOR VERIFY.PHP




/* DON'T TOUCH */
header('Content-Type: application/json');

// file-based nonce store map (directory must be writable)
$nonceStoreDir = __DIR__ . '/_nonces';
if (!is_dir($nonceStoreDir)) mkdir($nonceStoreDir, 0700, true);

// nonce generation
$nonce = bin2hex(random_bytes(16));
$expires = time() + 60; // nonce lifetime of 60s

file_put_contents("$nonceStoreDir/$nonce", json_encode(['expires' => $expires, 'used' => false]));

// response
echo json_encode([
  'nonce' => $nonce,
  'difficulty' => $difficulty,
  'expires' => $expires
]);