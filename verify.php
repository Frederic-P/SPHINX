<?php
// PART OF THE ANTI-BOT IMPLEMENTATION FOR TM

/**CONFIG */
$difficulty = 4; // This should be the same as challenge.php




/**CODE DON'T TOUCH */
// // POST JSON: { nonce: "...", suffix: "..." }
header('Content-Type: application/json');

// config
$nonceStoreDir = __DIR__ . '/_nonces';
$sessionStoreDir = __DIR__ . '/_sessions';
if (!is_dir($sessionStoreDir)) mkdir($sessionStoreDir, 0700, true);

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!$data || !isset($data['nonce']) || !isset($data['suffix'])) {
    http_response_code(400); echo json_encode(['ok'=>false,'msg'=>'invalid']); exit;
}

$nonce = preg_replace('/[^a-f0-9]/', '', $data['nonce']);
$suffix = $data['suffix'];
$nonceFile = "$nonceStoreDir/$nonce";
if (!file_exists($nonceFile)) { http_response_code(400); echo json_encode(['ok'=>false,'msg'=>'unknown']); exit; }

$meta = json_decode(file_get_contents($nonceFile), true);
if ($meta['used']) { http_response_code(400); echo json_encode(['ok'=>false,'msg'=>'replay']); exit; }
if (time() > $meta['expires']) { http_response_code(400); echo json_encode(['ok'=>false,'msg'=>'expired']); exit; }

// recompute SHA256(nonce + suffix)
$payload = $nonce . $suffix;
$hash = hash('sha256', $payload);

// difficulty must match server-side expectation
// store same difficulty used to create challenge (for simplicity, we can re-derive or assume constant)

// require leading hex zeros: e.g., difficulty=3 => first 3 hex chars == '000'
$required = str_repeat('0', $difficulty);

if (substr($hash, 0, $difficulty) !== $required) {
    http_response_code(403); echo json_encode(['ok'=>false,'msg'=>'bad proof']); exit;
}

// mark nonce used
$meta['used'] = true;
file_put_contents($nonceFile, json_encode($meta));
//TODO maybe better to unlink($nonceFile)

// create session token (store server-side)
$tok = bin2hex(random_bytes(24));
$sessionData = [
  'created' => time(),
  'ip' => $_SERVER['REMOTE_ADDR'],
  'ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
];
file_put_contents("$sessionStoreDir/$tok", json_encode($sessionData));

// set HttpOnly cookie (won't be accessible to JS)
$cookieName = 'vsess'; // change to randomized name in prod
$cookieExpire = time() + 7200; // 2 hours
// For production, set Secure => true and proper domain/path
setcookie($cookieName, $tok, $cookieExpire, '/', '', false, true);

echo json_encode(['ok'=>true,'msg'=>'accepted']);
