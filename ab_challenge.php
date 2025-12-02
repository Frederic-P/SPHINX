<?php
// ab_challenge.php
// POST endpoint that returns a JSON challenge (nonce, difficulty, expires).

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); header('Allow: POST'); 
    exit;
}

$config = include __DIR__ . '/ab_config.php';
header('Content-Type: application/json; charset=utf-8');

// Make sure storage dir exists 
$storage = $config['storage_dir'];
$nonceDir = $storage . '/_nonces';
@mkdir($nonceDir, 0700, true);

$difficulty = max(0, intval($config['difficulty']));
$nonce = bin2hex(random_bytes(16));
$expires = time() + intval($config['nonce_ttl']);

$meta = ['expires'=>$expires, 'used'=>false, 'difficulty'=>$difficulty, 'created'=>time()];
file_put_contents("$nonceDir/$nonce", json_encode($meta));

echo json_encode(['nonce'=>$nonce, 'difficulty'=>$difficulty, 'expires'=>$expires]);

// garbage collecting ==> delete stale nonce files: 
include_once('ab_gc.php');
gc_cleanup($nonceDir, intval($config['nonce_ttl'])*1.1);
exit;
?>
