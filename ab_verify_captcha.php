<?php
// ab_verify_captcha.php
// checks if the captcha solution is correct, if not it dies with a 4XX code.
// when correct, captcha file is cleaned and a single use token is set 
// (later, client reads the single use token and creates a persistent cookie with liefetime according to config file.)


if ($_SERVER['REQUEST_METHOD'] !== 'POST') { 
    http_response_code(405); 
    header('Allow: POST'); 
    exit; 
}

$config = include __DIR__ . '/ab_config.php';

header('Content-Type: application/json; charset=utf-8');

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!$data || !isset($data['capid']) || !isset($data['solution'])) {
    http_response_code(400); 
    echo json_encode(['ok'=>false,'msg'=>'invalid']); 
    exit;
}

$capid = preg_replace('/[^a-f0-9]/','', $data['capid']);
$solution = strtoupper(preg_replace('/[^A-Z0-9]/','', $data['solution']));
$capdir = $config['storage_dir'] . '/_captchas/';
$capFile = $capdir . $capid;

if (!file_exists($capFile)) { 
    http_response_code(404); 
    echo json_encode(['ok'=>false,'msg'=>'notfound']); 
    exit;
}

$meta = json_decode(file_get_contents($capFile), true);
if ($meta['used'] || time() > $meta['expires']) { 
    http_response_code(410); 
    echo json_encode(['ok'=>false,'msg'=>'expired']); 
    exit;
}
if ($meta['solution'] !== $solution) { 
    http_response_code(403); 
    echo json_encode(['ok'=>false,'msg'=>'wrong']); 
    exit; 
}

// delete captcha file ==> safe to delete as the solution was correct
@unlink($capFile); 

// Make sure storage dir exists 
$allowDir = $config['storage_dir'] . '/_cap_allow';
@mkdir($allowDir,0700,true);
$ctoken = bin2hex(random_bytes(20));
$allowMeta = ['created'=>time(),'expires'=>time()+intval($config['ctoken_ttl']),'used'=>false,'ip'=>$_SERVER['REMOTE_ADDR'] ?? ''];
file_put_contents("$allowDir/$ctoken", json_encode($allowMeta));

// set ab_ctoken so next request will be authorized
$cookieName = $config['ctoken_cookie_name'];
$expire = time() + intval($config['ctoken_ttl']);
setcookie($cookieName, $ctoken, $expire, '/', '', false, true);

echo json_encode(['ok'=>true,'msg'=>'captcha_accepted']);
exit;
?>
