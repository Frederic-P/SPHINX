<?php
// ab_verify.php
// takes in a post-request with a JSON body that contains the results of the client side tests done in JS. 
// Response: JSON only. If accepted, server sets HttpOnly session cookie.
// If suspicious, server returns captcha instruction and a captcha id; the client will fetch captcha via POST.

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); header('Allow: POST'); exit;
}

$config = include __DIR__ . '/ab_config.php';
include_once('ab_ip_handling.php'); 

header('Content-Type: application/json; charset=utf-8');

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!$data || !isset($data['nonce']) || !isset($data['suffix'])) {
    http_response_code(400); echo json_encode(['ok'=>false,'msg'=>'invalid_request']); exit;
}

// Make sure storage dir exists 
$storage = $config['storage_dir'];
$nonceDir = $storage . '/_nonces';
$sessionsDir = $storage . '/_sessions';
$capDir = $storage . '/_captchas';
@mkdir($nonceDir,0700,true);
@mkdir($sessionsDir,0700,true);
@mkdir($capDir,0700,true);

$nonce = preg_replace('/[^a-f0-9]/','',$data['nonce']);
$suffix = $data['suffix'];
$nonceFile = "$nonceDir/$nonce";
if (!file_exists($nonceFile)) {
    http_response_code(400); 
    echo json_encode(
        ['ok'=>false,'msg'=>'unknown_nonce']
    ); 
    exit; 
}

$meta = json_decode(file_get_contents($nonceFile), true);
if ($meta['used']) { 
    http_response_code(400); 
    echo json_encode(['ok'=>false,'msg'=>'replay']); 
    exit; 
}
if (time() > $meta['expires']) { 
    http_response_code(400); 
    echo json_encode(['ok'=>false,'msg'=>'expired']); 
    exit; 
}

// recompute SHA256(nonce+suffix)
$payload = $nonce . $suffix;
$hash = hash('sha256', $payload);

// check difficulty
$difficulty = isset($meta['difficulty']) ? intval($meta['difficulty']) : intval($config['difficulty']);
$required = str_repeat('0', $difficulty);
if (substr($hash, 0, $difficulty) !== $required) {
    http_response_code(403); 
    echo json_encode(['ok'=>false,'msg'=>'bad_pow']); 
    exit;
}

// mark nonce used
$meta['used'] = true;
file_put_contents($nonceFile, json_encode($meta));

// scoring
$clientScore = isset($data['score']) ? floatval($data['score']) : 0.0;
$clientDetails = $data['details'] ?? [];
$threshold = floatval($config['score_threshold']);

// server-side checks
$timeNow = time();
//Try to detect very quick sequences of requests and penalize the request strongly!
$elapsed = isset($clientDetails['ts_request']) ? ($timeNow - intval($clientDetails['ts_request'])) : null;
if ($elapsed !== null && $elapsed < 0.05) {
    $clientScore -= 5;
};
// Try to detect webdriver (selenium puppeteer ...) and penalize the request strongly!
if (!empty($clientDetails['webdriver'])) {
    $clientScore -= 6;
} 

//if configured to have forced user interaction during POW check ==> and none is given. THEN 
//  apply a strong penalty on the request:
if (!empty($config['require_interaction']) && empty($clientDetails['interacted'])) {
    $clientScore -= 30;
}

// // // If IP is whitelisted, accept immediately
// $clientIp = function() use ($config) {
//     $src = $config['ip_source'] ?? 'remote';
//     if ($src === 'xff') {
//         $hdr = $config['xff_header'] ?? 'X-Forwarded-For';
//         $h = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $hdr))] ?? '';
//         if ($h !== '') {
//             $parts = array_map('trim', explode(',', $h));
//             if (!empty($parts[0])){
//                  return $parts[0];
//             }
//         }
//     }
//     return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
// };
$clientIp = get_client_ip($config);




// function cidr_match_local($ip, $cidr) {
//     if (strpos($cidr, '/') === false){
//          return ($ip === $cidr);
//     }
//     list($subnet, $mask) = explode('/', $cidr, 2);
//     $mask = intval($mask);
//     $ip_long = ip2long($ip);
//     $subnet_long = ip2long($subnet);
//     if ($ip_long === false || $subnet_long === false){
//          return false;
//     }
//     $mask_long = -1 << (32 - $mask);
//     return (($ip_long & $mask_long) === ($subnet_long & $mask_long));
// }
// $ipWhitelisted = false;
// foreach ($config['ip_whitelist'] as $entry) {
//     if (cidr_match_local($clientIp, $entry)) { 
//         $ipWhitelisted = true;
//         break;
//     }
// }

$ipWhitelisted = ip_is_whitelisted($clientIp, $config['ip_whitelist'], $config['goodbotfile']);
if ($ipWhitelisted) {
    $tok = bin2hex(random_bytes(24));
    $expires = time() + intval($config['session_ttl']);
    $sessionMeta = ['created'=>time(),'expires'=>$expires,'ip'=>$clientIp,'ua'=>$_SERVER['HTTP_USER_AGENT'] ?? ''];
    file_put_contents("$sessionsDir/$tok", json_encode($sessionMeta));
    setcookie($config['cookie_name'], $tok, $expires, '/', '', false, true);
    echo json_encode(['ok'=>true,'msg'=>'ip_whitelist']);
    exit;
}




$suspicious = false;
if (!empty($clientDetails['webdriver'])){
    $suspicious = true;
}
// extra checks
if ($suspicious || $clientScore < $threshold) {
    // require captcha only when suspicious OR score below threshold
    $captchaLength = 8;

    $capid = bin2hex(random_bytes(20));
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $solution = '';
    
    for ($i=0;$i<$captchaLength;$i++) {
        $solution .= $chars[random_int(0, strlen($chars)-1)];
    }
    $capMeta = ['solution'=>$solution,'created'=>time(),'expires'=>time()+intval($config['captcha_ttl']),'used'=>false,'ip'=>$clientIp];
    file_put_contents("$capDir/$capid", json_encode($capMeta));
    // return capid to client; client will POST to fetch captcha image (no URL params)
    echo json_encode(['ok'=>false,'captcha'=>true,'capid'=>$capid,'msg'=>'captcha_required']);
    exit;
}

// If not suspicious and score >= threshold ==> grant session
if ($clientScore >= $threshold) {
    $tok = bin2hex(random_bytes(24));
    $expires = time() + intval($config['session_ttl']);
    $sessionMeta = ['created'=>time(),'expires'=>$expires,'ip'=>$clientIp,'ua'=>$_SERVER['HTTP_USER_AGENT'] ?? ''];
    file_put_contents("$sessionsDir/$tok", json_encode($sessionMeta));
    setcookie($config['cookie_name'], $tok, $expires, '/', '', false, true);
    echo json_encode(['ok'=>true,'msg'=>'accepted']);
    exit;
}

// Fallback: require captcha if we reach here
$capid = bin2hex(random_bytes(20));
$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
$solution = '';
for ($i=0;$i<$captchaLength;$i++) {
    $solution .= $chars[random_int(0, strlen($chars)-1)];
}
$capMeta = ['solution'=>$solution,'created'=>time(),'expires'=>time()+intval($config['captcha_ttl']),'used'=>false,'ip'=>$clientIp];
file_put_contents("$capDir/$capid", json_encode($capMeta));
echo json_encode(['ok'=>false,'captcha'=>true,'capid'=>$capid,'msg'=>'captcha_required']);
exit;
?>