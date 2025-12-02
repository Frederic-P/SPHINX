<?php
// ab_protect.php
// Include at top of your pages or via auto_prepend_file in php.ini
//      see: https://www.php.net/manual/en/function.include-once.php 
//      or: https://phpbuilder.com/automagically-adding-files-before-after-scripts/
// Including this file will enforce bot protection measures unless the IP
// is known to be from a good bot, or the request path is whitelisted.
// whitelisting paths and ips are done in the ab_config.php file
//      IPS should be whitelisted to allow google indexer bots to index your site
//      PATHS should be whitestlisted to keep API endpoints functioning for legitimate API ingesters
//      a good up to date list of ip's that should be whitelisted is currated by https://github.com/AnTheMaker/GoodBots


$config = include __DIR__ . '/ab_config.php';
include_once('ab_ip_handling.php'); 
// If protection disabled, do nothing ==> allow all
if (empty($config['enabled'])) {
    return;
}



// Request info
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH); // strip query string
$clientIp = get_client_ip($config);
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Make sure storage dir exists 
$storage = $config['storage_dir'];
$sessionsDir = $storage . '/_sessions';
$capAllowDir = $storage . '/_cap_allow';
@mkdir($sessionsDir, 0700, true);
@mkdir($capAllowDir, 0700, true);

// Path whitelist
foreach ($config['whitelist_paths'] as $prefix) {
    //TODO: keep strpos, but make you sure you document that 
    //  whitelistpaths are CASE SENSITIVE 
    //TODO: keep strpos === 0 expectation, whoever implements this
    //  will need to understand that the paths should be given in full 
    //  from the base URL!
    if ($prefix !== '' && strpos($path, $prefix) === 0) {
        // skip protection if the path is excluded from ab*protection.  
        return; 
    }
}

// IP whitelisting


if (ip_is_whitelisted($clientIp, $config['ip_whitelist'], $config['goodbotfile'])) {
    return;
}

// session cookie check
$cookieName = $config['cookie_name'];
$sessionValid = false;
if (!empty($_COOKIE[$cookieName])) {
    $tok = preg_replace('/[^a-f0-9]/', '', $_COOKIE[$cookieName]);
    $fn = "$sessionsDir/$tok";
    if (file_exists($fn)) {
        $meta = json_decode(file_get_contents($fn), true);
        if (isset($meta['expires']) && time() < $meta['expires']) {
            $sessionValid = true;
        } else {
            @unlink($fn);
        }
    }
}

// one-time captcha token via cookie (no GET/POST params)
$ctcookie = $config['ctoken_cookie_name'];
if (!$sessionValid && !empty($_COOKIE[$ctcookie])) {
    $ct = preg_replace('/[^a-f0-9]/','', $_COOKIE[$ctcookie]);
    $fn = "$capAllowDir/$ct";
    if (file_exists($fn)) {
        $meta = json_decode(file_get_contents($fn), true);
        if (!$meta['used'] && time() < $meta['expires']) {
            // consume token
            // $meta['used'] = true;
            // file_put_contents($fn, json_encode($meta));
            // Create a session cookie after consuming the captcha token
            $tok = bin2hex(random_bytes(24));
            $expires = time() + intval($config['session_ttl']);
            $sessionMeta = ['created'=>time(),'expires'=>$expires,'ip'=>$clientIp,'ua'=>$userAgent];
            file_put_contents("$sessionsDir/$tok", json_encode($sessionMeta));
            setcookie($config['cookie_name'], $tok, $expires, '/', '', false, true);
            
            $sessionValid = true;
            //TODO: move unlink out of if scope!
            //delete the token after setting the cookie
            @unlink($fn);

        } else {
            @unlink($fn);
        }
    }
    //delete stale token files: 
    include_once('ab_gc.php');
    gc_cleanup($capAllowDir, $config['ctoken_ttl']*1.1);
}

// If session valid ==>  allow access
if ($sessionValid) {
    return;
}

// Otherwise, return a minimal challenge page that will POST to endpoints and set cookies.
$currentPath = $path;
http_response_code(403);
header('Content-Type: text/html; charset=utf-8');
include_once('ab_challenge_document.php');
die(); 


?>



<?php
exit;
?>