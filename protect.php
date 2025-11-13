<?php
// protect.php - include at top of pages (or set auto_prepend_file)
$allowed_path = '/dataservices/';
$uri = $_SERVER['REQUEST_URI'];
if (strpos($uri, $allowed_path) === 0) {
    return; // skip protection for /dataservices/
}

// check session cookie
$cookieName = 'vsess';
if (!isset($_COOKIE[$cookieName])) {
    // no server-session cookie yet — show minimal placeholder that triggers the JS
    header('HTTP/1.1 403 Forbidden');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Checking...</title>';
    echo '<script src="/js/bot-check.js"></script>';
    echo '</head><body>';
    echo 'One moment please...';
    echo '</body></html>';
    exit;
} else {
    // validate session server-side (ensure token exists & not expired)
    $sessionStoreDir = __DIR__ . '/_sessions';
    $tok = preg_replace('/[^a-f0-9]/','',$_COOKIE[$cookieName]);
    $file = "$sessionStoreDir/$tok";
    if (!file_exists($file)) {
        header('HTTP/1.1 403 Forbidden');
        echo 'Access denied';
        exit;
    }
    $meta = json_decode(file_get_contents($file), true);
}
?>
