<?php
// ab_config.php
// Central configuration for anti-bot protection

return [
    // Master toggle:
    //      true = system is on 
    //      false = system is disabled.
    'enabled' => true,

    // Proof of work difficulty: the higher the longer it takes for clients, the less likely bots are going to pass. 
    'difficulty' => 4,

    // Nonce lifetime (seconds)
    'nonce_ttl' => 90,

    // Session lifetime (seconds) after successful challenge
    'session_ttl' => 7200,

    // Captcha lifetime (seconds)
    'captcha_ttl' => 300,

    // One-time allow token TTL (seconds) for captcha solution stored as cookie
    'ctoken_ttl' => 60,

    // Storage directory (will be created).
    'storage_dir' => __DIR__ . '/_ab_storage',

    // Session cookie name (HttpOnly)
    'cookie_name' => 'ab_vsess',

    // One-time cookie name for captcha allow (HttpOnly)
    'ctoken_cookie_name' => 'ab_ctoken',

    // Whitelist of IPs or CIDR ranges that should always be allowed
    // Example: ['127.0.0.1','192.168.0.0/16','203.0.113.5']
    'ip_whitelist' => [
        // '127.0.0.1',
    ],

    // Choose IP source: 'remote' uses $_SERVER['REMOTE_ADDR'],
    // 'xff' uses the configured X-Forwarded-For header
    //  you should determine this based on whether or not you use a reverse proxy. 
    'ip_source' => 'remote', // options: 'remote' or 'xff'

    // Paths to skip protection (prefix matching). Use URI PATHs (no querystring).
    //  NOTICE: PATHS ARE CASE SENSITIVE!
    //  ALWAYS include the full path starting from root for folders you want to have excluded
    //      e.g. : '/API/public/'
    //  Protection rules are replied recursively, any file/folder that is a child of an unprotected
    //      folder will not be protected either.
    'whitelist_paths' => [
        '/ds/'
    ],

    // If true, require at least one user interaction (mouse/keyboard/touch)
    //      this is one of the parametes reported by the client side JS check, is then taken into account on serverside. 
    'require_interaction' => true,

    // Minimal score threshold to accept client without captcha
    'score_threshold' => 8,

    // False or path from root to a PHP readable file that contains known good IPs:
    //      e.g.: https://github.com/AnTheMaker/GoodBots ==> CIDR ranges are allowed in the file
    'goodbotfile' => 'all.ips',

];
