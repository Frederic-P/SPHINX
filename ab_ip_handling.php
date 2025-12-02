<?php

// $config = include __DIR__ . '/ab_config.php';

function get_client_ip($config) {
    // return '213.180.207.123'; // part of 213.180.192.0/19    ==> OK
    // return '2a01:4f8:c17:6648:3a2f:9c11:4b7d:82c1';    //part of 2a01:4f8:c17:6648::/64 ==> OK
    // Get client IP for the current request, get it from XFF or REMOTE_ADDR
    //  end user should have configured if they are behind a reverse proxy or not. 
    $src = $config['ip_source'] ?? 'remote';
    if ($src === 'xff') {
        $h = $_SERVER['HTTP_X_FORWARDED_FOR'];
        if ($h !== '') {
            // header may contain comma-separated list; take first non-empty
            $parts = array_map('trim', explode(',', $h));
            if (!empty($parts[0])){
                return $parts[0];
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}


function cidr_match($ip, $cidr) {
    // If the CIDR does not contain a '/', treat it as one address 
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }

    list($subnet, $mask) = explode('/', $cidr, 2);
    $mask = intval($mask);

    // Detect if IPv4 or IPv6
    //    IPV4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        $mask_long = -1 << (32 - $mask);
        return (($ip_long & $mask_long) === ($subnet_long & $mask_long));
    }
    //   IPV6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }

        $ip_bits = unpack('H*', $ip_bin)[1];
        $subnet_bits = unpack('H*', $subnet_bin)[1];

        $ip_bin_str = '';
        $subnet_bin_str = '';
        for ($i = 0; $i < strlen($ip_bits); $i += 2) {
            $ip_bin_str .= str_pad(base_convert(substr($ip_bits, $i, 2), 16, 2), 8, '0', STR_PAD_LEFT);
            $subnet_bin_str .= str_pad(base_convert(substr($subnet_bits, $i, 2), 16, 2), 8, '0', STR_PAD_LEFT);
        }

        return substr($ip_bin_str, 0, $mask) === substr($subnet_bin_str, 0, $mask);
    }

    return false; // mismatched IP versions
}

function ip_is_whitelisted($ip, $whitelist, $goodbotFile) {
    //whitelisting check: 
    //first check if the IP is in the custom whitelist set. Allow CIDR there. 
    // whitelist takes precendence over $goodbotFile ==> we want to have our own custom ranges treated faster than google bots etc... 
    foreach ($whitelist as $good_ip) {
        if (cidr_match($ip, $good_ip)){
            return true;
        }
    }
    if (is_readable($goodbotFile)) {
        $lines = file($goodbotFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $goodBots = array_map('trim', $lines);
        foreach ($goodBots as $goodbot_ip) {
            if (cidr_match($ip, $goodbot_ip)){
                return true;
            }
        }
    }
    return false;
}


?>