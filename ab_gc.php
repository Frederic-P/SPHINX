<?php
//function responsible for pragmatic garbage collecting:
// $config = include __DIR__ . '/ab_config.php';
// GC works with error suppression;: on failure it'll not error out.

function gc_cleanup($directory, $maxage) {
    // Deletes all files in the directory whose mtime is older than (now - $maxage)

    if (!is_dir($directory)) {
        return false;
    }
    $threshold = time() - $maxage;
    $items = scandir($directory);
    if ($items === false) {
        return false;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $directory . DIRECTORY_SEPARATOR . $item;
        if (is_file($path)) {
            if (filemtime($path) < $threshold) {
                @unlink($path);
            }
        }
        elseif (is_dir($path)) {
            gc_cleanup($path, $maxage);
            @rmdir($path);
        }
    }
}


?>