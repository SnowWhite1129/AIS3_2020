<?php
if ($path = @$_GET['path']) {
    if (preg_match('/^(\.|\/)/', $path)) {
        // disallow /path/like/this and ../this
        die('<pre>[forbidden]</pre>');
    }
    $content = @file_get_contents($path, FALSE, NULL, 0, 1000);
    die('<pre>' . ($content ? htmlentities($content) : '[empty]') . '</pre>');
}
?>
