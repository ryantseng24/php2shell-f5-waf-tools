<?php
// Echo back what PHP actually parsed, so a test can prove whether a request reached the PHP engine.
header('Content-Type: text/plain; charset=utf-8');
echo "php2shell-lab backend\n";
echo "REACHED_PHP=yes\n";
echo "PHP_VERSION=" . PHP_VERSION . "\n";
echo "SAPI=" . PHP_SAPI . "\n";
echo "METHOD=" . $_SERVER['REQUEST_METHOD'] . "\n";
echo "URI=" . $_SERVER['REQUEST_URI'] . "\n";
echo "CONTENT_TYPE=" . ($_SERVER['CONTENT_TYPE'] ?? '') . "\n";
echo "POST_KEYS=" . implode(',', array_keys($_POST)) . "\n";
echo "FILES_KEYS=" . implode(',', array_keys($_FILES)) . "\n";
echo "upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "upload_progress.name=" . ini_get('session.upload_progress.name') . "\n";
