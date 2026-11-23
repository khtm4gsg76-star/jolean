<?php
/**
 * Private router used by Mazaji for user PHP websites.
 * It supports front-controller frameworks and blocks sensitive project files.
 */
$root = realpath(getenv('MAZAGI_SITE_ROOT') ?: getcwd());
if ($root === false) {
    http_response_code(500);
    exit('Site root unavailable');
}
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$decoded = rawurldecode($uri);
if (strpos($decoded, "\0") !== false || strpos($decoded, "\\") !== false) {
    http_response_code(404);
    exit('Not found');
}
$parts = array_values(array_filter(explode('/', $decoded), static function ($p) {
    return $p !== '' && $p !== '.' && $p !== '..';
}));
$blockedDirs = ['.git', '.svn', '.hg', '.venv', 'venv', 'node_modules', '__pycache__', '.idea', '.vscode', 'vendor', 'portable_data', '.mazagi-home', '.mazagi-tmp'];
$blockedNames = ['.env', 'db.json', 'credentials.json', 'service-account.json', '.htpasswd', 'id_rsa', 'id_ed25519', 'composer.json', 'composer.lock', 'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt', 'pyproject.toml'];
foreach ($parts as $part) {
    $lower = strtolower($part);
    if (in_array($lower, $blockedDirs, true) || (str_starts_with($lower, '.') && $lower !== '.well-known') || str_starts_with($lower, '.env')) {
        http_response_code(404);
        exit('Not found');
    }
}
$last = strtolower((string) end($parts));
if (in_array($last, $blockedNames, true) || preg_match('/\.(py|pyc|pyo|log|sqlite3?|db|pem|key|p12|pfx|bak|swp|tmp|upload_tmp|replace_tmp|inc|phar|phtml)$/i', $last)) {
    http_response_code(404);
    exit('Not found');
}
$relative = implode(DIRECTORY_SEPARATOR, $parts);
// Reject symlinks in PHP public paths. A URL alias must not bypass checks by
// pointing at hidden project files or source files with a harmless name.
$probe = $root;
foreach ($parts as $part) {
    $probe .= DIRECTORY_SEPARATOR . $part;
    if (is_link($probe)) {
        http_response_code(404);
        exit('Not found');
    }
}
$requested = realpath($root . DIRECTORY_SEPARATOR . $relative);
$prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
if ($requested !== false && $requested !== $root && strpos($requested, $prefix) !== 0) {
    http_response_code(404);
    exit('Not found');
}
if ($requested !== false && $requested !== $root) {
    $resolvedRelative = substr($requested, strlen($prefix));
    $resolvedParts = array_values(array_filter(explode(DIRECTORY_SEPARATOR, $resolvedRelative), static function ($p) { return $p !== ''; }));
    foreach ($resolvedParts as $resolvedPart) {
        $resolvedLower = strtolower($resolvedPart);
        if ((str_starts_with($resolvedLower, '.') && $resolvedLower !== '.well-known') || str_starts_with($resolvedLower, '.env') || in_array($resolvedLower, $blockedNames, true) || preg_match('/\.(py|pyc|pyo|log|sqlite3?|db|pem|key|p12|pfx|bak|swp|tmp|upload_tmp|replace_tmp|inc|phar|phtml)$/i', $resolvedLower)) {
            http_response_code(404);
            exit('Not found');
        }
    }
}
if ($requested !== false && is_dir($requested)) {
    foreach (['index.php', 'index.html', 'index.htm'] as $index) {
        $candidate = realpath($requested . DIRECTORY_SEPARATOR . $index);
        if ($candidate && strpos($candidate, $prefix) === 0 && is_file($candidate)) {
            return false;
        }
    }
    http_response_code(404); // Never expose a PHP document-root directory listing.
    exit('Not found');
}
if ($requested !== false && is_file($requested)) {
    return false; // Let PHP's built-in server serve static files or execute PHP scripts.
}
$frontController = $root . DIRECTORY_SEPARATOR . 'index.php';
if (is_file($frontController)) {
    $_SERVER['SCRIPT_NAME'] = '/index.php';
    $_SERVER['PHP_SELF'] = '/index.php';
    $_SERVER['SCRIPT_FILENAME'] = $frontController;
    require $frontController;
    return true;
}
http_response_code(404);
echo 'Not found';
return true;
