<?php
declare(strict_types=1);

$baseDir = realpath('/data/files');

/**
 * Stops the request and redirects the browser to the generic error page.
 *
 * Authentication and file-token validation already happened in Apache before
 * this script runs. Any failure here is about local file resolution only.
 */
function redirect_error(string $reason): never
{
    error_log('[file-server] ' . $reason);
    header('Location: /error.html', true, 302);
    exit;
}

$requestedFile = '';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
if (is_string($path) && str_starts_with($path, '/protected/')) {
    // Apache keeps the original path, so the PHP fallback can recover which protected file was requested.
    $requestedFile = rawurldecode(substr($path, strlen('/protected/')));
}

if ($baseDir === false) {
    redirect_error('Base directory is not available.');
}

if ($requestedFile === '') {
    redirect_error('Missing file name.');
}

$authorizedFile = (string) ($_SERVER['OIDC_CLAIM_file'] ?? '');
// The token must be scoped to exactly one file; otherwise a valid token could be replayed for a different path:
if ($authorizedFile === '' || $authorizedFile !== $requestedFile) {
    redirect_error('Bearer token is not bound to the requested file.');
}

$absolutePath = realpath($baseDir . DIRECTORY_SEPARATOR . $requestedFile);
if (
    $absolutePath === false ||
    !is_file($absolutePath) ||
    // Containment check prevents traversal through values like ../ even after filesystem resolution:
    strncmp($absolutePath, $baseDir . DIRECTORY_SEPARATOR, strlen($baseDir . DIRECTORY_SEPARATOR)) !== 0
) {
    redirect_error('Resolved file path is invalid.');
}

$mimeType = mime_content_type($absolutePath) ?: 'application/octet-stream';
$size = filesize($absolutePath);

// Disable caching so short-lived authorization decisions are not undermined by stale browser copies:
header('Cache-Control: no-store');
header('Content-Type: ' . $mimeType);
if ($size !== false) {
    header('Content-Length: ' . (string) $size);
}
header('Content-Disposition: inline; filename="' . basename($absolutePath) . '"');

readfile($absolutePath);
