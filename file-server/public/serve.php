<?php
declare(strict_types=1);

$secret = getenv('FILE_TOKEN_SECRET') ?: 'replace-this-hmac-secret'; //getenv('FILE_TOKEN_SECRET') should be set to the same value as FILE_TOKEN_SECRET in the middle service configuration
$expectedIssuer = getenv('FILE_TOKEN_ISSUER') ?: 'middle-poc';
$expectedAudience = getenv('FILE_TOKEN_AUDIENCE') ?: 'image-server';
$baseDir = realpath('/data/files');

/**
 * Stops the current request and redirects the browser to the generic error page.
 *
 * @param string $reason A message describing the reason for the error
 * @return never
 */
function redirect_error(string $reason): never
{
    error_log('[file-server] ' . $reason);
    header('Location: /error.html', true, 302);
    exit;
}

/**
 * Decodes a JWT-style Base64URL segment.
 *
 * JWT parts omit the normal `=` padding, so this helper restores it before
 * decoding and returns `false` for malformed data.
 * 
 * @param string $value The Base64URL-encoded string to decode
 * @return string|false The decoded binary string, or `false` if decoding fails
 */
function base64url_decode_string(string $value): string|false
{
    $padding = strlen($value) % 4;
    if ($padding > 0) {
        $value .= str_repeat('=', 4 - $padding);
    }
    return base64_decode(strtr($value, '-_', '+/'), true);
}

/**
 * Validates the structure and HS256 signature of a JWT used by the file server.
 *
 * This is the critical verification step on the Apache side. It does not check
 * higher-level claims such as `exp`, `aud`, or the target file path; it focuses
 * only on cryptographic integrity and basic JWT structure:
 * - exactly three dot-separated segments
 * - decodable JSON header and payload
 * - `alg` is `HS256`
 * - computed HMAC matches the supplied signature
 *
 * The caller performs the claim validation afterwards so signature verification
 * and policy checks remain separate and easy to reason about.
 *
 * @param string $jwt The compact JWT string to verify
 * @param string $secret The shared secret key used for HMAC verification
 * @return array<string, mixed>|null
 */
function verify_hs256_jwt(string $jwt, string $secret): ?array
{
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return null;
    }

    // Decode the three parts of the JWT:
    [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
    $headerJson = base64url_decode_string($encodedHeader);
    $payloadJson = base64url_decode_string($encodedPayload);
    $signature = base64url_decode_string($encodedSignature);

    // If any part fails to decode properly, treat the token as invalid:
    if ($headerJson === false || $payloadJson === false || $signature === false) {
        return null;
    }

    // Parse the header and payload as JSON objects:
    $header = json_decode($headerJson, true);
    $payload = json_decode($payloadJson, true);

    if (!is_array($header) || !is_array($payload)) {
        return null;
    }

    if (($header['alg'] ?? '') !== 'HS256') {
        return null;
    }

    $expectedSignature = hash_hmac(
        'sha256',
        $encodedHeader . '.' . $encodedPayload,
        $secret,
        true
    );

    // Compute the expected signature using HMAC-SHA256 and compare it to the provided signature:
    // Use hash_equals to prevent timing attacks when comparing signatures!
    if (!hash_equals($expectedSignature, $signature)) {
        return null;
    }

    return $payload;
}

$requestedFile = $_GET['file'] ?? '';
$token = $_GET['token'] ?? '';

if ($requestedFile === '') {
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    if (is_string($path) && str_starts_with($path, '/protected/')) {
        $requestedFile = rawurldecode(substr($path, strlen('/protected/')));
    }
}

if ($baseDir === false) {
    redirect_error('Base directory is not available.');
}

if ($requestedFile === '' || $token === '') {
    redirect_error('Missing file name or token.');
}

$claims = verify_hs256_jwt($token, $secret);
if ($claims === null) {
    redirect_error('Token signature validation failed.');
}

// Validate the standard claims in the token to ensure it is valid and authorized for the requested file:
$now = time();
$exp = $claims['exp'] ?? null;
$nbf = $claims['nbf'] ?? null;

// 1. Check the issuer:
if (($claims['iss'] ?? '') !== $expectedIssuer) {
    redirect_error('Unexpected token issuer.');
}

// 2. Check the audience:
if (($claims['aud'] ?? '') !== $expectedAudience) {
    redirect_error('Unexpected token audience.');
}

// 3. Check the expiration time (with a small clock skew allowance):
if (!is_numeric($exp) || (int) $exp < ($now - 5)) {
    redirect_error('Token has expired.');
}

// 4. Check the "not before" time (with a small clock skew allowance):
if ($nbf !== null && is_numeric($nbf) && (int) $nbf > ($now + 5)) {
    redirect_error('Token is not valid yet.');
}

// 5. Check the custom "file" claim to ensure the token is bound to the requested file:
if (($claims['file'] ?? '') !== $requestedFile) {
    redirect_error('Token is not bound to the requested file.');
}

// Resolve the absolute path of the requested file and ensure it is within the base directory:
$absolutePath = realpath($baseDir . DIRECTORY_SEPARATOR . $requestedFile);
if (
    $absolutePath === false ||
    !is_file($absolutePath) ||
    strncmp($absolutePath, $baseDir . DIRECTORY_SEPARATOR, strlen($baseDir . DIRECTORY_SEPARATOR)) !== 0
) {
    redirect_error('Resolved file path is invalid.');
}

$mimeType = mime_content_type($absolutePath) ?: 'application/octet-stream';
$size = filesize($absolutePath);

header('Cache-Control: no-store');
header('Content-Type: ' . $mimeType);
if ($size !== false) {
    header('Content-Length: ' . (string) $size);
}
header('Content-Disposition: inline; filename="' . basename($absolutePath) . '"');

readfile($absolutePath);
