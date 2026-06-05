<?php
declare(strict_types=1);

/**
 * Reads a runtime setting from the environment and falls back to a default.
 *
 * @param string $name Environment variable name
 * @param string $default Default value when unset
 * @return string
 */
function env_value(string $name, string $default): string
{
    $value = getenv($name);
    return $value === false || $value === '' ? $default : $value;
}

define('APP_BASE_URL', rtrim(env_value('APP_BASE_URL', 'http://localhost:8080'), '/'));
define('KEYCLOAK_BROWSER_BASE_URL', rtrim(env_value('KEYCLOAK_BROWSER_BASE_URL', 'http://localhost:8081'), '/'));
define('KEYCLOAK_REALM', env_value('KEYCLOAK_REALM', 'image-poc'));
define('REQUIRED_ROLE', env_value('REQUIRED_ROLE', 'image-reader'));
define('FILES_BASE_URL', rtrim(env_value('FILES_BASE_URL', 'http://localhost:8090'), '/'));
define('FILES_INTERNAL_BASE_URL', rtrim(env_value('FILES_INTERNAL_BASE_URL', 'http://file-server'), '/'));
define('FILES_DIRECTORY', env_value('FILES_DIRECTORY', '/data/files'));
define('FILE_TOKEN_SECRET', env_value('FILE_TOKEN_SECRET', 'replace-this-hmac-secret'));
define('FILE_TOKEN_TTL_SECONDS', (int) env_value('FILE_TOKEN_TTL_SECONDS', '60'));
define('FILE_TOKEN_ISSUER', env_value('FILE_TOKEN_ISSUER', 'middle-poc'));
define('FILE_TOKEN_AUDIENCE', env_value('FILE_TOKEN_AUDIENCE', 'image-server'));
define('OIDC_CALLBACK_PATH', env_value('OIDC_CALLBACK_PATH', '/oidc/callback'));
define('TEMPLATE_HOME', dirname(__DIR__) . DIRECTORY_SEPARATOR . 'templates' . DIRECTORY_SEPARATOR . 'index.html');

route_request();

/**
 * Front controller for the reduced middle service.
 *
 * Apache and mod_auth_openidc now own the browser authentication flow. This
 * script only renders the landing pages, evaluates the local authorization
 * policy, mints short-lived file tokens, and streams files back to the browser.
 *
 * Protected paths are enforced in Apache:
 * - `/app`
 * - `/request-file/<name>`
 * - `OIDC_CALLBACK_PATH`
 *
 * @return never
 */
function route_request(): never
{
    $path = (string) (parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/');

    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        fail_request(405, 'Method not allowed.');
    }

    if ($path === '/' || $path === '/app') {
        render_home();
    }

    if (str_starts_with($path, '/request-file/')) {
        $fileName = rawurldecode(substr($path, strlen('/request-file/')));
        handle_request_file($fileName);
    }

    fail_request(404, 'Not found.');
}

/**
 * Applies the local access policy and mints a file-specific JWT.
 *
 * Browser authentication is already complete when this handler runs. Apache has
 * authenticated the user with Keycloak and passed the identity material to PHP
 * through environment variables and request metadata. This function then:
 * - reconstructs the current user from Apache-provided identity data
 * - checks the requested file is real and inside the mounted sample directory
 * - checks the configured Keycloak role
 * - creates a short-lived HMAC bearer token for the file server
 * - either returns JSON token metadata or performs a server-side Bearer-token
 *   request to the file server and streams the file back to the browser
 *
 * @return never
 */
function handle_request_file(string $fileName): never
{
    $user = current_user_from_environment();
    if ($user === null) {
        fail_request(401, 'Authentication is required.');
    }

    $resolved = resolve_file($fileName);
    if ($resolved === null) {
        fail_request(404, 'Requested file not found.');
    }

    $roles = $user['roles'] ?? [];
    if (!is_array($roles)) {
        $roles = [];
    }

    if (REQUIRED_ROLE !== '' && !in_array(REQUIRED_ROLE, $roles, true)) {
        fail_request(
            403,
            'Authenticated, but policy denied access. Required role: ' . REQUIRED_ROLE . '.'
        );
    }

    $safeFileName = basename($resolved);
    $token = build_file_token($user, $safeFileName);
    $directDownloadUrl = FILES_BASE_URL . '/protected/' . rawurlencode($safeFileName);

    if (request_wants_json()) {
        json_response([
            'file' => $safeFileName,
            'access_token' => $token,
            'direct_download_url' => $directDownloadUrl,
            'expires_in' => FILE_TOKEN_TTL_SECONDS,
            'token_type' => 'Bearer',
        ]);
    }

    stream_file_from_server($safeFileName, $token);
}

/**
 * Renders the landing page template with normalized view data.
 *
 * `/` stays public so the landing page can explain the PoC before login. `/app`
 * is protected in Apache and therefore renders the same template with live user
 * identity attached.
 *
 * @return never
 */
function render_home(int $statusCode = 200, ?string $errorMessage = null): never
{
    http_response_code($statusCode);

    $user = current_user_from_environment();
    $files = list_available_files();
    $requiredRole = REQUIRED_ROLE;
    $fileTokenTtl = FILE_TOKEN_TTL_SECONDS;
    $directFilesBaseUrl = FILES_BASE_URL;
    $loginUrl = '/app';
    $logoutUrl = OIDC_CALLBACK_PATH . '?logout=' . rawurlencode(APP_BASE_URL . '/');
    $keycloakAdminUrl = APP_BASE_URL . '/kc/admin/';

    require TEMPLATE_HOME;
    exit;
}

/**
 * Rebuilds the current authenticated user from Apache-provided identity data.
 *
 * mod_auth_openidc now performs the browser OIDC flow and exposes claims through
 * environment variables. We use the passed access token only to extract realm
 * roles for the local policy decision; Apache itself remains the trusted
 * authentication component.
 *
 * @return array<string, mixed>|null
 */
function current_user_from_environment(): ?array
{
    $preferredUsername = first_server_value([
        'OIDC_CLAIM_preferred_username',
        'REDIRECT_OIDC_CLAIM_preferred_username',
        'REMOTE_USER',
        'REDIRECT_REMOTE_USER',
    ]);

    if ($preferredUsername === null || $preferredUsername === '') {
        return null;
    }

    $subject = first_server_value([
        'OIDC_CLAIM_sub',
        'REDIRECT_OIDC_CLAIM_sub',
    ]) ?? $preferredUsername;

    $email = first_server_value([
        'OIDC_CLAIM_email',
        'REDIRECT_OIDC_CLAIM_email',
    ]);

    $name = first_server_value([
        'OIDC_CLAIM_name',
        'REDIRECT_OIDC_CLAIM_name',
    ]);

    $roles = [];
    $accessToken = first_server_value([
        'OIDC_access_token',
        'REDIRECT_OIDC_access_token',
    ]);

    if ($accessToken !== null && $accessToken !== '') {
        $claims = decode_unverified_jwt($accessToken);
        $candidateRoles = $claims['realm_access']['roles'] ?? [];
        if (is_array($candidateRoles)) {
            foreach ($candidateRoles as $role) {
                if (is_string($role) && $role !== '') {
                    $roles[] = $role;
                }
            }
        }
    }

    $roleClaim = first_server_value([
        'OIDC_CLAIM_realm_access_roles',
        'REDIRECT_OIDC_CLAIM_realm_access_roles',
    ]);
    if ($roleClaim !== null && $roleClaim !== '') {
        foreach (preg_split('/[,\s]+/', $roleClaim) ?: [] as $role) {
            if ($role !== '') {
                $roles[] = $role;
            }
        }
    }

    $roles = array_values(array_unique($roles));
    sort($roles);

    return [
        'sub' => $subject,
        'name' => $name,
        'preferred_username' => $preferredUsername,
        'email' => $email,
        'roles' => $roles,
    ];
}

/**
 * Reads the first non-empty value from $_SERVER or process environment.
 *
 * @param list<string> $keys
 * @return string|null
 */
function first_server_value(array $keys): ?string
{
    foreach ($keys as $key) {
        $value = $_SERVER[$key] ?? getenv($key);
        if (is_string($value) && $value !== '') {
            return $value;
        }
    }

    return null;
}

/**
 * Returns the list of mounted sample files.
 *
 * @return list<string>
 */
function list_available_files(): array
{
    if (!is_dir(FILES_DIRECTORY)) {
        return [];
    }

    $files = [];
    foreach (scandir(FILES_DIRECTORY) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || str_starts_with($entry, '.')) {
            continue;
        }

        $candidate = FILES_DIRECTORY . DIRECTORY_SEPARATOR . $entry;
        if (is_file($candidate)) {
            $files[] = $entry;
        }
    }

    sort($files);
    return $files;
}

/**
 * Resolves a requested file name to a safe absolute path.
 *
 * @return string|null
 */
function resolve_file(string $name): ?string
{
    $baseDirectory = realpath(FILES_DIRECTORY);
    if ($baseDirectory === false) {
        return null;
    }

    $normalized = str_replace('\\', '/', $name);
    $candidate = realpath($baseDirectory . DIRECTORY_SEPARATOR . $normalized);
    if ($candidate === false || !is_file($candidate)) {
        return null;
    }

    if (!str_starts_with($candidate, $baseDirectory . DIRECTORY_SEPARATOR)) {
        return null;
    }

    return $candidate;
}

/**
 * Builds the short-lived HS256 JWT understood by the file-server module.
 *
 * For this step we keep the PoC's shared-secret token model so Apache on the
 * file server can validate it with `OIDCOAuthVerifySharedKeys`. The token still
 * includes the exact `file` claim even though the module-only file binding is
 * deferred for now.
 *
 * @param array<string, mixed> $user
 * @return string
 */
function build_file_token(array $user, string $fileName): string
{
    $now = time();
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT',
    ];
    $payload = [
        'iss' => FILE_TOKEN_ISSUER,
        'aud' => FILE_TOKEN_AUDIENCE,
        'sub' => $user['sub'] ?? null,
        'preferred_username' => $user['preferred_username'] ?? null,
        'file' => $fileName,
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + FILE_TOKEN_TTL_SECONDS,
        'jti' => base64url_encode(random_bytes(8)),
    ];

    $headerSegment = base64url_encode((string) json_encode($header, JSON_UNESCAPED_SLASHES));
    $payloadSegment = base64url_encode((string) json_encode($payload, JSON_UNESCAPED_SLASHES));
    $signingInput = $headerSegment . '.' . $payloadSegment;
    $signature = hash_hmac('sha256', $signingInput, FILE_TOKEN_SECRET, true);

    return $signingInput . '.' . base64url_encode($signature);
}

/**
 * Decodes a JWT payload without verifying its signature.
 *
 * This is used only for access-token claim extraction after Apache has already
 * authenticated the user and handed us the token.
 *
 * @return array<string, mixed>
 */
function decode_unverified_jwt(string $token): array
{
    if ($token === '') {
        return [];
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return [];
    }

    $payloadJson = base64url_decode($parts[1]);
    if ($payloadJson === null) {
        return [];
    }

    $payload = json_decode($payloadJson, true);
    return is_array($payload) ? $payload : [];
}

/**
 * Encodes raw text or bytes as Base64URL.
 *
 * @return string
 */
function base64url_encode(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

/**
 * Decodes a Base64URL segment and restores omitted padding.
 *
 * @return string|null
 */
function base64url_decode(string $raw): ?string
{
    $padded = strtr($raw, '-_', '+/');
    $remainder = strlen($padded) % 4;
    if ($remainder !== 0) {
        $padded .= str_repeat('=', 4 - $remainder);
    }

    $decoded = base64_decode($padded, true);
    return $decoded === false ? null : $decoded;
}

/**
 * Returns whether the caller explicitly asked for JSON.
 *
 * @return bool
 */
function request_wants_json(): bool
{
    $format = strtolower((string) ($_GET['format'] ?? ''));
    if ($format === 'json') {
        return true;
    }

    $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
    return str_contains($accept, 'application/json');
}

/**
 * Writes a JSON response and terminates the request.
 *
 * @param array<string, mixed> $payload
 * @return never
 */
function json_response(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    echo (string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Ends the request in HTML or JSON form.
 *
 * @return never
 */
function fail_request(int $statusCode, string $message): never
{
    if (request_wants_json()) {
        json_response(['error' => $message], $statusCode);
    }

    render_home($statusCode, $message);
}

/**
 * Fetches a protected file from the file server with a Bearer token and streams
 * the response back to the browser.
 *
 * The file server becomes a pure bearer-token resource server. Browsers still do
 * not need to attach the Authorization header themselves because the middle
 * service performs the handoff server-to-server.
 *
 * @return never
 */
function stream_file_from_server(string $fileName, string $token): never
{
    $url = FILES_INTERNAL_BASE_URL . '/protected/' . rawurlencode($fileName);
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", [
                'Accept: */*',
                'Authorization: Bearer ' . $token,
            ]),
            'timeout' => 30,
            'ignore_errors' => true,
        ],
    ]);

    $stream = @fopen($url, 'rb', false, $context);
    $headers = $http_response_header ?? [];
    $statusCode = http_status_code_from_headers($headers);

    if ($stream === false || $statusCode < 200 || $statusCode >= 300) {
        if ($statusCode === 401 || $statusCode === 403 || $statusCode === 404) {
            fail_request(403, 'The file server rejected the issued token.');
        }

        fail_request(502, 'The file server could not deliver the requested file.');
    }

    http_response_code($statusCode);
    foreach ($headers as $header) {
        if (
            stripos($header, 'Content-Type:') === 0 ||
            stripos($header, 'Content-Length:') === 0 ||
            stripos($header, 'Content-Disposition:') === 0 ||
            stripos($header, 'Cache-Control:') === 0
        ) {
            header($header, true);
        }
    }

    while (!feof($stream)) {
        $chunk = fread($stream, 8192);
        if ($chunk === false) {
            break;
        }

        echo $chunk;
    }

    fclose($stream);
    exit;
}

/**
 * Extracts the HTTP status code from PHP's response header buffer.
 *
 * @param list<string> $headers
 * @return int
 */
function http_status_code_from_headers(array $headers): int
{
    foreach ($headers as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $matches) === 1) {
            return (int) $matches[1];
        }
    }

    return 0;
}

/**
 * Builds the local middle-service URL for requesting a protected file.
 *
 * @return string
 */
function request_file_url(string $fileName): string
{
    return '/request-file/' . rawurlencode($fileName);
}

/**
 * Escapes dynamic text for HTML output.
 *
 * @return string
 */
function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
