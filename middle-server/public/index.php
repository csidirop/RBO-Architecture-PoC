<?php
declare(strict_types=1);

/**
 * Reads a required runtime setting from the environment and falls back to a safe local default when the variable is unset.
 * * 
 * @param $name The name of the environment variable to read
 * @param $default The default value to use if the variable is not set or empty
 * @return string The value of the environment variable, or the default if not set
 */
function env_value(string $name, string $default): string
{
    $value = getenv($name);
    return $value === false || $value === '' ? $default : $value;
}

// Define all configuration constants at the top of the script for easy reference and modification:
define('APP_SECRET_KEY', env_value('APP_SECRET_KEY', 'replace-this-session-secret')); // Used for session encryption and should be set to a strong random value in production
define('APP_BASE_URL', rtrim(env_value('APP_BASE_URL', 'http://localhost:8080'), '/'));
define('KEYCLOAK_BROWSER_BASE_URL', rtrim(env_value('KEYCLOAK_BROWSER_BASE_URL', 'http://localhost:8081'), '/'));
define('KEYCLOAK_INTERNAL_BASE_URL', rtrim(env_value('KEYCLOAK_INTERNAL_BASE_URL', 'http://keycloak:8080'), '/'));
define('KEYCLOAK_REALM', env_value('KEYCLOAK_REALM', 'image-poc'));
define('KEYCLOAK_CLIENT_ID', env_value('KEYCLOAK_CLIENT_ID', 'middle-poc'));
define('KEYCLOAK_CLIENT_SECRET', env_value('KEYCLOAK_CLIENT_SECRET', 'middle-secret-please-change'));
define('REQUIRED_ROLE', env_value('REQUIRED_ROLE', 'image-reader'));
define('FILES_BASE_URL', rtrim(env_value('FILES_BASE_URL', 'http://localhost:8090'), '/'));
define('FILES_DIRECTORY', env_value('FILES_DIRECTORY', '/data/files'));
define('FILE_TOKEN_SECRET', env_value('FILE_TOKEN_SECRET', 'replace-this-hmac-secret')); // This should be set to the same value as FILE_TOKEN_SECRET in the file server configuration
define('FILE_TOKEN_TTL_SECONDS', (int) env_value('FILE_TOKEN_TTL_SECONDS', '60')); // Time to live
define('FILE_TOKEN_ISSUER', env_value('FILE_TOKEN_ISSUER', 'middle-poc')); // The issuer claim in the file token, which should be set to a unique value for this service
define('FILE_TOKEN_AUDIENCE', env_value('FILE_TOKEN_AUDIENCE', 'image-server')); // The audience claim in the file token, which should match what the file server expects
define('TEMPLATE_HOME', dirname(__DIR__) . DIRECTORY_SEPARATOR . 'templates' . DIRECTORY_SEPARATOR . 'index.html');

session_name('middle-poc-session');
session_set_cookie_params([
    'httponly' => true,
    'path' => '/',
    'samesite' => 'Lax',
]);
session_start();

route_request();

/**
 * Very small front-controller router for the middle service.
 * 
 * Only GET routes are supported because the browser-facing flow is redirect driven:
 * - `/` renders the landing page
 * - `/login` starts the OIDC flow
 * - `/callback` receives the authorization code from Keycloak
 * - `/logout` clears the local session and sends the browser back to Keycloak
 * - `/request-file/<name>` applies policy and mints the short-lived file token
 *
 * Each handler terminates the request on its own, so this function is marked
 * `never` and acts as the single entry point for the script.
 * 
 * @return never
 */
function route_request(): never
{
    $path = (string) (parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/');

    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        render_home(405, 'Method not allowed.');
    }

    if ($path === '/') {
        render_home();
    }

    if ($path === '/login') {
        handle_login();
    }

    if ($path === '/callback') {
        handle_callback();
    }

    if ($path === '/logout') {
        handle_logout();
    }

    if (str_starts_with($path, '/request-file/')) {
        $fileName = rawurldecode(substr($path, strlen('/request-file/')));
        handle_request_file($fileName);
    }

    render_home(404, 'Not found.');
}

/**
 * Starts the browser OIDC authorization-code flow against Keycloak.
 *
 * The most important value here is `state`, which is stored in the local session and later compared in `handle_callback()`. 
 * That comparison protects the callback from CSRF-style login injection and from stale browser tabs replaying an old 
 * authorization response.
 * 
 * @return never
 */
function handle_login(): never
{
    $_SESSION['oidc_state'] = base64url_encode(random_bytes(24)); // Generate a random state value for this login attempt and store it in the session for later verification in the callback handler.

    $params = http_build_query([
        'client_id' => KEYCLOAK_CLIENT_ID,
        'redirect_uri' => APP_BASE_URL . '/callback',
        'response_type' => 'code',
        'scope' => 'openid profile email',
        'state' => $_SESSION['oidc_state'],
    ]);

    redirect_to(browser_oidc_endpoint('auth') . '?' . $params);
}

/**
 * Completes the OIDC browser login after Keycloak redirects back with a code.
 *
 * 1. Validate the returned `state` against the locally stored nonce.
 * 2. Exchange the authorization code for tokens on Keycloak's internal URL.
 * 3. Decode the returned JWT payloads without verifying them locally.
 * 4. Read identity claims from the `id_token` and authorization roles from the `access_token`.
 * 5. Persist the normalized user record in the PHP session for later requests.
 *
 * A few design choices are intentional:
 * - We use the `id_token` for identity data because it is meant for the client.
 * - We use the `access_token` for realm roles because that is where Keycloak exposes authorization data for this PoC.
 * - We do not call `/userinfo` here anymore because the previous version added an extra network hop and became the main 
 *   failure point during login.
 *
 * In a production system we would normally verify token signatures, issuer, audience, and nonce more rigorously.
 * For this PoC the middle service already trusts the direct token response from Keycloak and keeps the implementation
 * intentionally small. But the `decode_unverified_jwt()` helper is available if more local validation is desired in the future.
 * 
 * @return never
 */
function handle_callback(): never
{
    if (isset($_GET['error'])) {
        $message = (string) ($_GET['error_description'] ?? $_GET['error']);
        render_home(400, 'Login failed: ' . $message);
    }

    $state = (string) ($_GET['state'] ?? '');
    $code = (string) ($_GET['code'] ?? '');

    if ($state === '' || $state !== ($_SESSION['oidc_state'] ?? null)) {
        render_home(400, 'Invalid OIDC state.');
    }

    if ($code === '') {
        render_home(400, 'Missing authorization code.');
    }

    unset($_SESSION['oidc_state']);

    try {
        $tokenData = http_post_form_json(
            internal_oidc_endpoint('token'),
            [
                'grant_type' => 'authorization_code',
                'client_id' => KEYCLOAK_CLIENT_ID,
                'client_secret' => KEYCLOAK_CLIENT_SECRET,
                'code' => $code,
                'redirect_uri' => APP_BASE_URL . '/callback',
            ]
        );

        $accessClaims = decode_unverified_jwt((string) ($tokenData['access_token'] ?? ''));
        $idClaims = decode_unverified_jwt((string) ($tokenData['id_token'] ?? ''));
    } catch (RuntimeException $exception) {
        render_home(502, 'Keycloak communication failed: ' . $exception->getMessage());
    }

    $roles = $accessClaims['realm_access']['roles'] ?? [];
    if (!is_array($roles)) {
        $roles = [];
    }
    sort($roles);

    $userClaims = $idClaims !== [] ? $idClaims : $accessClaims;

    $_SESSION['user'] = [
        'sub' => (string) ($userClaims['sub'] ?? ''),
        'name' => $userClaims['name'] ?? null,
        'preferred_username' => (string) (
            $userClaims['preferred_username']
            ?? $userClaims['email']
            ?? $userClaims['sub']
            ?? 'unknown'
        ),
        'email' => $userClaims['email'] ?? null,
        'roles' => $roles,
    ];

    redirect_to('/');
}

/**
 * Clears the local application session and delegates identity logout to Keycloak.
 *
 * The local session is removed first so that the PoC immediately forgets the current user even if the user closes the browser 
 * before the IdP logout flow completes.
 * 
 * @return never
 */
function handle_logout(): never
{
    $_SESSION = [];
    if (session_id() !== '') {
        session_destroy();
    }

    $params = http_build_query([
        'client_id' => KEYCLOAK_CLIENT_ID,
        'post_logout_redirect_uri' => APP_BASE_URL . '/',
    ]);

    redirect_to(browser_oidc_endpoint('logout') . '?' . $params);
}

/**
 * Applies the local access policy and mints a file-specific HMAC JWT.
 *
 * This function is the "policy decision point" of the reduced architecture.
 * It does three things:
 * - Ensures a browser session exists
 * - Ensures the requested file is real and safely inside the mounted file area
 * - Ensures the authenticated user has the required Keycloak realm role
 *
 * Once those checks pass, it creates a short-lived JWT that is scoped to the resolved file name. The browser is then
 * redirected to the Apache file server, which independently validates that JWT before serving bytes.
 *
 * The security model here is intentionally split:
 * - Keycloak authenticates the user
 * - The middle service decides whether the user may request a file
 * - The file server trusts only the signed HMAC token, not the browser session
 * 
 * @return never
 */
function handle_request_file(string $fileName): never
{
    $user = $_SESSION['user'] ?? null;
    if (!is_array($user)) {
        redirect_to('/login');
    }

    $resolved = resolve_file($fileName);
    if ($resolved === null) {
        render_home(404, 'Requested file not found.');
    }

    $roles = $user['roles'] ?? [];
    if (!is_array($roles)) {
        $roles = [];
    }

    if (REQUIRED_ROLE !== '' && !in_array(REQUIRED_ROLE, $roles, true)) {
        render_home(
            403,
            'Authenticated, but policy denied access. Required role: ' . REQUIRED_ROLE . '.'
        );
    }

    $safeFileName = basename($resolved);
    $token = build_file_token($user, $safeFileName);
    $targetUrl = FILES_BASE_URL . '/protected/' . rawurlencode($safeFileName)
        . '?' . http_build_query(['token' => $token]);

    redirect_to($targetUrl);
}

/**
 * Renders the landing page template with normalized view data.
 *
 * The template itself stays HTML-heavy so the visual structure is easy to edit, while this function prepares the 
 * small amount of dynamic state the page needs:
 * current user, mounted files, URLs, and optional error text.
 * 
 * @return never
 */
function render_home(int $statusCode = 200, ?string $errorMessage = null): never
{
    http_response_code($statusCode);

    $user = $_SESSION['user'] ?? null;
    if (!is_array($user)) {
        $user = null;
    }

    $files = list_available_files();
    $requiredRole = REQUIRED_ROLE;
    $fileTokenTtl = FILE_TOKEN_TTL_SECONDS;
    $loginUrl = '/login';
    $logoutUrl = '/logout';
    $keycloakAdminUrl = KEYCLOAK_BROWSER_BASE_URL . '/admin/';

    require TEMPLATE_HOME;
    exit;
}

/**
 * Returns the list of sample files exposed through the PoC.
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
 * Resolves a user-supplied file name to a safe absolute path.
 *
 * This is one of the key file-safety checks in the middle service. The function normalizes separators, resolves the 
 * real path on disk, and then verifies that the resolved file still lives underneath `FILES_DIRECTORY`.
 *
 * That final containment check prevents directory traversal attempts such as`../../secret.txt`, even if the filesystem 
 * would otherwise resolve them.
 *
 * @return string|null The absolute path to the requested file if it is valid and within the base directory, or `null` if the file does not exist or is outside the allowed area.
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

    // Ensure the resolved file is still within the base directory to prevent directory traversal attacks:
    if (!str_starts_with($candidate, $baseDirectory . DIRECTORY_SEPARATOR)) {
        return null;
    }

    return $candidate;
}

/**
 * Builds the short-lived HS256 JWT understood by the Apache file gate.
 *
 * The token deliberately contains only the claims needed by the downstream validator:
 * - issuer and audience so the token cannot be confused with another one
 * - subject and preferred username for traceability
 * - exact file name so the token cannot be replayed for another path
 * - timestamps and a random `jti` so the token is short-lived and distinguishable
 *
 * The token is signed with a shared secret known to the middle service and the file server. This keeps the PoC
 * simple while still modeling a detached access artifact that the file server can validate without talking to Keycloak.
 * 
 * @return string The serialized JWT token that can be included in the file request URL.
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
 * This helper is intentionally narrow: it is used only after the middle service has already received a direct token response
 * from Keycloak. It is not meant to decide whether a third-party token is trustworthy; it only extracts claims from a token
 * that is already trusted by the current code path.
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
 * Encodes raw bytes or text as URL-safe Base64 without padding, which is the format used by JWT segments.
 * 
 * @return string The Base64URL-encoded string.
 */
function base64url_encode(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

/**
 * Decodes URL-safe Base64 and restores the required padding automatically.
 *
 * Returns `null` instead of throwing so the callers can treat malformed JWT segments as ordinary invalid input.
 * 
 * @return string|null The decoded binary string, or `null` if decoding fails due to invalid input.
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
 * Sends an `application/x-www-form-urlencoded` POST request and expects JSON.
 *
 * This is the main transport helper used for the Keycloak code-to-token exchange. It is intentionally opinionated:
 * - request body is form encoded, matching OAuth/OIDC token endpoints
 * - response is expected to be JSON
 * - non-2xx replies are converted into readable exceptions with the best available error detail from the response body
 *
 * Keeping this logic in one helper makes the callback flow easier to read and ensures Keycloak failures are surfaced to 
 * the user in a consistent form.
 *
 * @param array<string, scalar> $fields
 * @return array<string, mixed>
 */
function http_post_form_json(string $url, array $fields): array
{
    $content = http_build_query($fields);
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", [
                'Accept: application/json',
                'Content-Type: application/x-www-form-urlencoded',
            ]),
            'content' => $content,
            'timeout' => 10,
            'ignore_errors' => true,
        ],
    ]);

    $body = @file_get_contents($url, false, $context);
    $headers = $http_response_header ?? [];
    $statusCode = http_status_code_from_headers($headers);

    if ($body === false) {
        throw new RuntimeException('Request failed for ' . $url);
    }

    $decoded = json_decode($body, true);
    if ($statusCode < 200 || $statusCode >= 300) {
        $detail = 'Unexpected response';
        if (is_array($decoded)) {
            $detail = (string) ($decoded['error_description'] ?? $decoded['error'] ?? $detail);
        }
        throw new RuntimeException('HTTP ' . $statusCode . ' from ' . $url . ': ' . $detail);
    }

    if (!is_array($decoded)) {
        throw new RuntimeException('Invalid JSON response from ' . $url);
    }

    return $decoded;
}

/**
 * Extracts the numeric HTTP status code from PHP's response-header array.
 *
 * @return int The HTTP status code, or 0 if not found.
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
 * Builds the browser-facing Keycloak OIDC endpoint URL.
 *
 * This uses the host-visible base URL because the user's browser, not the container network, follows these redirects.
 * 
 * @return string The full URL to the specified OIDC endpoint on the Keycloak server, suitable for browser redirects.
 */
function browser_oidc_endpoint(string $name): string
{
    return KEYCLOAK_BROWSER_BASE_URL . '/realms/' . rawurlencode(KEYCLOAK_REALM) . '/protocol/openid-connect/' . $name;
}

/**
 * Builds the container-internal Keycloak OIDC endpoint URL.
 *
 * This uses the Docker-network hostname so server-to-server requests do not need to leave the compose network and come back through
 * host port mappings.
 * 
 * @return string The full URL to the specified OIDC endpoint on the Keycloak server, suitable for internal server requests.
 */
function internal_oidc_endpoint(string $name): string
{
    return KEYCLOAK_INTERNAL_BASE_URL . '/realms/' . rawurlencode(KEYCLOAK_REALM) . '/protocol/openid-connect/' . $name;
}

/**
 * Sends a redirect response and terminates execution immediately.
 * 
 * @return never
 */
function redirect_to(string $url): never
{
    header('Location: ' . $url, true, 302);
    exit;
}

/**
 * Generates the local route used to request a protected file through the middle service.
 * 
 * @return string The URL path to request the specified file, which will trigger the policy checks and token minting in
 * `handle_request_file()`.
 */
function request_file_url(string $fileName): string
{
    return '/request-file/' . rawurlencode($fileName);
}

/**
 * HTML-escapes user-controlled or dynamic text before rendering.
 * 
 * @return string The escaped string, safe for inclusion in HTML contexts.
 */
function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
