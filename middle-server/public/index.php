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
define('APP_BASE_URL', rtrim(env_value('APP_BASE_URL', 'http://localhost:8080'), '/'));
define('KEYCLOAK_BROWSER_BASE_URL', rtrim(env_value('KEYCLOAK_BROWSER_BASE_URL', 'http://localhost:8081'), '/'));
define('CANTALOUPE_BASE_URL', rtrim(env_value('CANTALOUPE_BASE_URL', 'http://localhost:8182'), '/'));
define('REQUIRED_ROLE', env_value('REQUIRED_ROLE', 'image-reader'));
define('FILES_DIRECTORY', env_value('FILES_DIRECTORY', '/data/files'));
define('UNPROTECTED_FILES_SUBDIRECTORY', env_value('UNPROTECTED_FILES_SUBDIRECTORY', 'unprotected'));
define('PROTECTED_FILES_SUBDIRECTORY', env_value('PROTECTED_FILES_SUBDIRECTORY', 'protected'));
define('FILE_TOKEN_PRIVATE_KEY_PATH', env_value('FILE_TOKEN_PRIVATE_KEY_PATH', '/run/secrets/file-token-private.pem'));
define('FILE_TOKEN_TTL_SECONDS', (int) env_value('FILE_TOKEN_TTL_SECONDS', '60')); // Time to live
define('FILE_TOKEN_ISSUER', env_value('FILE_TOKEN_ISSUER', 'middle-poc')); // The issuer claim in the file token, which should be set to a unique value for this service
define('FILE_TOKEN_AUDIENCE', env_value('FILE_TOKEN_AUDIENCE', 'image-server')); // The audience claim in the file token, which should match what the file server expects
define('UNPROTECTED_FILE_PROXY_PATH_PREFIX', '/unprotected');
define('FILE_PROXY_PATH_PREFIX', '/file-proxy');
define('FILE_TOKEN_COOKIE_NAME', 'file_access_token');
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
 * - `/login` is protected by Apache/mod_auth_openidc and stores the authenticated user claims locally
 * - `/logout` clears the local session and delegates logout to mod_auth_openidc
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

    if ($path === '/callback' || $path === '/oidc/callback') {
        redirect_to('/');
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
 * Completes the Apache-managed login hand-off.
 *
 * The `/login` route is protected by `mod_auth_openidc`, so PHP only runs here after
 * Apache has already completed the OIDC flow and exposed the validated user claims.
 * 
 * @return never
 */
function handle_login(): never
{
    $user = apache_authenticated_user();
    if ($user === null) {
        render_home(401, 'Login finished, but Apache did not provide user claims.');
    }

    $_SESSION['user'] = $user;

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
    clear_issued_file_token_cookies();

    $_SESSION = [];
    clear_php_session_cookie();

    if (session_id() !== '') {
        session_destroy();
    }

    redirect_to(apache_oidc_logout_url('/'));
}

/**
 * Stops the request when the authenticated user lacks the configured Keycloak role.
 *
 * @param array<string, mixed> $user
 */
function assert_user_has_required_role(array $user): void
{
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
}

/**
 * Expires the PHP session cookie in the browser as well as destroying server-side state.
 */
function clear_php_session_cookie(): void
{
    if (session_id() === '') {
        return;
    }

    $params = session_get_cookie_params();
    $options = [
        'expires' => time() - 3600,
        'path' => ($params['path'] ?? '') !== '' ? $params['path'] : '/',
        'secure' => (bool) ($params['secure'] ?? false),
        'httponly' => (bool) ($params['httponly'] ?? true),
        'samesite' => ($params['samesite'] ?? '') !== '' ? $params['samesite'] : 'Lax',
    ];

    if (($params['domain'] ?? '') !== '') {
        $options['domain'] = $params['domain'];
    }

    setcookie(session_name(), '', $options);
}

/**
 * Expires path-scoped file-token cookies issued during this browser session.
 */
function clear_issued_file_token_cookies(): void
{
    $paths = $_SESSION['file_token_cookie_paths'] ?? [];
    if (!is_array($paths)) {
        return;
    }

    foreach (array_keys($paths) as $path) {
        if (is_string($path) && str_starts_with($path, FILE_PROXY_PATH_PREFIX . '/')) {
            expire_file_token_cookie($path);
        }
    }
}

/**
 * Applies the local access policy and mints a file-specific JWT.
 *
 * This function is the "policy decision point" of the reduced architecture.
 * It does three things:
 * - Ensures a browser session exists
 * - Ensures the requested file is real and safely inside the mounted file area
 * - Ensures the authenticated user has the required Keycloak realm role
 *
 * Once those checks pass, it creates a short-lived JWT that is scoped to the resolved file name. The token is stored in
 * a short-lived, path-scoped cookie and the browser is redirected to a middle-server proxy path. Apache converts that
 * cookie into an `Authorization: Bearer` header when it forwards the request to the file server.
 *
 * The security model here is intentionally split:
 * - Keycloak authenticates the user
 * - The middle service decides whether the user may request a file
 * - The file server trusts only the signed file token, not the browser session
 * 
 * @return never
 */
function handle_request_file(string $fileName): never
{
    $user = current_user();
    if (!is_array($user)) {
        redirect_to('/login');
    }

    $resolvedFileName = resolve_file($fileName);
    if ($resolvedFileName === null) {
        render_home(404, 'Requested file not found.');
    }

    assert_user_has_required_role($user);

    try {
        $token = build_file_token($user, $resolvedFileName);
        issue_access_token_cookie($token, proxy_file_cookie_path($resolvedFileName));
    } catch (RuntimeException $exception) {
        render_home(500, 'Failed to prepare the file access hand-off.');
    }

    $targetUrl = file_token_cookie_path($resolvedFileName); //Builds the same-origin proxy URL that will forward the file request to the file server.

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

    $user = current_user();

    $unprotectedFiles = list_available_files_in_subdirectory(UNPROTECTED_FILES_SUBDIRECTORY);
    $protectedFiles = list_available_files_in_subdirectory(PROTECTED_FILES_SUBDIRECTORY);
    $requiredRole = REQUIRED_ROLE;
    $fileTokenTtl = FILE_TOKEN_TTL_SECONDS;
    $loginUrl = '/login';
    $logoutUrl = '/logout';
    $keycloakAdminUrl = KEYCLOAK_BROWSER_BASE_URL . '/admin/';

    require TEMPLATE_HOME;
    exit;
}

/**
 * Returns the authenticated user from Apache claims or from the local display session.
 *
 * Apache is now responsible for the OIDC protocol. PHP keeps a small normalized
 * user snapshot only so the public landing page can still show who is signed in.
 *
 * @return array<string, mixed>|null
 */
function current_user(): ?array
{
    $apacheUser = apache_authenticated_user();
    if ($apacheUser !== null) {
        $_SESSION['user'] = $apacheUser;
        return $apacheUser;
    }

    $sessionUser = $_SESSION['user'] ?? null;
    return is_array($sessionUser) ? $sessionUser : null;
}

/**
 * Reads validated identity claims that mod_auth_openidc exposed to PHP.
 *
 * @return array<string, mixed>|null
 */
function apache_authenticated_user(): ?array
{
    $remoteUser = server_value('REMOTE_USER');
    $sub = server_value('OIDC_CLAIM_sub');

    if ($remoteUser === '' && $sub === '') {
        return null;
    }

    $roles = apache_claim_roles();
    sort($roles);

    $preferredUsername = first_non_empty([
        server_value('OIDC_CLAIM_preferred_username'),
        server_value('OIDC_CLAIM_email'),
        $sub,
        $remoteUser,
        'unknown',
    ]);

    return [
        'sub' => $sub !== '' ? $sub : $remoteUser,
        'name' => nullable_string(server_value('OIDC_CLAIM_name')),
        'preferred_username' => $preferredUsername,
        'email' => nullable_string(server_value('OIDC_CLAIM_email')),
        'roles' => $roles,
    ];
}

/**
 * Collects Keycloak realm roles from the claim shapes commonly exposed by mod_auth_openidc.
 *
 * @return list<string>
 */
function apache_claim_roles(): array
{
    $roles = [];
    foreach ([
        'OIDC_CLAIM_realm_access.roles',
        'OIDC_CLAIM_realm_access_roles',
        'OIDC_CLAIM_roles',
        'OIDC_CLAIM_groups',
    ] as $claimName) {
        $roles = array_merge($roles, claim_value_to_list(server_value($claimName)));
    }

    $realmAccess = json_decode(server_value('OIDC_CLAIM_realm_access'), true);
    if (is_array($realmAccess)) {
        $roles = array_merge($roles, claim_value_to_list($realmAccess['roles'] ?? []));
    }

    $roles = array_values(array_unique(array_filter(
        array_map(static fn (string $role): string => trim($role), $roles),
        static fn (string $role): bool => $role !== ''
    )));

    return $roles;
}

/**
 * Converts a claim value into a flat string list.
 * 
 * @return list<string>
 */
function claim_value_to_list(mixed $value): array
{
    if (is_array($value)) {
        if (isset($value['roles'])) {
            return claim_value_to_list($value['roles']);
        }

        $items = [];
        foreach ($value as $item) {
            if (is_scalar($item)) {
                $items[] = (string) $item;
            }
        }
        return $items;
    }

    if (!is_scalar($value)) {
        return [];
    }

    $stringValue = trim((string) $value);
    if ($stringValue === '') {
        return [];
    }

    $decoded = json_decode($stringValue, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        return claim_value_to_list($decoded);
    }

    return preg_split('/[\s,]+/', $stringValue, -1, PREG_SPLIT_NO_EMPTY) ?: [];
}

function server_value(string $name): string
{
    $value = $_SERVER[$name] ?? getenv($name);
    return is_scalar($value) ? (string) $value : '';
}

/**
 * @param list<string> $values
 */
function first_non_empty(array $values): string
{
    foreach ($values as $value) {
        if ($value !== '') {
            return $value;
        }
    }

    return '';
}

function nullable_string(string $value): ?string
{
    return $value === '' ? null : $value;
}

/**
 * Returns the list of sample files exposed through a mounted subdirectory.
 *
 * @return list<string>
 */
function list_available_files_in_subdirectory(string $relativeDirectory): array
{
    $baseDirectory = realpath(FILES_DIRECTORY);
    if ($baseDirectory === false) {
        return [];
    }

    $normalizedDirectory = trim(str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $relativeDirectory), DIRECTORY_SEPARATOR);
    if ($normalizedDirectory === '') {
        return [];
    }

    $directory = realpath($baseDirectory . DIRECTORY_SEPARATOR . $normalizedDirectory);
    if ($directory === false || !is_dir($directory)) {
        return [];
    }

    $basePrefix = $baseDirectory . DIRECTORY_SEPARATOR;
    if (!str_starts_with($directory . DIRECTORY_SEPARATOR, $basePrefix)) {
        return [];
    }

    $files = [];
    foreach (scandir($directory) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || str_starts_with($entry, '.')) {
            continue;
        }

        $candidate = $directory . DIRECTORY_SEPARATOR . $entry;
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
 * @return string|null The normalized path relative to the base directory if it is valid and within the allowed area, or
 * `null` if the file does not exist or is outside the allowed area.
 */
function resolve_file(string $name): ?string
{
    $baseDirectory = realpath(FILES_DIRECTORY);
    if ($baseDirectory === false) {
        return null;
    }

    $normalized = str_replace('\\', '/', $name);
    $candidate = realpath($baseDirectory . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $normalized));
    if ($candidate === false || !is_file($candidate)) {
        return null;
    }

    // Ensure the resolved file is still within the base directory to prevent directory traversal attacks:
    $basePrefix = $baseDirectory . DIRECTORY_SEPARATOR;
    if (!str_starts_with($candidate, $basePrefix)) {
        return null;
    }

    $relativePath = substr($candidate, strlen($basePrefix));
    return str_replace(DIRECTORY_SEPARATOR, '/', $relativePath);
}

/**
 * Builds the short-lived RS256 JWT understood by the Apache file gate.
 *
 * The token deliberately contains only the claims needed by the downstream validator:
 * - issuer and audience so the token cannot be confused with another one
 * - subject and preferred username for traceability
 * - exact file name so the token cannot be replayed for another path
 * - timestamps and a random `jti` so the token is short-lived and distinguishable
 *
 * The token is signed with the middle service's private key. Apache on the file server verifies that
 * signature with the matching public certificate, so the file server never needs the signing key itself.
 * 
 * @return string The serialized JWT token that Apache can forward in an Authorization header.
 */
function build_file_token(array $user, string $fileName): string
{
    $now = time();
    $header = [
        'alg' => 'RS256',
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
    $privateKeyContents = @file_get_contents(FILE_TOKEN_PRIVATE_KEY_PATH);
    if ($privateKeyContents === false || $privateKeyContents === '') {
        throw new RuntimeException('File-token signing key is not readable.');
    }

    $privateKey = openssl_pkey_get_private($privateKeyContents);
    if ($privateKey === false) {
        throw new RuntimeException('File-token signing key is invalid.');
    }

    $signature = '';
    $success = openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
    if ($success !== true) {
        throw new RuntimeException('File-token signing failed.');
    }

    return $signingInput . '.' . base64url_encode($signature);
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
 * Builds the mod_auth_openidc logout URL and sends the browser back to the public home page afterwards.
 */
function apache_oidc_logout_url(string $returnPath): string
{
    $normalizedPath = '/' . ltrim($returnPath, '/');
    return APP_BASE_URL . '/oidc/callback?logout=' . rawurlencode(APP_BASE_URL . $normalizedPath);
}

/**
 * Stores the short-lived file token in a path-scoped cookie for the proxy hop.
 *
 * The cookie is limited to the target proxy path so the browser sends it only on the
 * follow-up request that fetches the protected file through Apache.
 */
function issue_access_token_cookie(string $token, string $cookiePath): void
{
    $cookiePath = file_token_cookie_path($fileName);
    $success = setcookie(
        FILE_TOKEN_COOKIE_NAME,
        $token,
        [
            'expires' => time() + FILE_TOKEN_TTL_SECONDS,
            'httponly' => true,
            'path' => $cookiePath,
            'samesite' => 'Lax',
        ]
    );

    if ($success === false) {
        throw new RuntimeException('Failed to issue the file access cookie.');
    }

    $_SESSION['file_token_cookie_paths'][$cookiePath] = true;
}

/**
 * Expires a path-scoped file-token cookie in the browser.
 */
function expire_file_token_cookie(string $path): void
{
    setcookie(
        FILE_TOKEN_COOKIE_NAME,
        '',
        [
            'expires' => time() - 3600,
            'httponly' => true,
            'path' => $path,
            'samesite' => 'Lax',
        ]
    );
}

/**
 * Returns the exact browser path used for the file-token cookie.
 */
function file_token_cookie_path(string $fileName): string
{
    return FILE_PROXY_PATH_PREFIX . '/' . encode_url_path($fileName);
}

/**
 * Builds the cookie path for a direct protected-file request.
 */
function proxy_file_cookie_path(string $fileName): string
{
    return proxy_file_url($fileName);
}

/**
 * Builds the same-origin URL for files that bypass the protected token flow.
 */
function unprotected_file_url(string $fileName): string
{
    return UNPROTECTED_FILE_PROXY_PATH_PREFIX . '/' . encode_url_path($fileName);
}

/**
 * Builds the direct Cantaloupe image URL for a protected file.
 */
function cantaloupe_image_url(string $fileName): string
{
    return CANTALOUPE_BASE_URL . '/iiif/2/' . encode_url_path($fileName) . '/full/full/0/default.jpg';
}

/**
 * Builds the direct Cantaloupe IIIF info.json URL for a protected file.
 */
function cantaloupe_info_url(string $fileName): string
{
    return CANTALOUPE_BASE_URL . '/iiif/2/' . encode_url_path($fileName) . '/info.json';
}

/**
 * Generates the local route used to request a protected file through the middle service.
 * 
 * @return string The URL path to request the specified file, which will trigger the policy checks and token minting in
 * `handle_request_file()`.
 */
function request_file_url(string $fileName): string
{
    return '/request-file/' . encode_url_path($fileName);
}

/**
 * URL-encodes each path segment while preserving directory separators.
 */
function encode_url_path(string $path): string
{
    $normalizedPath = trim(str_replace('\\', '/', $path), '/');
    if ($normalizedPath === '') {
        return '';
    }

    $segments = array_filter(explode('/', $normalizedPath), static fn (string $segment): bool => $segment !== '');
    return implode('/', array_map(static fn (string $segment): string => rawurlencode($segment), $segments));
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
