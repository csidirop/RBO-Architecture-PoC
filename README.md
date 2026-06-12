# Keycloak to Middle Service to Apache File Server PoC

This repository contains a Docker Compose proof of concept for a protected file-access flow with three main parts:

1. [Keycloak](#keycloak) authenticates the user.
2. The [PHP middle service](#middle-service) decides whether that user may request a specific file.
3. The [file server](#file-server) gets the forwarded file-specific bearer token from Apache, where the `mod_auth_openidc` module validates it before PHP streams the bytes.

An additional `cantaloupe` container is included as a separate image-server option for local testing. It is not wired into the middle-service auth flow.

### Lineout

0. (after user authentication)
1. The _middle service_ mints a short-lived JWT that is valid for exactly those files written into the token.
2. The _middle service_ stores that JWT in a short-lived, path-scoped cookie for `/file-proxy/<file>`.
3. Apache on the _middle service_ converts that cookie into `Authorization: Bearer <jwt>` when proxying to the file server.
4. Apache on the _file server_ validates the bearer token with `mod_auth_openidc` in OAuth resource-server mode.
5. `serve.php` only resolves and streams the file after Apache auth has already succeeded.


## Architecture

### Keycloak

- Runs on `http://localhost:8081`
- Authenticates demo users for the middle service

### Middle Service

- Runs on `http://localhost:8080`
- Owns the browser login flow and the PHP session
- Shows the landing page and protected file links
- Applies the local role check
- Mints the file-specific RS256 JWT
- Stores that JWT in a short-lived cookie
- Proxies `/file-proxy/<file>` to the file server and injects the bearer header

### File Server

- Runs on `http://localhost:8090`
- Exposes a public landing page for testing
- Protects `/protected/<file>` with Apache auth
- Uses `mod_auth_openidc` to validate the JWT from the `Authorization` header
- Uses PHP only for safe path resolution and file streaming

### Cantaloupe

- Runs on `http://localhost:8182`
- Serves images directly from the mounted `sample-files/protected` directory
- Is separate from the Keycloak and middle-service flow in this version
- Can be tested directly with Cantaloupe's IIIF endpoint

## Request Flow

### 1. Browser Login

1. The user opens `http://localhost:8080`.
2. The middle service redirects the browser to Keycloak.
3. Keycloak returns an authorization code to `/callback`.
4. The middle service exchanges that code for tokens on the internal Keycloak URL.
5. The middle service stores a normalized user record in the PHP session.

### 2. Requesting a File

1. The browser requests `/request-file/<name>` on the middle service.
2. The middle service checks:
   - a valid PHP session exists
   - the resolved path stays inside `/data/files`
   - the user has the configured Keycloak role
3. If allowed, the middle service mints a short-lived RS256 JWT with claims for:
   - `iss`
   - `aud`
   - `sub`
   - `preferred_username`
   - `file`
   - `iat`
   - `nbf`
   - `exp`
   - `jti`
4. The middle service sets `file_access_token=<jwt>` as an `HttpOnly` cookie scoped to `/file-proxy/<file>`.
5. The middle service redirects the browser to `/file-proxy/<file>`.

### 3. Apache Proxy Hop

1. The browser calls `http://localhost:8080/file-proxy/<file>`.
2. Apache on the middle service reads `file_access_token` from the cookie.
3. Apache removes incoming cookies for the upstream hop.
4. Apache sets `Authorization: Bearer <jwt>`.
5. Apache proxies the request to `http://file-server/protected/<file>`.

### 4. File Server Authorization

Apache on the file server performs token verification before PHP runs:

1. Accept only bearer tokens from the `Authorization` header.
2. Validate the RS256 signature with the configured public certificate.
3. Require the configured issuer claim.
4. Require the configured audience claim.
5. Pass the validated claims to PHP, where `serve.php` enforces that the custom `file` claim matches the requested `/protected/<file>` path.

If any of those checks fail, Apache returns the generic error page.

If they pass, `serve.php` resolves the path safely and streams the file.

## Cantaloupe Access

Cantaloupe is exposed directly on port `8182` and is not protected by the middle-service token flow in this version.

Regular image URL:

```text
http://localhost:8182/iiif/2/1652998101_0002.jpg/full/full/0/default.jpg
```

IIIF metadata URL:

```text
http://localhost:8182/iiif/2/1652998101_0002.jpg/info.json
```

Those identifiers map to:

```text
sample-files/protected/
```

### 5. Browser Logout

1. PHP expires the local session cookie and any file-token cookies issued during that session.
2. The browser is sent to the `mod_auth_openidc` logout URL.
3. `mod_auth_openidc` clears its own session and forwards the logout to Keycloak's end-session endpoint.
4. Keycloak clears the SSO session and redirects the browser back to the landing page.

## Relevant Files

- `docker-compose.yml`
  - service definitions for Keycloak, middle, file-server, and Cantaloupe
- `middle-server/public/index.php`
  - browser login flow
  - policy decision
  - file-token minting
  - cookie hand-off to the proxy path
- `middle-server/apache/poc.conf`
  - same-origin reverse proxy
  - cookie-to-authorization-header translation
  - Keycloak login/logout endpoint configuration
- `file-server/apache/poc.conf`
  - `mod_auth_openidc` resource-server configuration
  - issuer and audience enforcement
- `file-server/public/serve.php`
  - safe path resolution and file streaming only

## Run It

```bash
docker compose up --build
```

Then open:

- `http://localhost:8080` for the middle-service landing page
- `http://localhost:8081/admin/` for the Keycloak admin console
- `http://localhost:8090` for the public file-server landing page
- `http://localhost:8182/iiif/2/1652998101_0002.jpg/full/full/0/default.jpg` for a direct Cantaloupe image test

### Demo Users

- `reader / reader123`
  - Has the `image-reader` role and can request protected files.
- `blocked / blocked123`
  - Can authenticate in Keycloak, but the middle service denies file access.
- `admin / admin`
  - Keycloak administrator account for local development.

## Notes

- The file-access JWT is intentionally local to this PoC and is signed by the middle service with a private key that is paired with the file server's public certificate.
- The token is no longer visible in browser URLs.
- Direct requests to `http://localhost:8090/protected/<file>` without a valid bearer token are rejected by Apache.
- Cantaloupe is currently just a separate direct server option; it is not yet integrated into the middle-service authorization flow.

## References

- https://github.com/OpenIDC/mod_auth_openidc
- https://cantaloupe-project.github.io/
- https://www.keycloak.org/securing-apps/oidc-layers
- https://openid.net/specs/openid-connect-core-1_0.html
