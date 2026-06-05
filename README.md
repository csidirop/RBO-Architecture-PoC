# Keycloak to Middle Service to Apache File Server PoC

This repository contains a small Docker Compose proof of concept for this flow:

1. Keycloak authenticates the user with OpenID Connect.
2. Apache on the middle server handles the browser login with `mod_auth_openidc`.
3. A small PHP middle service receives Apache-provided identity claims and applies a simple policy check.
4. The middle service mints a short-lived HMAC JWT for one file.
5. Apache on the file server validates that token before serving the file.
6. If the token is missing or invalid, Apache returns the error page.

### Overview

- Apache `mod_auth_openidc` now owns the browser authentication flow on the middle server.
- The PHP middle service is now mainly the landing page and the policy decision point.
- The policy is only a Keycloak role check.
- The file token is a shared-secret HMAC JWT instead of a full external PDP policy artifact.
- Apache on the file server validates the file token with `mod_auth_openidc` in OAuth 2.0 resource-server mode.
- The `file` claim is still minted into the token, but exact file-to-path binding is not yet enforced by the Apache module configuration in this first cut.

## How the PoC Works

The current Proof of Concept:

1. Keycloak authenticates the human user for the middle server.
2. Apache on the middle server passes the authenticated identity to PHP.
3. The middle service converts that authenticated user into a short-lived file token that the Apache file server can validate on its own.

### Keycloak to Middle Service

The browser carries the login flow, but Apache now does the OIDC work:

1. The user opens the middle server on `http://localhost:8080`.
2. Public content stays on `/`, while Apache protects `/app`, `/request-file/<name>`, and `/oidc/callback`.
3. When the browser reaches a protected path, `mod_auth_openidc` redirects the browser to Keycloak.
4. The middle Apache vhost proxies Keycloak under `/kc`, so both the browser and the module see the same provider URLs.
5. After login, Keycloak returns to `/oidc/callback` on the middle server and `mod_auth_openidc` establishes the local Apache session.
6. Apache passes claims and the access token to PHP through environment variables.
7. The middle service reads:
   - identity claims from Apache-provided claim variables
   - realm roles by decoding the Apache-provided access token

Important functions for this part:

- `route_request()` in `middle-server/public/index.php`
  - Dispatches `/`, `/app`, and `/request-file/<name>`
- `current_user_from_environment()` in `middle-server/public/index.php`
  - Rebuilds the current user from Apache-provided claim variables and the access token
- `decode_unverified_jwt()` in `middle-server/public/index.php`
  - Extracts realm roles from the access token after Apache has already authenticated the browser

### Middle Service to File Server

When the user requests a file, the middle service becomes the simplified policy decision point:

1. The user opens a protected file url.
2. The browser requests `/request-file/<name>` from the middle service.
3. The middle service checks:
   - Apache has already authenticated the browser
   - the requested file really exists
   - the resolved file path stays inside the mounted file directory
   - the user has the required Keycloak realm role, currently `image-reader`
4. If the user is allowed, the middle service creates a short-lived HS256 JWT that is valid only for that exact file.
5. The middle service supports two header-based handoff modes:
   - browser mode: `/request-file/<name>` streams the file back after a server-side Bearer-token request to the file server
   - API mode: return JSON metadata with a Bearer token plus a direct download URL

Important functions for this part:

- `handle_request_file()` in `middle-server/public/index.php`
  - Applies policy and either returns JSON token metadata or streams the file back to the browser
- `resolve_file()` in `middle-server/public/index.php`
  - Prevents path traversal and ensures the file stays inside the allowed directory
- `build_file_token()` in `middle-server/public/index.php`
  - Creates the signed file-access JWT

The file-access JWT contains these claims:

- `iss` = issuer: who created the token, in this PoC the middle service
- `aud` = audience: who the token is meant for, in this PoC the image/file server
- `sub` = subject: the user identifier the token belongs to
- `preferred_username` = the human-readable username of the authenticated user
- `file` = the exact file name this token is allowed to access
- `iat` = issued at: the Unix timestamp when the token was created
- `nbf` = not before: the Unix timestamp before which the token must not be accepted
- `exp` = expiry: the Unix timestamp after which the token is no longer valid
- `jti` = JWT ID: a unique token identifier so each token can be distinguished from others

### Validation on the Apache File Server

The file server does not trust the PHP session from the middle service and does not ask Keycloak anything. It trusts only the HMAC JWT created by the middle service.

Apache now validates the file token directly in the web server:

1. Apache exposes the mounted sample directory through `/protected/`.
2. The browser never sends the bearer token itself during the normal web flow; the middle service sends it in a server-to-server `Authorization: Bearer <jwt>` request.
3. `mod_auth_openidc` on the file server accepts bearer tokens only from the header.
4. Apache validates:
   - JWT signature with `OIDCOAuthVerifySharedKeys`
   - expected issuer claim
   - expected audience claim
   - standard token lifetime checks such as `exp` and `nbf`
5. If validation passes, Apache serves the static file directly from `/data/files`.
6. If validation fails, Apache serves `/error.html`.

Important current limitation:

- The token still carries the `file` claim, but Apache is not yet comparing that claim to the requested path in this first module-based version.
- That means a valid short-lived token is currently accepted for the protected area in general, not yet bound to one exact file path.
- Tight file-to-token binding is the next security step to add.

Important configuration for this part:

- `file-server/apache/poc.conf.template`
  - Defines `/protected/` as an Apache OAuth 2.0 protected location
- `OIDCOAuthAcceptTokenAs header`
  - Ensures only `Authorization: Bearer ...` is accepted
- `OIDCOAuthVerifySharedKeys`
  - Verifies the HS256 signature with the shared secret from the middle service
- `Require claim iss:...` and `Require claim aud:...`
  - Restrict accepted tokens to the expected issuer and audience

### Example Token

That is an example request target: `http://localhost:8090/protected/1652989927_0002.jpg`

The actual token sent to the file server is the JWT itself in the `Authorization: Bearer ...` header:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtaWRkbGUtcG9jIiwiYXVkIjoiaW1hZ2Utc2VydmVyIiwic3ViIjoiMmQ1NGM3Y2EtYzE4MC00NGYxLWEyOTMtZjliOGQxMTFiYjBmIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicmVhZGVyIiwiZmlsZSI6IjE2NTI5ODk5MjdfMDAwMi5qcGciLCJpYXQiOjE3NzgwNjg0NTUsIm5iZiI6MTc3ODA2ODQ1NSwiZXhwIjoxNzc4MDY4NTE1LCJqdGkiOiI0d1JrTDBJREU5YyJ9.RNQKGqhR0gcYqypdcbLqaqPFcAJH1jaR4qXIvnTfadE
```

The String consists of three parts separated by dots `.`:
1. Header: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` = `{"alg":"HS256","typ":"JWT"}`
2. Payload: `eyJpc3MiOiJtaWRkbGU ...` = the JSON claims shown below
3. Signature: `RNQKGqhR0gcYqypdcbLqaqPFcAJH1jaR4qXIvnTfadE` = the HMAC signature of the first two parts using the shared secret.

Below is the decoded payload of that token, which is the second part of the JWT:

```json
{
  "iss":"middle-poc",
  "aud":"image-server",
  "sub":"2d54c7ca-c180-44f1-a293-f9b8d111bb0f",
  "preferred_username":"reader",
  "file":"1652989927_0002.jpg",
  "iat":1778071200,
  "nbf":1778071200,
  "exp":1778071260,
  "jti":"4wRkL0IDE9c"
}
```

### How to Inspect a Token

To inspect a live token in this module-based version:

1. Request a token in JSON form from the middle service or generate one manually from the CLI.
2. Use that token in a direct request to `http://localhost:8090/protected/...`.
2. Split it by `.` into three parts.
3. Decode the first part from Base64URL to JSON.
4. Decode the second part from Base64URL to JSON.
5. The third part is the HMAC signature.

### Generate a Test Token in Bash

For manual CLI tests, you can generate a valid PoC file token directly in Bash with `openssl`:

```bash
jwt_b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

make_file_token() {
  local file="${1:?file required}"
  local sub="${2:-cli-test}"
  local user="${3:-cli-test}"
  local secret="${FILE_TOKEN_SECRET:-replace-this-hmac-secret}"
  local iss="${FILE_TOKEN_ISSUER:-middle-poc}"
  local aud="${FILE_TOKEN_AUDIENCE:-image-server}"
  local now exp header payload header_b64 payload_b64 signing_input sig

  now=$(date +%s)
  exp=$((now + 300))

  header='{"alg":"HS256","typ":"JWT"}'
  payload=$(printf '{"iss":"%s","aud":"%s","sub":"%s","preferred_username":"%s","file":"%s","iat":%s,"nbf":%s,"exp":%s,"jti":"manual-cli-test"}' \
    "$iss" "$aud" "$sub" "$user" "$file" "$now" "$now" "$exp")

  header_b64=$(printf '%s' "$header" | jwt_b64url)
  payload_b64=$(printf '%s' "$payload" | jwt_b64url)
  signing_input="${header_b64}.${payload_b64}"

  sig=$(printf '%s' "$signing_input" \
    | openssl dgst -sha256 -binary -hmac "$secret" \
    | jwt_b64url)

  printf '%s.%s\n' "$signing_input" "$sig"
}
```

Example usage:

```bash
TOKEN=$(make_file_token "1652989927_0002.jpg")
curl -H "Authorization: Bearer $TOKEN" \
  -I http://localhost:8090/protected/1652989927_0002.jpg
```

The file name in the JWT must exactly match the requested file path, and the `FILE_TOKEN_SECRET`, `FILE_TOKEN_ISSUER`, and `FILE_TOKEN_AUDIENCE` values must match the running Docker setup.

## Run It

Run the following command in the terminal:
```bash
docker compose up --build
```

Then open:

- `http://localhost:8080` for the middle-service landing page
- `http://localhost:8081/kc/admin/` for the Keycloak admin console
- `http://localhost:8090` for the Apache landing page

The middle-service landing page includes quick links to the protected sample files.

### Services

- `keycloak` on `http://localhost:8081`
- `middle server` on `http://localhost:8080`
- `file-server` on `http://localhost:8090`

### Demo Users

- `reader / reader123`
  - Has the `image-reader` role and can access protected files.
- `blocked / blocked123`
  - Can authenticate in Keycloak, but the middle service denies access.
- `admin / admin`
  - Keycloak administrator account for the local dev environment.

## Notes

- https://www.keycloak.org/securing-apps/mod-auth-openidc                      Keycloak guide for Apache `mod_auth_openidc`
- https://github.com/OpenIDC/mod_auth_openidc                                  Apache module used for browser OIDC on the middle server
- https://github-wiki-see.page/m/OpenIDC/mod_auth_openidc/wiki/OAuth-2.0-Resource-Server
  Resource-server mode reference used on the file server
- https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization               Claims-based authorization reference
