# Keycloak to Middle Service to Apache File Server PoC

This repository contains a small Docker Compose proof of concept for this flow:

1. Keycloak authenticates the user with OpenID Connect.
2. A PHP middle service receives the login result and applies a simple policy check.
3. The middle service mints a short-lived HMAC JWT for one file.
4. The Apache-based file server validates that token before streaming the file.
5. If the token is missing or invalid, Apache redirects the browser to an error page.

### Overview

- The PHP middle service is both the landing page and the policy decision point.
- The policy is only a Keycloak role check.
- The file token is a shared-secret HMAC JWT instead of a full external PDP policy artifact.
- Apache validates the token through a small PHP gate instead of a dedicated Apache auth module.

## How the PoC Works

The current Proof of Concept:

1. Keycloak authenticates the human user for the middle service.
2. The middle service converts that authenticated user into a short-lived file token that the Apache file server can validate on its own.

### Keycloak to Middle Service

The browser carries the login flow:

1. The user opens the middle server on `http://localhost:8080`.
2. The middle service sends the browser to the Keycloak authorization endpoint.
3. After login, Keycloak redirects the browser back to `/callback` on the middle service with an authorization `code` and the original `state`.
4. The middle service validates that `state` against the PHP session.
5. The middle service then performs a backend call from the container to Keycloak's internal token endpoint on `http://keycloak:8080/.../token`.
6. Keycloak returns the OIDC token response.
7. The middle service reads:
   - identity information from the `id_token`
   - realm roles from the `access_token`
8. The middle service stores a normalized user record in the PHP session.

Important functions for this part:

- `route_request()` in `middle-server/public/index.php`
  - Dispatches `/login` and `/callback`
- `handle_login()` in `middle-server/public/index.php`
  - Creates the OIDC `state` value and redirects the browser to Keycloak
- `handle_callback()` in `middle-server/public/index.php`
  - Validates the callback, exchanges the code for tokens, and stores the user session
- `http_post_form_json()` in `middle-server/public/index.php`
  - Makes the backend token request to Keycloak
- `browser_oidc_endpoint()` and `internal_oidc_endpoint()` in `middle-server/public/index.php`
  - Separate browser-facing URLs from container-internal URLs

### Middle Service to File Server

When the user requests a file, the middle service becomes the simplified policy decision point:

1. The user opens a protected file url.
2. The browser requests `/request-file/<name>` from the middle service.
3. The middle service checks:
   - a valid browser session exists
   - the requested file really exists
   - the resolved file path stays inside the mounted file directory
   - the user has the required Keycloak realm role, currently `image-reader`
4. If the user is allowed, the middle service creates a short-lived HS256 JWT that is valid only for that exact file.
5. The middle service redirects the browser to:
   - `http://localhost:8090/protected/<file>?token=<jwt>`

Important functions for this part:

- `handle_request_file()` in `middle-server/public/index.php`
  - Applies policy and performs the redirect to the file server
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

Apache routes `/protected/<file>` into `serve.php`, which performs the validation in stages:

1. Read the requested file path and the `token` query parameter.
2. Validate the JWT structure and the HS256 signature.
3. Validate the claims:
   - expected issuer
   - expected audience
   - expiry time
   - not-before time
   - exact file binding through the `file` claim
4. Resolve the final on-disk path and ensure it still points inside `/data/files`.
5. If all checks pass, stream the file.
6. If any check fails, redirect to `/error.html`.

Important functions for this part:

- `verify_hs256_jwt()` in `file-server/public/serve.php`
  - Verifies JWT structure and signature
- `base64url_decode_string()` in `file-server/public/serve.php`
  - Decodes JWT segments
- `redirect_error()` in `file-server/public/serve.php`
  - Stops invalid requests and redirects to the error page

### Example Token

That is an example url: `http://localhost:8090/protected/1652989927_0002.jpg?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtaWRkbGUtcG9jIiwiYXVkIjoiaW1hZ2Utc2VydmVyIiwic3ViIjoiMmQ1NGM3Y2EtYzE4MC00NGYxLWEyOTMtZjliOGQxMTFiYjBmIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicmVhZGVyIiwiZmlsZSI6IjE2NTI5ODk5MjdfMDAwMi5qcGciLCJpYXQiOjE3NzgwNjg0NTUsIm5iZiI6MTc3ODA2ODQ1NSwiZXhwIjoxNzc4MDY4NTE1LCJqdGkiOiI0d1JrTDBJREU5YyJ9.RNQKGqhR0gcYqypdcbLqaqPFcAJH1jaR4qXIvnTfadE`


The actual token sent to the file server is the part after `token=`, which is a compact JWT string:

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

To inspect a live token in the browser:

1. Open a protected file url and copy the `token=...` query parameter on the request of the redirected URL `http://localhost:8090/protected/...`.
2. Split it by `.` into three parts.
3. Decode the first part from Base64URL to JSON.
4. Decode the second part from Base64URL to JSON.
5. The third part is the HMAC signature.

## Run It

Run the following command in the terminal:
```bash
docker compose up --build
```

Then open:

- `http://localhost:8080` for the middle-service landing page
- `http://localhost:8081/admin/` for the Keycloak admin console
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

- https://www.keycloak.org/securing-apps/oidc-layers          Keycloak OIDC docs
- https://openid.net/specs/openid-connect-core-1_0-18.html    OIDC spec
- https://github.com/jumbojett/OpenID-Connect-PHP             PHP implementation of OIDC client flows, used for the middle service login
- https://github.com/googleapis/php-jwt                       PHP library for creating and verifying JWTs, used for the file token implementation