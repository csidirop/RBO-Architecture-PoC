# Notes

## Apache
### Directory, Location and LocationMatch

#### Directory

`<Directory ...>` matches filesystem paths on the server.

Example:

```apache
<Directory /var/www/html/public>
    Options -Indexes
    AllowOverride None
    Require all granted
    FallbackResource /index.php
</Directory>
```

This means: for files physically located under `/var/www/html/public`, apply these rules. It is about the local disk path inside the container, not the URL. It is useful for file permissions, directory listing rules, `.htaccess` behavior, and fallback routing.

#### Location and LocationMatch

`<Location ...>` matches URL paths.

Example:

```apache
<Location "/login">
    AuthType openid-connect
    Require valid-user
</Location>
```

This means: for requests whose URL path is `/login`, apply these rules. It does not matter whether `/login` exists as a real file. It is useful for routes, auth gates, API paths, and virtual endpoints.

`<LocationMatch ...>` is like `<Location>`, but with a regular expression.

Example:

```apache
<LocationMatch "^/request-file/">
    AuthType openid-connect
    Require valid-user
</LocationMatch>
```

This means: for every URL path starting with `/request-file/`, require a logged-in user. For example, `/request-file/protected/foo.jpg` matches.

Short version:

```text
Directory      -> filesystem path
Location       -> URL path
LocationMatch  -> regex URL path
```

### Proxy Directives

#### ProxyPreserveHost

`ProxyPreserveHost On` tells Apache to forward the original browser `Host` header to the backend.

If the browser calls:

```text
http://localhost:8080/file-proxy/foo.jpg
```

Apache proxies internally to `file-server`, but keeps:

```http
Host: localhost:8080
```

instead of changing it to:

```http
Host: file-server
```

This matters when the backend builds absolute URLs, checks hostnames, or logs the public host.

#### ProxyPassMatch

`ProxyPassMatch` forwards matching URL paths to another server using a regular expression.

Example:

```apache
ProxyPassMatch "^/file-proxy/(.+)$" "http://file-server/protected/$1"
```

The `(.+)` captures the rest of the path, and `$1` inserts it into the backend URL.

For example:

```text
/file-proxy/foo.jpg
```

is forwarded inside Docker as:

```text
http://file-server/protected/foo.jpg
```

##### ProxyPassReverse

`ProxyPassReverse` rewrites redirects coming back from the backend.

Example:

```apache
ProxyPassReverse "/file-proxy/" "http://file-server/protected/"
```

If the file server responds with:

```http
Location: http://file-server/protected/foo.jpg
```

Apache can rewrite it so the browser sees the public-facing route instead:

```http
Location: /file-proxy/foo.jpg
```

Without `ProxyPassReverse`, the browser might be redirected to an internal Docker hostname like `file-server`, which it cannot resolve.

### PoC Flow

In this PoC, the middle server acts as the browser-facing gateway:

```text
Browser -> localhost:8080/file-proxy/...
Middle Apache -> http://file-server/protected/...
Browser still sees -> localhost:8080/file-proxy/...
```

The file server stays behind the middle server for protected files. The browser sees the middle-server URL, while Apache performs the internal proxy request to the file server.
