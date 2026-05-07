# authwert

A lightweight authentication server designed to work as a forward-auth handler for reverse proxies like nginx. It protects any web application or static site without requiring changes to the application itself.

When a request arrives, your proxy asks authwert whether the visitor is logged in. Authwert checks their cookie, returns `200 OK` if valid or `401 Unauthorized` if not. The proxy then either forwards the request or redirects the browser to the login page.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Install](#install)
- [Quick Start](#quick-start)
- [Authentication Modes](#authentication-modes)
  - [Static User List](#static-user-list)
  - [JWT Tokens](#jwt-tokens)
  - [Custom Auth Plugin](#custom-auth-plugin)
- [Session Expiry](#session-expiry)
- [Nginx Integration](#nginx-integration)
- [Command-Line Reference](#command-line-reference)
- [Custom Auth Plugins](#custom-auth-plugins)
  - [Plugin Interface](#plugin-interface)
  - [WordPress](#wordpress)
  - [htpasswd](#htpasswd)
  - [LDAP / Active Directory](#ldap-active-directory)
  - [Django](#django)
  - [Drupal](#drupal)
  - [Nextcloud / ownCloud](#nextcloud-owncloud)
  - [Ghost](#ghost)
- [Running Tests](#running-tests)
- [Comparison to Similar Projects](#comparison-to-similar-projects)
- [References](#references)

---

<a id="how-it-works"></a>
## How It Works

```
Browser ──► nginx ──► your app
               │
               │  auth_request /auth/verify
               ▼
           authwert
           (port 18401)
```

1. A visitor requests a protected page.
2. nginx makes an internal subrequest to `authwert /auth/verify`, passing the visitor's cookies.
3. authwert validates the session cookie and replies `200` (pass) or `401` (deny).
4. On `401`, nginx redirects the browser to `/auth/login?rd=<original-url>`.
5. The visitor logs in; authwert sets a signed cookie and redirects back to `rd`.
6. All subsequent requests pass step 3 automatically until the session expires.

Two cookie strategies are available:

| Mode | Storage | Statefulness |
|---|---|---|
| **Session tokens** | Server memory (lost on restart) | Stateful — server tracks all sessions |
| **JWT tokens** | Signed cookie only (no server state) | Stateless — verify with public key |

---

<a id="install"></a>
## Install

```bash
pip3 install authwert
```

Or install from source:

```bash
git clone https://github.com/wheresjames/authwert.git
cd authwert
pip3 install .
```

---

<a id="quick-start"></a>
## Quick Start

Run a local test server (no TLS, single user):

```bash
authwert \
    --domain=localhost \
    --cookieid="cdec0879-3f2e-48bc-8ecd-92082cbd0639" \
    --scheme=http \
    --userinf='{"admin": {"password": "secret"}}'
```

Then visit `http://localhost:18401/auth/login` in your browser.

> **Note:** `--cookieid` should be a unique, secret string — it becomes the cookie name. Use a UUID or similar random value. Anyone who knows it can craft a cookie name, so treat it like a secret.

---

<a id="authentication-modes"></a>
## Authentication Modes

<a id="static-user-list"></a>
### Static User List

Credentials are supplied directly on the command line or via a JSON file.

**Inline JSON:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --userinf='{"alice": {"password": "alicepw"}, "bob": {"password": "bobpw"}}'
```

**Wildcard user** — one password for everyone:

```bash
--userinf='{"*": {"password": "sharedpassword"}}'
```

**JSON file:**

```bash
--userinf='/etc/authwert/users.json'
```

`/etc/authwert/users.json`:

```json
{
    "alice": {"password": "alicepw"},
    "bob":   {"password": "bobpw"}
}
```

> **Security note:** Passwords in the static user list are stored in plaintext. Use a dedicated auth plugin (see below) for production deployments where users manage their own credentials.

---

<a id="jwt-tokens"></a>
### JWT Tokens

With a private key, authwert issues signed JWT cookies instead of storing sessions in memory. This is stateless — any authwert instance with the same key can validate tokens, making it suitable for multi-server deployments.

**Generate a private key:**

```bash
openssl genrsa -out /etc/authwert/auth.key 2048
```

**Start authwert with the key:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --prvkey="/etc/authwert/auth.key" \
    --algorithm="RS256" \
    --userinf='/etc/authwert/users.json'
```

The default algorithm is `RS256`. Supported algorithms depend on the installed `pyjwt` version — `RS256`, `RS384`, `RS512`, `ES256`, and others are commonly available.

---

<a id="custom-auth-plugin"></a>
### Custom Auth Plugin

For production use — databases, LDAP, OAuth, etc. — supply a Python plugin file via `--authfile`. See [Custom Auth Plugins](#custom-auth-plugins) below.

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="/etc/authwert/my_auth.py" \
    --authparams="<connection-string-or-config>"
```

To avoid exposing credentials in the process list (`ps aux`) or shell history, prefix `--authparams` with `@` to read the value from a file instead:

```bash
# /etc/authwert/db.conf (chmod 600, owned by the authwert user)
mariadb://wp_user:wp_pass@localhost/wordpress
```

```bash
--authparams="@/etc/authwert/db.conf"
```

---

<a id="session-expiry"></a>
## Session Expiry

Control how long a login lasts:

```bash
# As a number of seconds (6 days = 518400)
--exptime=518400

# As a human-readable string (parsed by dateparser)
--expstr="after 6 days"
--expstr="after 8 hours"
--expstr="after 30 minutes"
```

`--expstr` is used as a fallback when `--exptime` is not set or is out of the allowed range (10 seconds – 90 days). The default is 6 days.

---

<a id="nginx-integration"></a>
## Nginx Integration

Add the following to your nginx site configuration:

```nginx
# ── Protected application ──────────────────────────────────────────────────

server {
    listen 443 ssl;
    server_name example.com;

    # Every request is checked against authwert
    auth_request /auth/verify;
    error_page 401 = @login_redirect;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }

    # ── authwert subrequest endpoint (internal only) ───────────────────────

    location = /auth/verify {
        internal;
        proxy_pass          http://127.0.0.1:18401/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header    Content-Length "";
        proxy_set_header    X-Original-URI $request_uri;
    }

    # ── Login / logout UI (public) ─────────────────────────────────────────

    location /auth/ {
        proxy_pass http://127.0.0.1:18401/auth/;
    }

    # ── Redirect to login page on 401 ─────────────────────────────────────

    location @login_redirect {
        return 302 https://$host/auth/login?rd=$scheme://$host$request_uri;
    }
}
```

**Minimal authwert command for this setup:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --prvkey="/etc/authwert/auth.key" \
    --userinf='/etc/authwert/users.json' \
    --logdir='/var/log/authwert'
```

---

<a id="command-line-reference"></a>
## Command-Line Reference

```
authwert [options]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--version` | | | Print version and exit |
| `--domain` | `-d` | *(required)* | Domain name used for the session cookie |
| `--rootpath` | `-r` | auto | Full URL prefix for the auth endpoints, e.g. `https://example.com/auth` |
| `--addr` | `-a` | `127.0.0.1` | Address to listen on |
| `--port` | `-p` | `18401` | Port to listen on |
| `--scheme` | `-s` | `https` | URL scheme (`http` or `https`) |
| `--cookieid` | `-k` | *(required)* | Cookie name — use a unique secret string |
| `--userinf` | `-u` | | Inline JSON or path to a JSON file containing user credentials |
| `--prvkey` | | | Path to a PEM private key file for signing JWT cookies |
| `--algorithm` | | `RS256` | JWT signing algorithm (requires `--prvkey`) |
| `--exptime` | | | Session lifetime in seconds |
| `--expstr` | | `after 6 days` | Session lifetime as a human-readable string |
| `--authfile` | | | Path to a Python auth plugin (see below) |
| `--authparams` | | | Connection string passed to the auth plugin. Prefix with `@` to read from a file: `--authparams="@/etc/authwert/db.conf"` |
| `--logdir` | `-l` | | Directory for log files |
| `--logfile` | `-L` | | Path to a specific log file |
| `--verbose` | `-V` | | Enable verbose request logging |
| `--serve` | `-S` | | Serve a local directory with login protection (all paths require authentication) |
| `--buildver` | `-b` | | Build version string (informational) |

---

<a id="custom-auth-plugins"></a>
## Custom Auth Plugins

A plugin is a plain Python file with three functions. Supply it with `--authfile` and pass any connection details with `--authparams`.

<a id="plugin-interface"></a>
### Plugin Interface

```python
def init(ctx):
    """Called once at startup. Use ctx.authparams for connection details."""
    pass

def verify(ctx, uid, secret):
    """
    Called on every login attempt.
    Return True to allow, False to deny.
    Must not raise — catch all exceptions and return False.
    """
    return False

def close(ctx):
    """Called on shutdown. Clean up connections."""
    pass
```

`ctx` is the authwert options bag. `ctx.authparams` holds whatever string was passed via `--authparams`.

Using the `!` prefix in `--authfile` resolves the path relative to the authwert package directory:

```bash
--authfile="!/etc/auth-wordpress.py"   # absolute path
--authfile="!auth-wordpress.py"        # bundled example
```

<a id="wordpress"></a>
### WordPress

Bundled at `authwert/etc/auth-wordpress.py`. Authenticates against the `wp_users` table using WordPress's phpass hashing. Users can log in with either their WordPress username or email address.

**Requirements:**

```bash
pip3 install mariadb passlib
```

**Usage:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-wordpress.py" \
    --authparams="mariadb://wp_user:wp_pass@localhost/wordpress"
```

Custom table prefix (default is `wp_`):

```bash
--authparams="mariadb://wp_user:wp_pass@localhost/wordpress?prefix=blog_"
```

---

<a id="htpasswd"></a>
### htpasswd

Bundled at `authwert/etc/auth-htpasswd.py`. Authenticates against an Apache-compatible `.htpasswd` file. Supports all passlib-backed schemes (bcrypt, SHA-1, MD5-crypt). The file is reloaded automatically when it changes on disk, so you can add or remove users without restarting authwert.

**Requirements:**

```bash
pip3 install passlib[bcrypt]
```

**Create an htpasswd file:**

```bash
# bcrypt (recommended)
htpasswd -B -c /etc/authwert/.htpasswd alice
htpasswd -B /etc/authwert/.htpasswd bob
```

**Usage:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-htpasswd.py" \
    --authparams="/etc/authwert/.htpasswd"
```

---

<a id="ldap-active-directory"></a>
### LDAP / Active Directory

Bundled at `authwert/etc/auth-ldap.py`. Searches for the user with a service-account bind, then validates their password with a second bind as that user. Supports both plain LDAP with StartTLS (`ldap://`) and LDAPS (`ldaps://`).

**Requirements:**

```bash
pip3 install ldap3
```

**Usage — OpenLDAP:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-ldap.py" \
    --authparams="ldap://svc_bind:secret@ldap.example.com/dc=example,dc=com"
```

**Usage — Active Directory:**

```bash
--authparams="ldap://svc_bind:secret@dc.corp.local/DC=corp,DC=local?filter=(sAMAccountName%3D{uid})"
```

**Usage — LDAPS:**

```bash
--authparams="ldaps://svc_bind:secret@ldap.example.com/dc=example,dc=com"
```

Optional query parameters:

| Parameter | Default | Description |
|---|---|---|
| `filter` | `(|(uid={uid})(mail={uid}))` | LDAP search filter; `{uid}` is replaced with the sanitised username |

---

<a id="django"></a>
### Django

Bundled at `authwert/etc/auth-django.py`. Authenticates against a Django `auth_user` table. Supports PBKDF2-SHA256, bcrypt, and argon2 password hashing. Works with MariaDB/MySQL, PostgreSQL, and SQLite backends.

**Requirements:**

```bash
pip3 install passlib[bcrypt,argon2]

# Plus the appropriate database driver:
pip3 install mariadb          # MariaDB / MySQL
pip3 install psycopg2-binary  # PostgreSQL
# sqlite3 is included in Python's standard library
```

**Usage — MariaDB/MySQL:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-django.py" \
    --authparams="mariadb://django_user:django_pass@localhost/myproject"
```

**Usage — PostgreSQL:**

```bash
--authparams="postgresql://django_user:django_pass@localhost/myproject"
```

**Usage — SQLite:**

```bash
--authparams="sqlite:////var/www/myproject/db.sqlite3"
```

Optional query parameters:

| Parameter | Default | Description |
|---|---|---|
| `table` | `auth_user` | Table name, if you use a custom user model |

---

<a id="drupal"></a>
### Drupal

Bundled at `authwert/etc/auth-drupal.py`. Authenticates against a Drupal 7/8/9/10 database using phpass hashing. Supports MariaDB/MySQL and PostgreSQL. Users can log in with their Drupal username or email address.

**Requirements:**

```bash
pip3 install passlib

# Plus the appropriate database driver:
pip3 install mariadb          # MariaDB / MySQL
pip3 install psycopg2-binary  # PostgreSQL
```

**Usage:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-drupal.py" \
    --authparams="mariadb://drupal_user:drupal_pass@localhost/drupal"
```

Optional query parameters:

| Parameter | Default | Description |
|---|---|---|
| `version` | `8` | Drupal major version; `7` uses the `users` table, `8`+ uses `users_field_data` |
| `table` | *(derived from version)* | Override the users table name |

---

<a id="nextcloud-owncloud"></a>
### Nextcloud / ownCloud

Bundled at `authwert/etc/auth-nextcloud.py`. Authenticates against a Nextcloud or ownCloud database. Supports current bcrypt hashes as well as the legacy SHA-1 and MD5 formats used by very old installations. Works with MariaDB/MySQL, PostgreSQL, and SQLite backends.

**Requirements:**

```bash
pip3 install passlib[bcrypt]

# Plus the appropriate database driver:
pip3 install mariadb          # MariaDB / MySQL
pip3 install psycopg2-binary  # PostgreSQL
# sqlite3 is included in Python's standard library
```

**Usage — MariaDB/MySQL:**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-nextcloud.py" \
    --authparams="mariadb://nc_user:nc_pass@localhost/nextcloud"
```

**Usage — SQLite:**

```bash
--authparams="sqlite:////var/www/nextcloud/data/owncloud.db"
```

Optional query parameters:

| Parameter | Default | Description |
|---|---|---|
| `prefix` | `oc_` | Table prefix |

---

<a id="ghost"></a>
### Ghost

Bundled at `authwert/etc/auth-ghost.py`. Authenticates Ghost staff users (admin/editor/author roles) against the Ghost `users` table using bcrypt. Only active accounts are accepted. Works with MariaDB/MySQL and SQLite (Ghost's default).

**Requirements:**

```bash
pip3 install passlib[bcrypt]

# Plus the appropriate database driver:
pip3 install mariadb  # MariaDB / MySQL
# sqlite3 is included in Python's standard library
```

**Usage — SQLite (Ghost default):**

```bash
authwert \
    --domain="example.com" \
    --rootpath="https://example.com/auth" \
    --cookieid="<your-secret-cookie-name>" \
    --authfile="!auth-ghost.py" \
    --authparams="sqlite:////var/lib/ghost/content/data/ghost.db"
```

**Usage — MySQL/MariaDB:**

```bash
--authparams="mariadb://ghost_user:ghost_pass@localhost/ghost"
```

Users log in with their Ghost staff email address.

---

<a id="running-tests"></a>
## Running Tests

Install test dependencies:

```bash
pip3 install pytest pytest-asyncio
```

Run the full suite from the project root:

```bash
# All tests
python3 -m pytest

# Verbose (shows each test name)
python3 -m pytest -v

# A single file
python3 -m pytest test/test_auth.py

# A single test class or function
python3 -m pytest test/test_auth.py::TestAuthVerify
python3 -m pytest test/test_auth.py::TestAuthVerify::test_valid_jwt_cookie_returns_200

# Stop on first failure
python3 -m pytest -x
```

The test suite covers configuration parsing, JWT token creation and validation, RSA key and certificate loading, open-redirect safety, the login/logout/verify request handlers, the `--serve` file server including authentication enforcement and path-traversal prevention, and all six bundled auth plugins (WordPress, htpasswd, LDAP, Django, Drupal, Nextcloud, Ghost). Plugin tests mock their third-party dependencies so no database or LDAP server is required to run them.

---

<a id="comparison-to-similar-projects"></a>
## Comparison to Similar Projects

Several tools solve the forward-auth problem in different ways. The right choice depends on where your user identities live and how much infrastructure you want to run.

---

### nginx HTTP basic auth

The built-in `auth_basic` module in nginx validates credentials against a static `htpasswd` file with no additional process required.

**Key differences:**

- nginx basic auth runs inside the nginx worker — there is no separate process, no session state, and no cookie. Every request re-sends credentials as a Base64-encoded `Authorization` header.
- The browser's built-in credential dialog is used; there is no custom login page and no way to add branding, error messages, or a logout button.
- Credentials are scoped to the browser session. There is no expiry control, and logging out requires the browser to be closed or the stored credentials cleared manually.
- authwert issues a signed cookie (JWT or server-side session token) after a single form-based login, so subsequent requests carry no credentials at all — just the cookie.

**Choose nginx basic auth if** you need the simplest possible protection for an internal tool, have a small fixed set of users, and do not need session cookies or a custom login page.

**Choose authwert if** you need a real login page, persistent sessions or JWT tokens, configurable expiry, or credentials validated against an existing database rather than a manually maintained file.

---

### Authelia

[Authelia](https://github.com/authelia/authelia) is the closest project in deployment model — it runs as a sidecar and integrates with nginx, Traefik, Caddy, and HAProxy via the same `auth_request` mechanism. It adds multi-factor authentication (TOTP, push), a full user management portal, and a rich YAML-driven policy engine.

**Key differences:**

- Authelia requires Postgres (or another SQL database) and Redis as backing services. authwert has no external service dependencies — it runs as a single process.
- Authelia is configured entirely through a YAML file with a dedicated schema; authwert is configured through command-line flags and a single Python plugin file.
- Authelia supports TOTP, WebAuthn, and push-based MFA. authwert has no MFA support.
- Authelia validates users against LDAP or a built-in file backend. authwert validates users against any source expressible in a Python plugin — including existing application databases that Authelia cannot reach without an LDAP facade.
- Authelia has significantly more active development, a larger community, and more documentation.

**Choose Authelia if** you need MFA, per-route access rules, an audit log, or self-service password reset. It is the natural upgrade path when authwert's feature set is outgrown.

**Choose authwert if** you want to validate credentials against an existing application database (WordPress, Django, Nextcloud, etc.) without standing up additional services, or if MFA and policy rules are not required.

---

### oauth2-proxy

[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) sits in front of your application and delegates all authentication to an upstream OAuth2 or OIDC provider (Google, GitHub, Azure AD, Okta, etc.).

**Key differences:**

- oauth2-proxy does not manage credentials at all — it redirects to an external identity provider and accepts the resulting token. authwert validates credentials directly against a local source.
- oauth2-proxy requires an OAuth2 client ID and secret registered with a provider. authwert requires no external accounts or registrations.
- oauth2-proxy can restrict access by email domain, group membership, or individual email address as reported by the provider. authwert's access control is limited to whether the credential check succeeds.
- oauth2-proxy is written in Go and ships as a single static binary with no runtime dependencies. authwert requires a Python environment.

**Choose oauth2-proxy if** your organisation already has a central identity provider and you want users to authenticate with their existing corporate or social credentials without managing passwords yourself.

**Choose authwert if** you need to authenticate against a local database with no dependency on an external identity provider, or if you are protecting a self-hosted application whose user accounts are already stored in its own database.

---

### Vouch Proxy

[Vouch Proxy](https://github.com/vouch/vouch-proxy) works similarly to oauth2-proxy — it validates OAuth2/OIDC tokens and issues its own session cookie for nginx. It is lighter than oauth2-proxy and easier to configure for simple single-provider setups.

**Key differences:**

- Like oauth2-proxy, Vouch requires an upstream OAuth2/OIDC provider and cannot authenticate against a local database.
- Vouch issues its own short-lived JWT after the OAuth2 handshake completes, which nginx then validates on subsequent requests. authwert issues its JWT directly after a username/password form submission.
- Vouch is more tightly coupled to nginx; oauth2-proxy and Authelia support a wider range of reverse proxies.
- Vouch is written in Go; authwert is written in Python.

**Choose Vouch if** you want OAuth2/OIDC with a smaller footprint than oauth2-proxy and your proxy is nginx.

**Choose authwert if** your users authenticate with a username and password stored in an application database rather than an OAuth2 provider.

---

### Pomerium

[Pomerium](https://github.com/pomerium/pomerium) is an identity-aware access proxy that handles both routing and authentication in a single component. It supports OIDC, fine-grained authorisation policies, and mTLS between services.

**Key differences:**

- Pomerium replaces your reverse proxy rather than sitting behind it. authwert is a sidecar that works alongside any existing proxy via `auth_request`.
- Pomerium enforces access policy at the routing layer, supporting conditions based on user identity, group, device posture, and time. authwert's only access control decision is pass or fail based on the credential check.
- Pomerium requires an OIDC identity provider. authwert has no such dependency.
- Pomerium supports service-to-service authentication with mTLS. authwert handles only browser-facing authentication.

**Choose Pomerium if** you need a zero-trust network access layer with per-route policy, device identity, or service-to-service authentication.

**Choose authwert if** you have an existing reverse proxy and only need to add a login gate to it without replacing your routing layer.

---

### Summary

| | authwert | nginx basic auth | Authelia | oauth2-proxy | Vouch Proxy | Pomerium |
|---|---|---|---|---|---|---|
| Login page | Yes | Browser dialog | Yes | Redirect to provider | Redirect to provider | Redirect to provider |
| Session / JWT cookies | Yes | No | Yes | Yes | Yes | Yes |
| MFA / 2FA | No | No | Yes | Delegated to provider | Delegated to provider | Delegated to provider |
| Auth against existing DB | Yes (plugins) | No | No | No | No | No |
| OAuth2 / OIDC | No | No | Yes | Yes | Yes | Yes |
| Custom auth backend | Yes (Python) | No | No | No | No | No |
| Proxy support | Any | nginx, Apache | nginx, Traefik, Caddy, HAProxy | Most | nginx, Traefik, Caddy | Replaces proxy |
| Extra services required | None | None | Postgres + Redis | None | None | None |
| Relative complexity | Low | Minimal | Medium–High | Low–Medium | Low | Medium–High |

---

<a id="references"></a>
## References

- [GitHub repository](https://github.com/wheresjames/authwert)
- [Report an issue](https://github.com/wheresjames/authwert/issues)
- [nginx `auth_request` module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
- [PyJWT](https://pyjwt.readthedocs.io/)
- [dateparser](https://dateparser.readthedocs.io/)
