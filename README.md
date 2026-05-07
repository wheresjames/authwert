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
  - [WordPress Example](#wordpress-example)
- [Running Tests](#running-tests)
- [References](#references)

---

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

## Authentication Modes

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

---

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
| `--authparams` | | | Arbitrary string passed to the auth plugin (e.g. a connection URL) |
| `--logdir` | `-l` | | Directory for log files |
| `--logfile` | `-L` | | Path to a specific log file |
| `--verbose` | `-V` | | Enable verbose request logging |
| `--debug` | `-D` | | Serve a local directory for testing (exposes files at `/debug/`) |
| `--buildver` | `-b` | | Build version string (informational) |

---

## Custom Auth Plugins

A plugin is a plain Python file with three functions. Supply it with `--authfile` and pass any connection details with `--authparams`.

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
--authfile="!/etc/auth-example-wordpress.py"   # absolute path
--authfile="!auth-wordpress.py"                 # bundled example
```

### WordPress Example

A ready-made plugin for WordPress is bundled at `authwert/etc/auth-wordpress.py`. It authenticates against the `wp_users` table using WordPress's phpass hashing.

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

Users can log in with either their WordPress username or their email address.

---

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

The test suite covers configuration parsing, JWT token creation and validation, RSA key and certificate loading, open-redirect safety, the login/logout/verify request handlers, and the debug file server including path-traversal prevention.

---

## References

- [GitHub repository](https://github.com/wheresjames/authwert)
- [Report an issue](https://github.com/wheresjames/authwert/issues)
- [nginx `auth_request` module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
- [PyJWT](https://pyjwt.readthedocs.io/)
- [dateparser](https://dateparser.readthedocs.io/)
