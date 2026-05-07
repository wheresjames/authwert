#!/usr/bin/env python3

# Authenticates against a Nextcloud / ownCloud database.
#
# Add to command line:
# --authparams="mariadb://user:password@localhost/nextcloud"
# --authparams="postgresql://user:password@localhost/nextcloud"
# --authparams="sqlite:////var/www/nextcloud/data/owncloud.db"
#
# Optional query parameters:
#   prefix    table prefix; default: oc_

import urllib.parse
import hashlib
import hmac

# Nextcloud uses bcrypt for new accounts and legacy SHA-1/MD5 for older ones.
from passlib.hash import bcrypt as passlib_bcrypt


def _check_password(secret, stored):
    # bcrypt (current default)
    if stored.startswith('$2y$') or stored.startswith('$2a$') or stored.startswith('$2b$'):
        normalized = stored.replace('$2y$', '$2b$', 1)
        try:
            return passlib_bcrypt.verify(secret, normalized)
        except Exception:
            return False
    # SHA-1 hex (very old accounts)
    if len(stored) == 40 and all(c in '0123456789abcdef' for c in stored.lower()):
        return hmac.compare_digest(hashlib.sha1(secret.encode()).hexdigest(), stored.lower())
    # MD5 hex
    if len(stored) == 32 and all(c in '0123456789abcdef' for c in stored.lower()):
        return hmac.compare_digest(hashlib.md5(secret.encode()).hexdigest(), stored.lower())
    return False


def _connect(url, database, prefix):
    scheme = url.scheme
    if scheme in ('mariadb', 'mysql'):
        import mariadb
        conn = mariadb.connect(
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port or 3306,
            database=database,
            connect_timeout=5,
        )
        return conn, '?', mariadb.OperationalError
    elif scheme in ('postgresql', 'postgres'):
        import psycopg2
        conn = psycopg2.connect(
            host=url.hostname,
            port=url.port or 5432,
            user=url.username,
            password=url.password,
            dbname=database,
            connect_timeout=5,
        )
        return conn, '%s', psycopg2.OperationalError
    elif scheme == 'sqlite':
        import sqlite3
        conn = sqlite3.connect(database, check_same_thread=False)
        return conn, '?', sqlite3.OperationalError
    else:
        raise ValueError(f'Unsupported scheme: {scheme!r}')


def init(ctx):
    ctx.dbinf.conn = None
    url = urllib.parse.urlparse(ctx.authparams)
    params = urllib.parse.parse_qs(url.query)

    if url.scheme == 'sqlite':
        database = url.path
    else:
        parts = [p for p in url.path.split('/') if p]
        if not parts:
            raise ValueError('No database name found in --authparams URL path')
        database = parts[0]

    prefix = params.get('prefix', ['oc_'])[0]
    ctx.dbinf.url = url
    ctx.dbinf.database = database
    ctx.dbinf.table = f'{prefix}users'

    conn, ph, op_err = _connect(url, database, prefix)
    ctx.dbinf.conn = conn
    ctx.dbinf.placeholder = ph
    ctx.dbinf.OperationalError = op_err


def verify(ctx, uid, secret):
    ph = ctx.dbinf.placeholder
    query = f'SELECT password FROM {ctx.dbinf.table} WHERE uid={ph}'
    for attempt in range(2):
        try:
            cur = ctx.dbinf.conn.cursor()
            cur.execute(query, (uid,))
            for (stored_hash,) in cur:
                if _check_password(secret, stored_hash):
                    return True
            return False
        except Exception as e:
            if attempt == 0 and isinstance(e, ctx.dbinf.OperationalError):
                try:
                    conn, ph, op_err = _connect(ctx.dbinf.url, ctx.dbinf.database, '')
                    ctx.dbinf.conn = conn
                except Exception as e2:
                    print(f'Reconnect failed: {e2}')
                    return False
            else:
                print(f'Auth error: {e}')
                return False
    return False


def close(ctx):
    conn = getattr(ctx.dbinf, 'conn', None)
    if conn:
        conn.close()
        ctx.dbinf.conn = None
