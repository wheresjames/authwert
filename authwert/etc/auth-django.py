#!/usr/bin/env python3

# Authenticates against a Django auth_user table.
#
# Add to command line:
# --authparams="postgresql://user:password@localhost/mydjango"
# --authparams="mysql://user:password@localhost/mydjango"
# --authparams="mariadb://user:password@localhost/mydjango"
# --authparams="sqlite:////var/www/myproject/db.sqlite3"
#
# Optional query parameters:
#   table     table name; default: auth_user

import urllib.parse
from passlib.hash import django_pbkdf2_sha256, django_bcrypt, django_argon2


_HASHERS = (django_pbkdf2_sha256, django_bcrypt, django_argon2)


def _check_hash(secret, stored):
    for hasher in _HASHERS:
        try:
            if hasher.verify(secret, stored):
                return True
        except Exception:
            continue
    return False


def _connect(ctx):
    url = ctx.dbinf.url
    scheme = url.scheme

    if scheme in ('postgresql', 'postgres'):
        import psycopg2
        ctx.dbinf.conn = psycopg2.connect(
            host=url.hostname,
            port=url.port or 5432,
            user=url.username,
            password=url.password,
            dbname=ctx.dbinf.database,
            connect_timeout=5,
        )
        ctx.dbinf.placeholder = '%s'

    elif scheme in ('mysql', 'mariadb'):
        import mariadb
        ctx.dbinf.conn = mariadb.connect(
            host=url.hostname,
            port=url.port or 3306,
            user=url.username,
            password=url.password,
            database=ctx.dbinf.database,
            connect_timeout=5,
        )
        ctx.dbinf.placeholder = '?'

    elif scheme == 'sqlite':
        import sqlite3
        ctx.dbinf.conn = sqlite3.connect(ctx.dbinf.database, check_same_thread=False)
        ctx.dbinf.placeholder = '?'

    else:
        raise ValueError(f'Unsupported scheme: {scheme!r}')


def init(ctx):
    ctx.dbinf.conn = None
    url = urllib.parse.urlparse(ctx.authparams)
    params = urllib.parse.parse_qs(url.query)

    if url.scheme == 'sqlite':
        ctx.dbinf.database = url.path
    else:
        parts = [p for p in url.path.split('/') if p]
        if not parts:
            raise ValueError('No database name found in --authparams URL path')
        ctx.dbinf.database = parts[0]

    ctx.dbinf.url = url
    ctx.dbinf.table = params.get('table', ['auth_user'])[0]
    _connect(ctx)


def verify(ctx, uid, secret):
    ph = ctx.dbinf.placeholder
    query = f'SELECT password FROM {ctx.dbinf.table} WHERE username={ph} OR email={ph}'
    for attempt in range(2):
        try:
            cur = ctx.dbinf.conn.cursor()
            cur.execute(query, (uid, uid))
            for (stored_hash,) in cur:
                if _check_hash(secret, stored_hash):
                    return True
            return False
        except Exception as e:
            scheme = ctx.dbinf.url.scheme
            is_operational = (
                (scheme in ('mysql', 'mariadb') and 'OperationalError' in type(e).__name__)
                or (scheme in ('postgresql', 'postgres') and 'OperationalError' in type(e).__name__)
            )
            if attempt == 0 and is_operational:
                try:
                    _connect(ctx)
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
