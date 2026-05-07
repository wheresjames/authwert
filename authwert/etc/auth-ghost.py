#!/usr/bin/env python3

# Authenticates against a Ghost blog database.
#
# Add to command line:
# --authparams="mysql://user:password@localhost/ghost"
# --authparams="mariadb://user:password@localhost/ghost"
# --authparams="sqlite:////var/lib/ghost/content/data/ghost.db"
#
# Ghost stores passwords as bcrypt hashes in the users table.

import urllib.parse
from passlib.hash import bcrypt as passlib_bcrypt


def _normalize_bcrypt(stored):
    return stored.replace('$2y$', '$2b$', 1)


def _connect(url, database):
    scheme = url.scheme
    if scheme in ('mysql', 'mariadb'):
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
    elif scheme == 'sqlite':
        import sqlite3
        conn = sqlite3.connect(database, check_same_thread=False)
        return conn, '?', sqlite3.OperationalError
    else:
        raise ValueError(f'Unsupported scheme: {scheme!r} (expected mysql, mariadb, or sqlite)')


def init(ctx):
    ctx.dbinf.conn = None
    url = urllib.parse.urlparse(ctx.authparams)

    if url.scheme == 'sqlite':
        database = url.path
    else:
        parts = [p for p in url.path.split('/') if p]
        if not parts:
            raise ValueError('No database name found in --authparams URL path')
        database = parts[0]

    ctx.dbinf.url = url
    ctx.dbinf.database = database

    conn, ph, op_err = _connect(url, database)
    ctx.dbinf.conn = conn
    ctx.dbinf.placeholder = ph
    ctx.dbinf.OperationalError = op_err


def verify(ctx, uid, secret):
    ph = ctx.dbinf.placeholder
    query = f'SELECT password FROM users WHERE email={ph} AND status="active"'
    for attempt in range(2):
        try:
            cur = ctx.dbinf.conn.cursor()
            cur.execute(query, (uid,))
            for (stored_hash,) in cur:
                try:
                    if passlib_bcrypt.verify(secret, _normalize_bcrypt(stored_hash)):
                        return True
                except Exception:
                    continue
            return False
        except Exception as e:
            if attempt == 0 and isinstance(e, ctx.dbinf.OperationalError):
                try:
                    conn, ph, op_err = _connect(ctx.dbinf.url, ctx.dbinf.database)
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
