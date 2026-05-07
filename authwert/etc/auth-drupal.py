#!/usr/bin/env python3

# Authenticates against a Drupal 7/8/9/10 database.
#
# Add to command line:
# --authparams="mariadb://user:password@localhost/drupal"
# --authparams="postgresql://user:password@localhost/drupal"
#
# Optional query parameters:
#   table     override the users table; default: users_field_data (D8+) or users (D7)
#   version   7 or 8 (default: 8); selects the default table and name column

import urllib.parse
from passlib.hash import phpass


def _connect(url, database):
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
    else:
        raise ValueError(f'Unsupported scheme: {scheme!r} (expected mariadb or postgresql)')


def init(ctx):
    ctx.dbinf.conn = None
    url = urllib.parse.urlparse(ctx.authparams)
    params = urllib.parse.parse_qs(url.query)
    parts = [p for p in url.path.split('/') if p]
    if not parts:
        raise ValueError('No database name found in --authparams URL path')

    version = params.get('version', ['8'])[0]
    default_table = 'users_field_data' if version != '7' else 'users'
    name_col = 'name'

    ctx.dbinf.url = url
    ctx.dbinf.database = parts[0]
    ctx.dbinf.table = params.get('table', [default_table])[0]
    ctx.dbinf.name_col = name_col

    conn, ph, op_err = _connect(url, ctx.dbinf.database)
    ctx.dbinf.conn = conn
    ctx.dbinf.placeholder = ph
    ctx.dbinf.OperationalError = op_err


def verify(ctx, uid, secret):
    ph = ctx.dbinf.placeholder
    query = f'SELECT pass FROM {ctx.dbinf.table} WHERE {ctx.dbinf.name_col}={ph} OR mail={ph}'
    for attempt in range(2):
        try:
            with ctx.dbinf.conn.cursor() as cur:
                cur.execute(query, (uid, uid))
                for (stored_hash,) in cur:
                    if phpass.verify(secret, stored_hash):
                        return True
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
