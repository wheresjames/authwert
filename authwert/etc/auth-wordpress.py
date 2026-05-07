#!/usr/bin/env python3

# Add to command line:
# --authparams="mariadb://user:password@localhost/wordpress"
#
# To use a custom table prefix (default is wp_):
# --authparams="mariadb://user:password@localhost/wordpress?prefix=wp_"

import urllib
import mariadb
from passlib.hash import phpass


def init(ctx):
    ctx.dbinf.conn = None
    url = urllib.parse.urlparse(ctx.authparams)

    if url.scheme != 'mariadb':
        raise ValueError(f'Unsupported scheme: {url.scheme!r} (expected mariadb)')

    parts = [p for p in url.path.split('/') if p]
    if not parts:
        raise ValueError('No database name found in --authparams URL path')

    params = urllib.parse.parse_qs(url.query)
    ctx.dbinf.prefix = params.get('prefix', ['wp_'])[0]
    ctx.dbinf.url = url
    ctx.dbinf.database = parts[0]
    ctx.dbinf.conn = mariadb.connect(
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port or 3306,
        database=ctx.dbinf.database,
        connect_timeout=5,
    )


def verify(ctx, uid, secret):
    table = f'{ctx.dbinf.prefix}users'
    query = f'SELECT user_pass FROM {table} WHERE user_login=? OR user_email=?'
    for attempt in range(2):
        try:
            with ctx.dbinf.conn.cursor() as cur:
                cur.execute(query, (uid, uid))
                for (_hash,) in cur:
                    if phpass.verify(secret, _hash):
                        return True
            return False
        except mariadb.OperationalError as e:
            if attempt == 0:
                try:
                    init(ctx)
                except Exception as e2:
                    print(f'Reconnect failed: {e2}')
                    return False
            else:
                print(f'DB error after reconnect: {e}')
                return False
        except Exception as e:
            print(f'Auth error: {e}')
            return False
    return False


def close(ctx):
    conn = getattr(ctx.dbinf, 'conn', None)
    if conn:
        conn.close()
        ctx.dbinf.conn = None
