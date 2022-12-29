#!/usr/bin/env python3

# Add to command line
# --authparams="mariadb://user:password@localhost/wordpress"

import urllib
import mariadb

def init(ctx):

    # Parse connection url
    ctx.dbinf.url = urllib.parse.urlparse(ctx.authparams)
    if 'mariadb' == ctx.dbinf.url.scheme:
        ctx.dbinf.table = [e for e in ctx.dbinf.url.path.split('/') if e]

        # Connect to database
        ctx.dbinf.conn = mariadb.connect( user=ctx.dbinf.url.username,
                                          password=ctx.dbinf.url.password,
                                          host=ctx.dbinf.url.hostname,
                                          port=ctx.dbinf.url.port if ctx.dbinf.url.port else 3306,
                                          database=ctx.dbinf.table[0]
                                        )

def verify(ctx, uid, secret):
    try:
        from passlib.hash import phpass
        cur = ctx.dbinf.conn.cursor()
        cur.execute("SELECT ID,user_pass FROM wp_users WHERE user_login=? OR user_email=?", (uid, uid))
        for _id,_hash in cur:
            if phpass.verify(secret, _hash):
                return True
        return False
    except Exception as e:
        print(e)
        init(ctx)

def close(ctx):
    if ctx.dbinf and ctx.dbinf.conn:
        ctx.dbinf.conn.close()
        del ctx.dbinf.conn
