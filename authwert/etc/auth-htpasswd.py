#!/usr/bin/env python3

# Add to command line:
# --authparams="/etc/authwert/.htpasswd"

from passlib.apache import HtpasswdFile


def init(ctx):
    ctx.dbinf.path = ctx.authparams.strip()
    ctx.dbinf.ht = HtpasswdFile(ctx.dbinf.path)


def verify(ctx, uid, secret):
    try:
        ctx.dbinf.ht.load_if_changed()
        return ctx.dbinf.ht.check_password(uid, secret) is True
    except Exception as e:
        print(f'Auth error: {e}')
        return False


def close(ctx):
    pass
