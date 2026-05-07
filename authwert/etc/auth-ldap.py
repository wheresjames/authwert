#!/usr/bin/env python3

# Add to command line:
# --authparams="ldap://binddn:password@ldap.example.com/dc=example,dc=com"
#
# Optional query parameters:
#   filter    LDAP search filter template; {uid} is replaced with the username
#             default: (|(uid={uid})(mail={uid}))
#   attr      attribute to bind as; default: dn (bind by full DN)
#
# Active Directory example:
# --authparams="ldap://svc_auth:secret@dc.corp.local/DC=corp,DC=local?filter=(sAMAccountName%3D{uid})"

import urllib.parse
import ldap3
from ldap3.core.exceptions import LDAPException


def init(ctx):
    url = urllib.parse.urlparse(ctx.authparams)
    if url.scheme not in ('ldap', 'ldaps'):
        raise ValueError(f'Unsupported scheme: {url.scheme!r} (expected ldap or ldaps)')

    parts = [p for p in url.path.split('/') if p]
    if not parts:
        raise ValueError('No base DN found in --authparams URL path')

    params = urllib.parse.parse_qs(url.query)
    ctx.dbinf.url = url
    ctx.dbinf.base_dn = parts[0]
    ctx.dbinf.bind_dn = urllib.parse.unquote(url.username or '')
    ctx.dbinf.bind_pw = urllib.parse.unquote(url.password or '')
    ctx.dbinf.filter_tmpl = params.get('filter', ['(|(uid={uid})(mail={uid}))'])[0]
    ctx.dbinf.use_ssl = (url.scheme == 'ldaps')
    port = url.port or (636 if ctx.dbinf.use_ssl else 389)
    ctx.dbinf.server = ldap3.Server(
        url.hostname,
        port=port,
        use_ssl=ctx.dbinf.use_ssl,
        get_info=ldap3.NONE,
    )


def verify(ctx, uid, secret):
    try:
        safe_uid = uid.replace('\\', '').replace('*', '').replace('(', '').replace(')', '').replace('\x00', '')
        search_filter = ctx.dbinf.filter_tmpl.replace('{uid}', safe_uid)

        with ldap3.Connection(
            ctx.dbinf.server,
            user=ctx.dbinf.bind_dn,
            password=ctx.dbinf.bind_pw,
            auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND if not ctx.dbinf.use_ssl else ldap3.AUTO_BIND_NO_TLS,
        ) as conn:
            conn.search(ctx.dbinf.base_dn, search_filter, attributes=['dn'])
            entries = conn.entries
            if not entries:
                return False

        for entry in entries:
            entry_dn = entry.entry_dn
            try:
                with ldap3.Connection(
                    ctx.dbinf.server,
                    user=entry_dn,
                    password=secret,
                    auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND if not ctx.dbinf.use_ssl else ldap3.AUTO_BIND_NO_TLS,
                ):
                    return True
            except LDAPException:
                continue

        return False
    except Exception as e:
        print(f'Auth error: {e}')
        return False


def close(ctx):
    pass
