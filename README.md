
# authwert

Simple Authenticator

```
usage: authwert [-h] [--domain DOMAIN] [--rootpath ROOTPATH]
                [--addr ADDR] [--port PORT]
                [--logdir LOGDIR] [--logfile LOGFILE] [--verbose]
                [--debug DEBUG] [--cookieid COOKIEID]
                [--userinf USERINF] [--scheme SCHEME]
                [--authfile AUTHFILE] [--authparams AUTHPARAMS]

options:
  -h, --help            Show this help message and exit
  --domain DOMAIN, -d DOMAIN
                        Domain name: mydomain.com
  --rootpath ROOTPATH, -r ROOTPATH
                        Root web path: http://mydomain.com/where/is/auth
  --addr ADDR, -a ADDR  Address to bind to, default is 127.0.0.1
  --port PORT, -p PORT  Port to bind to, default is 18401
  --logdir LOGDIR, -l LOGDIR
                        Default log directory
  --logfile LOGFILE, -L LOGFILE
                        Default log directory
  --verbose, -V         Verbose mode
  --debug DEBUG, -D DEBUG
                        Debug site, /path/to/local/site/files
  --cookieid COOKIEID, -k COOKIEID
                        The cookie name/id to use
  --userinf USERINF, -u USERINF
                        User login info, can be a json string or a file path.
  --scheme SCHEME, -s SCHEME
                        Network Scheme, http or https
  --authfile AUTHFILE   Python file containing authentication funtions.
                        Start with ! to reference authwert install path
  --authparams AUTHPARAMS
                        String to pass to auth file
```

---------------------------------------------------------------------
## Table of contents

* [Install](#install)
* [Examples](#examples)
* [References](#references)

&nbsp;

---------------------------------------------------------------------
## Install

    $ pip3 install authwert

&nbsp;


---------------------------------------------------------------------
## Examples

Local test
```
    authwert \
        --domain=localhost \
        --cookieid="cdec0879-3f2e-48bc-8ecd-92082cbd0639" \
        --scheme=http \
        --userinf='{"admin" : {"password": "secret"}}'
```

Static user list (please don't deploy this)
```
    authwert \
        --domain="<domain-for-cookie>" \
        --rootpath="https://<domain-name>/auth" \
        --cookieid="cdec0879-3f2e-48bc-8ecd-92082cbd0639" \
        --userinf='{"admin" : {"password": "secretAdminPassword"}}'

    # OR

    authwert \
        --domain="<domain-for-cookie>" \
        --rootpath="https://<domain-name>/auth" \
        --cookieid="cdec0879-3f2e-48bc-8ecd-92082cbd0639" \
        --userinf='/path/to/json/userlist'

```

Wordpress integration
```
    authwert \
        --domain="<domain-for-cookie>" \
        --rootpath="https://<domain-name>/auth" \
        --cookieid="cdec0879-3f2e-48bc-8ecd-92082cbd0639" \
        --authfile="!/etc/auth-example-wordpress.py" \
        --authparams="mariadb://user:pass@localhost/wordpress"
```

&nbsp;


---------------------------------------------------------------------
## References

- Python
    - https://www.python.org/

- pip
    - https://pip.pypa.io/en/stable/

