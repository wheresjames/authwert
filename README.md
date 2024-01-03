
# authwert

Simple Authenticator

```
usage: authwert [-h] [--domain DOMAIN] [--rootpath ROOTPATH] [--buildver BUILDVER] 
                [--addr ADDR] [--port PORT] [--logdir LOGDIR] [--logfile LOGFILE] 
                [--verbose] [--debug DEBUG] [--cookieid COOKIEID] [--userinf USERINF] 
                [--scheme SCHEME] [--authfile AUTHFILE] [--authparams AUTHPARAMS] 
                [--prvkey PRVKEY] [--exptime EXPTIME] [--expstr EXPSTR] 
                [--userlist USERLIST] [--algorithm ALGORITHM]

options:
  -h, --help            show this help message and exit
  --domain DOMAIN, -d DOMAIN
                        Domain name
  --rootpath ROOTPATH, -r ROOTPATH
                        Root Path
  --buildver BUILDVER, -b BUILDVER
                        Build Version
  --addr ADDR, -a ADDR  Server address
  --port PORT, -p PORT  Server port
  --logdir LOGDIR, -l LOGDIR
                        Default log directory
  --logfile LOGFILE, -L LOGFILE
                        Default log directory
  --verbose, -V         Verbose mode
  --debug DEBUG, -D DEBUG
                        Debug site
  --cookieid COOKIEID, -k COOKIEID
                        cookieid
  --userinf USERINF, -u USERINF
                        User information
  --scheme SCHEME, -s SCHEME
                        Network Scheme
  --authfile AUTHFILE   Python authorize file
  --authparams AUTHPARAMS
                        Parameters to pass to auth file
  --prvkey PRVKEY       File containing private key to sign JWT tokens
  --exptime EXPTIME     Login expire time in seconds
  --expstr EXPSTR       Login expire time as string
  --userlist USERLIST   Set to always maintain an internal list of active users
  --algorithm ALGORITHM
                        Private key algorithm
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

