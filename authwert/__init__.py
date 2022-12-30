
import os
import ssl
import jwt
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sparen
Log = sparen.log

def loadConfig(fname):
    globals()["__info__"] = {}
    with open(fname) as f:
        lines = f.readlines()
        for line in lines:
            parts = line.strip().replace("\t", " ").split(" ")
            k = parts.pop(0).strip()
            if '#' != k[0]:
                globals()["__%s__"%k] = " ".join(parts).strip()
                globals()["__info__"][k] = " ".join(parts).strip()

def libPath(p):
    return os.path.join(os.path.dirname(__file__), p) if p else os.path.dirname(__file__)

loadConfig(libPath('PROJECT.txt'))


def createSessionToken(claims, opts):
    if 'prvpem' not in opts:
        return None
    return jwt.encode(claims, opts['prvpem'], algorithm="RS256")


def getSesionInfo(token, opts):

    sid = ''
    unv = {}
    dec = {}

    # JWT?
    if 'pubpem' in opts:
        try:
            unv = jwt.decode(token, options={"verify_signature": False})
            dec = jwt.decode(token, opts['pubpem'], algorithms=["RS256"])
            return dec
        except jwt.ExpiredSignatureError:
            Log(f'Expired: {unv} {dec}')
            return None
        except jwt.InvalidSignatureError:
            Log(f'Invalid signature: {unv} {dec}')
            return None
        except Exception as e:
            Log(e)
            return None

    # Session id
    elif 'sessions' in opts:
        if token in opts['sessions']:
            si = opts['sessions'][token]
            if 'exp' in si:
                t = time.time()
                exp = float(si['exp'])

                # Check expire time
                if exp < t:
                    return None

                return si

    return None

''' Reads private key file and creates public key

    @param [in] fname   - Path to private key file
    @param [in] opts    - Options

    @return     - Returns the private and public key in
                  opts['prvpem'] and opts['pubpem'] respectively
'''
def readPrivateKey(fname, opts):
    # Read the private key
    if not os.path.isfile(fname):
        return False

    with open(fname) as f:
        opts['prvpem'] = f.read()

    if 'prvpem' not in opts:
        raise Exception(f'Failed to read private key from : {_p.prvkey}')

    pkey = serialization.load_pem_private_key(opts['prvpem'].encode(), None, default_backend())
    opts['pubpem'] = pkey.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf8')

    if not opts['pubpem']:
        raise Exception(f'Failed to derive public key from : {_p.prvkey}')

    return True


''' Creates public key from cert file

    @param [in] fname   - Path to cert file
    @param [in] opts    - Options

    @return     - Returns the public key in opts['pubpem']
'''
def readCert(fname, opts):

    crtpem = None
    with open(crtfile) as f:
        crtpem = f.read()
    if not crtpem:
        return False

    # Get public key from certificate
    co = x509.load_pem_x509_certificate(str.encode(crtpem))
    opts['pubpem'] = prvkey.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf8')

    return True


''' Fetches cert from website

    @param [in] fname   - Path to cert file
    @param [in] opts    - Options

    @return     - Returns the public key in opts['pubpem']

    Example:

    readSiteCert("mysite.com", 443, opts)

'''
def readSiteCert(addr, port, opts):

    # Fetch certificate from server
    cert = ssl.get_server_certificate((addr, port))

    # Get public key from certificate
    co = x509.load_pem_x509_certificate(str.encode(cert))
    opts['pubpem'] = co.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf8')

    return True