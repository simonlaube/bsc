import key_manager
from hashlib import md5

# some symmetric private key for testing
pk = key_manager.get_pk()
# some secret for testing
secret = key_manager.get_secret()

mksign = lambda sym_key, m: md5(sym_key + m).digest()
verify = lambda s, sym_key, m: s == md5(sym_key + m).digest()

def encode(b):
    pkt = mksign(pk, secret + b)
    return pkt

def decode(pkt):
    for i in range(256):
        b = bytes([i])
        if verify(pkt, pk, secret + b):
            return b
