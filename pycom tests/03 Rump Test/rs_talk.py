import key_manager
from hashlib import md5

pk = key_manager.get_pk()
secret = key_manager.get_secret()

mksign = lambda pk, m: md5(pk + m).digest()
verify = lambda s, pk, m: s == md5(pk + m).digest()

def encode(b):
    pkt = mksign(pk, secret + b)
    return pkt

def decode(pkt):
    for i in range(256):
        b = bytes([i])
        if verify(pkt, pk, secret + b):
            return b
