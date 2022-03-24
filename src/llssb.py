import os
import key_manager
from hashlib import md5

# some symmetric private key for testing
pk = key_manager.get_pk()

# for now we use md5 with symmetric key instead of ed25519 and asymmetric keys
mksign = lambda sym_key, m: md5(sym_key + m).digest()
verify = lambda s, sym_key, m: s == md5(sym_key + m).digest()

class LlssbType:
    STD_SIGN = 0

    SSB_LOG = 1

class DMX:
    PAYLOAD_48B = 1


def encode(payload, llssb_type):
    """Encodes payload into one llssb packet"""
    if llssb_type == LlssbType.STD_SIGN:
        sign = mksign(pk, payload)
        demux_content = LlssbType.STD_SIGN.to_bytes(1, 'little') + payload + sign
        demux = 0.to_bytes(7, 'little') # for now just placeholder
        pkt = 0.to_bytes(8, 'little') + demux # for now just placeholder
    elif llssb_type == LlssbType.SSB_LOG:
        pass
    else:
        print('Error: No LlssbType defined for packet!')

def decode(payload, llssb_type):
    if llssb_type == LlssbType.STD_SIGN:

    elif llssb_type == LlssbType.SSB_LOG:
        pass
    else:
        print('Error: No LlssbType defined for packet!')
