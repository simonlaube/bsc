import os
import key_manager
from hashlib import md5, sha256

# some symmetric private key for testing
pk = key_manager.get_pk()

# for now we use md5 with symmetric key instead of ed25519 and asymmetric keys
mksign = lambda sym_key, m: md5(sym_key + m).digest()
verify = lambda s, sym_key, m: s == md5(sym_key + m).digest()

class LlssbType:
    STD_48B = 0
    SSB_LOG = 1

def encode_48B(payload_48):
    """Returns the signed payload with SHA256 and added padding of 32B"""
    sign_64 = sha256(pk + payload_48).digest() + b'\0' * 32
    return LlssbType.STD_48B.to_bytes(1, 'little') + payload_48 + sign_64

def decode(demuxed_pkt):
    """Splits and checks the first byte for llssb-type,
    then hands it on to appropriate decoder
    """
    llssb_type = int.from_bytes(demuxed_pkt[0:1], "little")
    data = demuxed_pkt[1:]

    if llssb_type == LlssbType.STD_48B:
        return decode_48B(data)
    elif llssb_type == LlssbType.SSB_LOG:
        return decode_ssb_log(data)
    else:
        print('Given llssb-type is not valid')
        return b''

# change this method once 64B signature implemented
def decode_48B(data):
    payload = data[0:48]
    sign = data[48:80] # data[48:112] if signature is 64 B
    if sha256(pk + payload).digest() == sign:
        return payload
    else:
        print("signature of packet is not valid")

def decode_ssb_log(data):
    pass

"""
def encode(payload, llssb_type):
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
"""
