import hashlib
import pure25519

PKTTYPE_plain48 = 0x00 # ed25519 signature, single packet with 48B
PKTTYPE_chain20 = 0x01 # ed25519 signature, start of hash sidechain

def _dmx(name):
    hashlib.sha256(name).digest()[:7]

class Packet:

    def __init__(self, feed_id, seq, prev):
        self.feed_id = feed_id # ed25519 public key
        self.seq = seq # packet sequence number in big endian format
        self.prev = prev # previous msg_id
        self.name = self.feed_id + self.seq.to_bytes(4, 'big') + self.prev
        self.dmx = _dmx(self.name)

        self.type = None
        self.payload = None
        self.signature = None
        self.wire = None # bytes that get sent and are stored in feed
        self.msg_id = None
        
        self.chain_len = -1
        self.chain_content = b''
        self.chain_next_hash = None # hashpointer to next (pending) blob

    def _msg_id(self):
        return hashlib.sha256(self.name + self.wire).digest()[:20]
        
    # def _expand(self):
    #     return self.name + self.dmx + self.type + self.payload

    def _sign(self, type, payload, sign_fct):
        self.type = bytes([type])
        self.payload = payload
        msg = self.dmx + self.type + self.payload
        self.signature = sign_fct(self.name + msg)
        self.wire = msg + self.signature
        self.msg_id = self._msg_id()

    def mk_plain48(self, payload, sign_fct):
        assert len(payload) <= 48
        if len(payload) < 48:
            payload += b'\x00' * (48 - len(payload))
        self._sign(PKTTYPE_plain48, payload, sign_fct)

    def predict_next_dmx(self):
        next_name = self.feed_id + (self.seq + 1).to_bytes(4, 'big') + self.msg_id

def plain_from_bytes(buf120, feed_id, seq, prev, verify_sign_fct):
    """Returns a Packet from given arguments. If packet was not yet validated, 
    a signature verifying function has to be passed.
    Returns None if either demultiplexing or signature verifying failed."""
    pkt = Packet(feed_id, seq, prev)

    if verify_sign_fct: # packet has not yet been validated
        if buf120[:7] != pkt.dmx:
            print("Demultiplexing failed, not a valid log extension.")
            return None
    
    pkt.type = buf120[7:8]
    pkt.payload = buf120[8:56]
    pkt.signature = buf120[56:]

    if verify_sign_fct: # packet has not yet been validated
        if not verify_sign_fct(feed_id, pkt.signature, pkt.nam + buf120[:56]):
            print("Signature verifying failed")
            return None 

    pkt.wire = buf120
    pkt.msg_id = pkt._msg_id()
    return pkt