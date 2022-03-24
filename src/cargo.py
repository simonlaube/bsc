import rs_talk
import llssb
from llssb import LlssbType

class CargoProtocol:
    RS_TALK = 0
    LLSSB = 1

class Cargo:

    def __init__(self, msg, cargo_protocol, llssb_type = None):
        self.msg = msg
        self.cargo_protocol = cargo_protocol
        self.llssb_type = llssb_type
        self.payload_size = self._payload_size()
        self.next_pos = 0

    def _payload_size(self):
        """Returns the amount of payload per packet depending on payload_type"""
        # Only 1B 'payload', rest is encryption
        if self.cargo_protocol == CargoProtocol.RS_TALK:
            return 1
        # 128B - (8B cloaking, 7B DMX, 64B crypto-sign, 1B Type)
        if self.llssb_type == LlssbType.STD_SIGN:
            return 48
        # 128B - (8B cloaking, 7B DMX, 64B crypto-sign, 1B Type,
        # 1B length, 20B hash of first blob in chain)
        if self.llssb_type == LlssbType.SSB_LOG:
            return 27

    def _assemble_pkt(self, payload):
        if self.cargo_protocol == CargoProtocol.RS_TALK:
            return rs_talk.encode(payload)
        if self.cargo_protocol == CargoProtocol.LLSSB:
            return llssb.encode(payload, self.llssb_type)

    def pkt_gen(self):
        """Encodes the message and iteratively yields packets"""
        while self.next_pos < len(self.msg):
            start = self.next_pos
            end = min(start + self.payload_size, len(self.msg))
            self.next_pos = end
            payload = self.msg[start:end]
            yield self._assemble_pkt(payload)
