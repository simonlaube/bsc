import rs_talk
import llssb
from llssb import LlssbType
from hashlib import sha256

class CargoProtocol:
    RS_TALK = 0
    LLSSB = 1

class CargoSend:
    def __init__(self, port):
        self.port = port
        self.data = b''
        self.next_pos = 0
        self.seq = 0

    def set_data(self, data):
        self.data = data

    def pack_next(self, llssb_type = LlssbType.STD_48B):
        """Iteratively encodes the message and returns packets"""
        if self.next_pos >= len(self.data):
            print("No more data to be encoded")
            return None

        start = self.next_pos
        if llssb_type == LlssbType.STD_48B:
            end = min(start + 48, len(self.data))
            # TODO: Add proper padding
            if end - start < 48: # data shorter than available payload space
                self.data += b'\0' * (48 - (end - start)) # add padding
                end = len(self.data)
            encoded = llssb.encode_48B(self.data[start:end])
        elif llssb == LlssbType.SSB_LOG:
            pass

        self.next_pos = end
        pkt = b'\0' * 8 + sha256(bytes([self.port + self.seq])).digest()[:7] + encoded # add RND (for now just placeholder)
        return pkt

class CargoRecv:
    def __init__(self, port):
        self.port = port
        self.data = b''
        self.length = 0 # first packet should specify length
        self.seq = 0

    def unpack_next(self, demuxed_pkt, seq):
        if seq != self.seq:
            # TODO: send NAK
            return False
        self.seq = self.seq * (-1) + 1 # 0 -> 1, 1 -> 0
        self.data += llssb.decode(demuxed_pkt)
        print(self.data)
        return True

    # set flag when packet is complete + properly unpad payload
    def get(self):
        pass
