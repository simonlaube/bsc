import rs_talk
import llssb
from llssb import LlssbType

class CargoProtocol:
    RS_TALK = 0
    LLSSB = 1

class Port:
    SOME_PORT_1 = 1
    SOME_PORT_2 = 2

class CargoSend:

    def __init__(self, port, data):
        self.port = port
        self.data = data
        self.next_pos = 0

    def pack_next(self, llssb_type = LlssbType.STD_48B):
        """Encodes the message and iteratively returns packets"""
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
        pkt = b'\0' * 16 + encoded # add RND and DMX (for now just placeholder)
        return pkt

class CargoRecv:

    def __init__(self, port):
        self.port = port
        self.data = b''
        self.length = 0 # first packet should specify length

    def unpack_next(self, pkt):
        demuxed_pkt = pkt[16:] # remove first 8B (for now just placeholder)
        self.data += llssb.decode(demuxed_pkt)

    # set flag when packet is complete + properly unpad payload
    def get(self):
        pass
