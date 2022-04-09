class Log:
    
    def __init__(self, file_name, verify_sign_fct):
        self.verify_sign_fct = verify_sign_fct
        self.f = open(file_name, 'rb+')
        self.f.seek(0)
        header = self.f.read(128)
        header = header[12:] # first 12 bytes are not used
        self.feed_id = header[:32]
        self.parent_feed_id = header[32:64]
        self.parent_seq = int.from_bytes(header[64:68], 'big')
        self.anchor_seq = int.from_bytes(header[68:72], 'big') # trusted seq nr
        self.anchor_msg_id = header[72:92] # trusted msg id
        self.front_seq = int_from_bytes(header[92:96]) # seq of newest rec
        self.front_msg_id = header[96:116] # msg id of newest rec
        self.f.seek(0, 2)
        assert self.f.tell() == 128 + 128 * (self.front_seq - self.anchor_seq), "log file length mismatch"
    
    def _append(self, pkt):
        assert pkt.seq == self.front_seq + 1, "New log entry not in sequence."
        # append to file:
        self.f.seek(0, 2)
        self.f.write(bytes(8) + pkt.wire)
        # update file header:
        self.front_seq += 1
        self.front_msg_id = pkt.msg_id
        self.f.seek(12+92) # position of front fields
        self.f.write(self.front_seq.to_bytes(4, 'big') + self.front_msg_id)
        self.f.flush
        return pkt
    
    def append(self, buf120):
        pkt = packet.plain_from_bytes(buf120, self.feed_id, self.front_seq + 1,
                                self.front_msg_id, self.verify_sign_fct)
        if pkt == None: return None
        return self._append(pkt)


    def get_front(self):
        return (self.front_seq, self.front_msg_id)