import os
import sys
from microssb import packet, util

"""Device dependent functions"""
if sys.implementation.name == 'micropython':
    def isfile(fn):
        try:
            return os.stat(fn)[0] & 0x8000 != 0
        except:
            return False
    
    def isdir(dn):
        try: 
            return os.stat(fn)[0] & 0x4000 != 0
        except:
            return False
else:
    isfile = os.path.isfile
    isdir = os.path.isdir


# ---------------------------------------------------------------------------- #

class Repo:
    
    def __init__(self, path, verify_sign_fct):
        self.path = path
        self.verify_sign_fct = verify_sign_fct
        try: os.mkdir(self.path + '/_logs')
        except: pass
        try: os.mkdir(self.path + '/_blobs')
        except: pass
        self.open_logs = {}

    def _log_file_name(self, feed_id):
        return self.path + '/_logs' + util.hex(feed_id) + '.log'
    
    def create_log(self, feed_id, trusted_seq, trusted_msg_id,
                   buf120 = None, parent_feed_id = bytes(32), parent_seq = 0):
        """Creates a log where log-entries can start at any index."""
        file_name = self._log_file_name(feed_id)
        if isfile(file_name):
            print("Log " + file_name + " already exists.")                        
            return None
        header = bytes(12)
        header += feed_id
        header += parent_feed_id + parent_seq.to_bytes(4, 'big')
        buf = trusted_seq.to_bytes(4, 'big') + trusted_msg_id
        header += buf
        if buf120 == None:
            hdr += buf # set trusted seq and msg-id as front
        else:
            pkt = packet.plain_from_bytes(buf120, feed_id, trusted_seq + 1,
                                          trusted_msg_id, self.verify_sign_fct)
            if pkt == None: return None             
            
            hdr += pkt.seq.to_bytes(4, 'big') + pkt.msg_id # set as front
        assert len(header) == 128, "Log file header must be 128B"
        
        with open(fn, 'wb') as f:
            f.write(header)
            if buf120 != None:
                f.write(bytes(8) + buf120) # write first log entry with trusted seq + 1
        return self.get_log(feed_id)

    def genesis_log(
        self, feed_id, buf48, sign_fct,
        parent_feed_id = bytes(32), parent_seq = 0):
        """Creates a Log where entries start at sequence 1."""
        prev = feed_id[:20] # this is a convention, like a self-signed certificate
        genesis_block = packet.Packet(feed_id, 1, prev)
        genesis_block.mk_plain48(buf48, sign_fct)
        return self.create_log(feed_id, 0, prev, genesis_block.wire,
                               parent_feed_id, parent_seq)   

    def get_log(self, feed_id):
        if not feed_id in self.open_logs:
            file_name = self._log_file_name(feed_id)
            if not isfile(file_name):
                print("Log does not yet exist.")
                return None
            log = Log(file_name, self.verify_sign_fct)
            if log == None:
                return None
            self.open_logs[feed_id] = log
        return self.open_logs[feed_id]