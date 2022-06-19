# -------------------------------------------------
# Implementation by Simon laube
# -------------------------------------------------

import sys
import time
import _thread

if sys.implementation.name == 'micropython':
    import machine
else:
    import random

"""Stores and manages dmx values of the node. Feeds can be assigned
to categories and per feed one dmx value is present."""
class DMXFilter:

    def __init__(self):
        self.fltr_dict = {}
        self.size = 0
        self.want_buffer = {}
        self.max_tries = 1 # number of unsuccesful tries until wait
        self.lock = _thread.allocate_lock()
    
    def __contains__(self, fid: str):
        """Returns True if a dmx value for the given feed ID exists."""
        keys = self._find(fid)
        if keys:
            return True        
        return False
    
    def __getitem__(self, fid: str):
        keys = self._find(fid)
        if keys:
            k1, k2 = keys
            return self.fltr_dict[k1][k2]
        print('dmx not found')
        return None
   
    def __iter__(self):
        for k, v in self.fltr_dict.items():
            for k2, v2 in self.fltr_dict[k].items():
                yield (k2, v2)
    
    def __str__(self):
        res = 'dmx filters: \n'
        for k, v in self:
            v, _ = v
            res += k
            res += ' : ' + str(v) + '\n'
        return res
    
    def _find(self, fid: str):
        """Returns the dmx valaue for the given feed ID."""
        self.lock.acquire()
        for k, v in self.fltr_dict.items():
            for k2, v2 in v.items():
                if k2 == fid:
                    self.lock.release()
                    return (k, k2)
        self.lock.release()
        return None
    
    def get_next_want_wire(self, feed_mngr, dmx_fct):
        """Returns a random want request packet. If the same
        packet is to be return again and 3 * number of dmx-values
        seconds have not passed yet, a different packet is returned."""
        if self.size == 0:
            return None
        if sys.implementation.name == 'micropython':
            want_pos = machine.rng() % self.size
        else:
            want_pos = random.randint(0, self.size)
        wire = None
        pos = 0
        self.lock.acquire()
        for k, v in self.fltr_dict.items():
            for k2, v2 in v.items():
                if want_pos != pos:
                    pos = (pos + 1) % self.size
                    continue
                feed = feed_mngr.get_feed(k2)
                if feed.has_ended():
                    want_pos = (want_pos + 1) % self.size
                    continue
                dmx = dmx_fct(feed.fid + b'want')
                seq = len(feed) + 1
                hash_pointer = feed.waiting_for_blob()
                if hash_pointer:
                    wire = dmx + feed.fid + (seq - 1).to_bytes(4, 'big') + hash_pointer
                else:
                    wire = dmx + feed.fid + seq.to_bytes(4, 'big')

                ti = int(time.time())
                tries = 1
                if k2 in self.want_buffer:
                    last_want = self.want_buffer[k2]
                    if last_want:
                        s, t, tr = last_want
                        # if same want -> wait for some time
                        if s == seq and ti - t < self.size * 3:
                            # try again if max tries not yet reached
                            if tr < self.max_tries:
                                self.want_buffer[k2] = (s, ti, tr + 1)
                                self.lock.release()
                                return wire
                            want_pos = (want_pos + 1) % self.size
                            continue
                self.want_buffer[k2] = (seq, ti, tries)
                self.lock.release()
                return wire
        self.lock.release()
        return None

    def append(self, category: str, fid: str, dmx):
        """Adds a dmx value to the given category and feed."""
        self.lock.acquire()
        self.size += 1
        if category not in self.fltr_dict.keys():
            self.fltr_dict[category] = { fid : dmx }
            self.lock.release()
            return
        self.fltr_dict[category][fid] = dmx
        self.lock.release()

    def pop(self, fid: str):
        """Removes dmx value of the given feed."""
        keys = self._find(fid)
        self.lock.acquire()
        if keys:
            k1, k2 = keys
            del self.fltr_dict[k1][k2]
            self.size -= 1
            self.lock.release()
            return
        print(fid + ' is not in dmx filter')
        self.lock.release()
    
    def reset_category(self, category: str):
        """Removes all dmx values of given category."""
        self.lock.acquire()
        if category not in self.fltr_dict.keys():
            self.lock.release()
            return
        for k, v in self.fltr_dict[category].items():
            self.size -= 1
        self.fltr_dict[category].clear()
        self.lock.release()
    
    def reset(self):
        """Removes all dmx values."""
        self.size = 0
        self.fltr_dict = {}