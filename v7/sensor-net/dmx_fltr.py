import time

class DMXFilter:

    def __init__(self):
        self.fltr_dict = {}
        self.size = 0
        self.want_pos = 0
        self.want_buffer = {}
    
    def __contains__(self, fid: str):
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
        for k, v in self.fltr_dict.items():
            for k2, v2 in v.items():
                if k2 == fid:
                    return (k, k2)
        return None
    
    def get_next_want_wire(self, feed_mngr, dmx_fct):
        if self.want_pos + 1 > self.size:
            self.want_pos = 0
        wire = None
        pos = 0
        for k, v in self.fltr_dict.items():
            for k2, v2 in v.items():
                if self.want_pos != pos:
                    pos += 1
                    continue
                feed = feed_mngr.get_feed(k2)
                dmx = dmx_fct(feed.fid + b'want')
                seq = len(feed) + 1
                hash_pointer = feed.waiting_for_blob()
                if hash_pointer:
                    wire = dmx + feed.fid + (seq - 1).to_bytes(4, 'big') + hash_pointer
                else:
                    wire = dmx + feed.fid + seq.to_bytes(4, 'big')
                self.want_pos += 1

                ti = int(time.time())
                if k2 in self.want_buffer:
                    last_want = self.want_buffer[k2]
                    if last_want:
                        s, t = last_want
                        # if same want -> wait for some time
                        if s == seq and ti - t < self.size * 3:
                            continue
                self.want_buffer[k2] = (seq, ti)
                return wire
        self.want_pos = 0
        return None

    def append(self, category: str, fid: str, dmx):
        self.size += 1
        if category not in self.fltr_dict.keys():
            self.fltr_dict[category] = { fid : dmx }
            return
        self.fltr_dict[category][fid] = dmx

    def pop(self, fid: str):
        keys = self._find(fid)
        if keys:
            k1, k2 = keys
            del self.fltr_dict[k1][k2]
            self.size -= 1
            return
        print(fid + ' is not in dmx filter')
    
    def reset_category(self, category: str):
        if category not in self.fltr_dict.keys():
            return
        for k, v in self.fltr_dict[category].items():
            self.size -= 1
        self.fltr_dict[category].clear()
    
    def reset(self):
        self.size = 0
        self.fltr_dict = {}