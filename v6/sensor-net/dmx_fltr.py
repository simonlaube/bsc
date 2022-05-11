class DMXFilter:

    def __init__(self):
        self.fltr_dict = {}
    
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
    
    def _find(self, fid: str):
        for k, v in self.fltr_dict.items():
            for k2, v2 in v.items():
                if k2 == fid:
                    return (k, k2)
        return None
        
    def append(self, category: str, fid: str, dmx):
        if category not in self.fltr_dict.keys():
            self.fltr_dict[category] = { fid : dmx }
            return
        self.fltr_dict[category][fid] = dmx

    def pop(self, fid: str):
        keys = self._find(fid)
        if keys:
            k1, k2 = keys
            del self.fltr_dict[k1][k2]
            return
        print(fid + ' is not in dmx filter')
    
    def reset_category(self, category: str):
        if category not in self.fltr_dict.keys():
            return
        self.fltr_dict[category].clear()
    
    def reset(self):
        self.fltr_dict = {}