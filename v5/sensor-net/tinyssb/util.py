#

# tinyssb/util.py

import base64
import sys

if sys.implementation.name == 'micropython':
    import binascii
    fromhex = binascii.unhexlify
    hex = lambda b: binascii.hexlify(b).decode()
else:
    fromhex = lambda h: bytes.fromhex(h)
    hex = lambda b: b.hex()

b64 = lambda b: base64.b64encode(b).decode()

# because micropython json.dumps() does not have the 'indent' keyword ...
def json_pp(d, indent=''):
    indent += '  '
    if d == None:      return "null"
    if type(d) == int: return str(d)
    if type(d) == str: return '"' + d + '"'
    if type(d) == list:
        jsonstr = '[\n'
        cnt = 1
        for i in d:
            jsonstr += indent + json_pp(i, indent)
            jsonstr += ',\n' if cnt < len(d) else  '\n'
            cnt += 1
        jsonstr += indent[:-2] + ']'
        return jsonstr
    if type(d).__name__ in ['dict', 'OrderedDict']:
        jsonstr = '{\n'
        cnt = 1
        for k,v in d.items():
            jsonstr += indent + '"' + k + '": ' + json_pp(v, indent)
            jsonstr += ',\n' if cnt < len(d) else '\n'
            cnt += 1
        jsonstr += indent[:-2] + '}'
        return jsonstr
    return "??"

class SSBPriorityQueue:
    """Implementation for the TinySSB ressource manager queue.
    Highest Priority: 0. Priorities get lower the higher the priority number is.
    This queue gives entries of all priority classes a chance to get popped,
    however higher priority entries have more assigned slots.
    Number of slots: sum_{i = 0..nr_priorities-1} int(i^1.5)"""
    def __init__(self, nr_priorities):

        # defines the number of different priority classes
        self.nr_priorities = nr_priorities 
        self.queue = []
        self.slots = self._calculate_slots()
        self.nr_pos = sum(slots)
        self.current_pos = 0 # iterates over all slots
        self.size = 0
    
    def _init_priority_queues(self):
        for i in range(0, self.nr_priorities):
            self.queue[i] = []
    
    def _calculate_slots(self):
        slots = []
        for i in range(0, self.nr_priorities):
            # exponential slot assignments.
            sum = sum(slots)
            slots.insert(0, sum + int(pow(i, 1.5))) 
    
    def append(self, priority, pkt):
        if priority < 0 or priority > self.nr_priorities - 1:
            print('the given priority is out of range: it is now adjusted to the closest valid priority.')
        if priority <= 0:
            self.queue[0].append(pkt)
        elif priority >= self.nr_priorities - 1:
            self.queue[self.nr_priorities - 1].append(pkt)
        else:
            self.queue[priority].append(pkt)
        self.size += 1
    
    def _next_with_priority(self, priority):
        """Gets first packet in priority class. If class is empty, go to next class until pkt found.
        If no packet in priority queue, return None."""
        if self.size == 0:
            return None
        i = 0
        while not self.queue[priority] and i < self.nr_priorities:
            priority = (priority + 1) % nr_priorities
            i += 1
        return self.queue[priority].pop(0)
            

    def next(self):
        for i in range(0, self.nr_priorities):
            if self.current_pos < self.slots[i]:
                self._next_with_priority(i)
            
# eof
