import time
import hashlib
import json
import _thread
from priority_queue import PriorityQueue
from tinyssb import io, packet, repository, util

def mk_verify_fct(secret):
    def vfct(pk, s, msg):
        try:
            pure25519.VerifyingKey(pk).verify(s,msg)
            return True
        except Exception as e:
            print(e)
        return False
    return vfct

class RessourceManager:
    
    # TODO: add states for energy and storage availability

    def __init__(self, faces, path):
        print('rm init started')
        self.faces = faces
        self.path = path
        self.config = {}
        with open(path + 'config.json') as f:
            self.config = json.load(f)
        for i in self.config: # hex to bytes
            if i == 'child_feeds':
                child_feeds = {}
                for j, sk in self.config[i].items():
                    child_feeds[util.fromhex(j)] = util.fromhex(sk)
                self.config[i] = child_feeds
            elif not i in ['alias', 'name']:
                self.config[i] = util.fromhex(self.config[i])   
        print(self.config)

        self.repo = repository.REPO(self.path, mk_verify_fct(self.config['secret']))
        self.dmx_front_filters = {}
        self.dmx_want_filters = {}
        self.blob_filters = {}
        self.in_queue = PriorityQueue(3) # queue with 3 priority classes
        self.out_queue = PriorityQueue(3) # queue with 3 priority classes
        self.critical_feeds = self._get_critical_feeds()
        # TODO: maybe add medium critical category
        self._load_dmx_front_filters()
        self._load_dmx_want_filters()
        print('rm init ended')
    
    def _get_critical_feeds(self):
        """Returns a list of feed_ids that are considered critical."""
        if self.config['feed_id'] == self.config['admin']:
            return []
        critical_feed_ids = []
        critical_feed_ids.append(self.config['admin'])
        # TODO: add child feeds of admin
        return critical_feed_ids
    
    def _get_front_dmx(self, feed_id):
        """Returns dmx of this feed with latest seq + 1. Returns None if given
        feed ID belongs to this repo."""
        if feed_id == self.config['feed_id']:
            # TODO: also return None if it is child feed of current feed
            return None
        feed = self.repo.get_log(feed_id)
        seq, prev_hash = feed.getfront()
        next_seq = (seq + 1).to_bytes(4, 'big')
        pkt_dmx = packet._dmx(feed.fid + next_seq + prev_hash)
        return pkt_dmx
    
    def _load_dmx_front_filters(self):
        """Adds the dmx bytes of expected packets to dmx-filter."""
        self.dmx_front_filters = {} # reset dictionary
        for feed_id in self.repo.listlog():
            dmx = self._get_front_dmx(feed_id)
            if dmx:
                self.dmx_front_filters[feed_id] = dmx
    
    def _load_dmx_want_filters(self):
        """Adds the dmx bytes of expected want requests to dmx-filter."""
        self.dmx_want_filters = {} # reset dictionary
        for feed_id in self.repo.listlog():
            self.dmx_want_filters[feed_id] = packet._dmx(feed_id + b'want')
            print('want filters: ')
            print(self.dmx_want_filters[feed_id])
    
                       
    def _pack_want(self, feed):
        """Returns for given feed a want packet 
        according to ssb protocol conventions.
        """
        want_dmx = packet._dmx(feed.fid + b'want')
        seq = len(feed) + 1
        wire = want_dmx + feed.fid + seq.to_bytes(4, 'big')
        return wire    

    def _want_broadcast(self):
        # TODO: implement some priority queue that prioritizes admin feeds
        # TODO: don't broadcast want for own child feeds
        # TODO: implement want for feeds that are not yet in repo but in admin feed
        # or alternatively directly add feed when admin msg arrives
        """
        Adds want packets to priority queue. If feed is 'critical',
        it will have highest priority.
        """
        for feed_id in self.repo.listlog():
            if feed_id == self.config['feed_id']:
                continue
            feed = self.repo.get_log(feed_id)
            if feed_id in self.critical_feeds:
                self.out_queue.append(0, (self._pack_want(feed), None))
            else:
                self.out_queue.append(2, (self._pack_want(feed), None))

    def _handle_front_receive(self, buf, feed_id):
        self.repo.get_log(feed_id).append(buf)
    
    def _handle_want_request(self, buf, neigh):
        buf = buf[7:]
        while len(buf) >= 36: # check for all want requests in pkt
            feed_id = buf[:32]
            seq = int.from_bytes(buf[32:36], 'big')
            try:
                feed = self.repo.get_log(feed_id)
                if feed:
                    self.out_queue.append(2, (feed[seq].wire, neigh.face))
            except: 
                print('something happened while getting feed from repo')
            buf = buf[36:]
    
    def _handle_blob_receive(self, buf):
        pass
        
    def on_receive(self, buf, neigh):
        """If incoming packet dmx / hash is in filters, this function handles the
        packets appropriately. If not, the packet gets discarded."""
        # TODO: proper uncloaking
        dmx = buf[:7]
        for k, v in self.dmx_front_filters.items():
            if v == dmx:
                print('received front dmx: ' + str(dmx))
                self._handle_front_receive(buf, k)
                return
           
        for k, v in self.dmx_want_filters.items():
            if v == dmx:
                print('received want dmx: ' + str(dmx))
                self._handle_want_request(buf, neigh)
                return

        hash_ptr = hashlib.sha256(buf).digest()[:20]
        if hash_ptr in self.blob_filters.values():
            print('received expected blob')
            self._handle_blob_receive(buf)
        else:
            print('dmx not expected: ' + str(dmx))
        # print('neighbour: ' + str(neighbour))
   
    def ressource_manager_loop(self):
        while True:
            next_out = self.out_queue.next()
            if next:
                (pkt, face) = next
                if pkt != None:
                    if not face:
                        for f in self.faces:
                            f.enqueue(pkt)
                    else:
                        face.enqueue(pkt)
            # TODO: check battery and decide
            time.sleep(2)
    
    def start(self):
        self.io_loop = io.IOLOOP(self.faces, self.on_receive)
        print('io loop created')
        _thread.start_new_thread(self.io_loop.run, tuple())
        _thread.start_new_thread(self.ressource_manager_loop, tuple())
        
        # keep main thread alive
        while True:
            time.sleep(4)
            self._want_broadcast()
            # for feed_id in self.repo.listlog():
            #     if feed_id == self.config['feedID']:
            #         continue
            #     self._send_want(self.repo.get_log(feed_id))