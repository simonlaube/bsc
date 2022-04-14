import time
import hashlib
import json
import _thread
from tinyssb import io, packet, repository, util
from microssb import log_manager, log

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
    
    def __init__(self, faces, path):
        print('rm init started')
        self.faces = faces
        self.path = path
        self.log_manager = LogManager(path)
        self.config = {}
        with open(path + 'config.json') as f:
            self.config = json.load(f)
        for i in self.config: # hex to bytes
            if not i in ['alias', 'name']:
                self.config[i] = util.fromhex(self.config[i])   
        print(self.config)

        # self.repo = repository.REPO(self.path, mk_verify_fct(self.config['secret']))
        self.dmx_front_filters = {}
        self.dmx_want_filters = {}
        self.blob_filters = {}
        self.out_queue = []
        # self.user = {}
        # self.peer_nodes = {}
        self._load_dmx_front_filters()
        self._load_dmx_want_filters()
        print('rm init ended')
    
    def _get_front_dmx(self, feed_id):
        """Returns dmx of this feed with latest seq + 1. Returns None if given
        feed ID belongs to this repo."""
        if feed_id == self.config['feedID']:
            # TODO: also return None if it is child feed of current feed
            return None
        # feed = self.repo.get_log(feed_id)
        feed = self.log_manager.get_log(feed_id)
        seq, prev_hash = feed.getfront()
        next_seq = (seq + 1).to_bytes(4, 'big')
        pkt_dmx = packet._dmx(feed.fid + next_seq + prev_hash)
        return pkt_dmx
    
    def _load_dmx_front_filters(self):
        """Adds the expected dmx bytes to dmx-filter."""
        self.dmx_front_filters = {} # reset dictionary
        for feed_id in self.repo.listlog():
            dmx = self._get_front_dmx(feed_id)
            if dmx:
                self.dmx_front_filters[feed_id] = dmx
    
    def _load_dmx_want_filters(self):
        self.dmx_want_filters = {} # reset dictionary
        for feed_id in self.repo.listlog():
            self.dmx_want_filters[feed_id] = packet._dmx(feed_id + b'want')
            print('want filters: ')
            print(self.dmx_want_filters[feed_id])
    
    def prepare_to_send(self, pkt):
        for f in self.faces:
            f.enqueue(pkt)
                    
    def _send_want(self, feed):
        want_dmx = packet._dmx(feed.fid + b'want')
        seq = len(feed) + 1
        wire = want_dmx + feed.fid + seq.to_bytes(4, 'big')
        self.prepare_to_send(wire)    
    
    def want_broadcast(self):
        # TODO: implement some priority queue that prioritizes admin feeds
        # TODO: implement want for feeds that are not yet in repo but in admin feed
        # or alternatively directly add feed when admin msg arrives
        for feed_id in self.repo.listlog():
            if feed_id == self.config['feedID']:
                continue
            feed = self.repo.get_log(feed_id)
            self._send_want(feed)

    def _handle_front_receive(self, buf):
        pass
    
    def _handle_want_request(self, buf, neigh):
        buf = buf[7:]
        while len(buf) >= 36: # check for all want requests in pkt
            feed_id = buf[:32]
            seq = int.from_bytes(buf[32:36], 'big')
            try:
                feed = self.repo.get_log(feed_id)
                if feed:
                    neigh.face.enqueue(feed[seq].wire)
            except: 
                print('something happened while getting feed from repo')
            buf = buf[36:]
    
    def _handle_blob_receive(self, buf):
        pass
        
    def on_receive(self, buf, neigh):
        """If incoming packet dmx / hash is in filters, this function handles the
        packets appropriately. If not, the packet gets discarded."""
        # TODO: uncloaking
        dmx = buf[:7]
        if dmx in self.dmx_front_filters.values():
            print('received front dmx: ' + str(dmx))
            self._handle_front_receive(buf)
            
        elif dmx in self.dmx_want_filters.values():
            print('received want dmx: ' + str(dmx))
            self._handle_want_request(buf, neigh)

        else:
            hash_ptr = hashlib.sha256(buf).digest()[:20]
            if hash_ptr in self.blob_filters.values():
                print('received expected blob')
                self._handle_blob_receive(buf)
            else:
                print('dmx not expected: ' + str(dmx))
        # print('neighbour: ' + str(neighbour))
   
    def ressource_manager_loop(self):
        time.sleep(2)
        print('2 secs passed')
    
    def start(self):
        self.io_loop = io.IOLOOP(self.faces, self.on_receive)
        print('io loop created')
        _thread.start_new_thread(self.io_loop.run, tuple())
        _thread.start_new_thread(self.ressource_manager_loop, tuple())
        
        # keep main thread alive
        while True:
            time.sleep(4)
            for feed_id in self.repo.listlog():
                if feed_id == self.config['feedID']:
                    continue
                self._send_want(self.repo.get_log(feed_id))