import time
import hashlib
import json
import _thread
from priority_queue import PriorityQueue
from tinyssb import io
from microssb import packet, feed_manager, ssb_util

def dmx(msg: bytes):
    return hashlib.sha256(msg).digest()[:7]

class RessourceManager:
    
    # TODO: add states for energy and storage availability

    def __init__(self, faces, path):
        print('rm init started')
        self.faces = faces
        self.path = path
        self.config = {}
        with open(path + 'config.json') as f:
            self.config = json.load(f)
        # for i in self.config: # hex to bytes
            # if i == 'child_feeds':
            #     child_feeds = {}
            #     for j, sk in self.config[i].items():
            #         child_feeds[ssb_util.from_hex(j)] = ssb_util.from_hex(sk)
            #     self.config[i] = child_feeds
            # elif not i in ['alias', 'name']:
            #     self.config[i] = ssb_util.from_hex(self.config[i])   

        self.feed_mngr = feed_manager.FeedManager(self.path, self._get_key_dict())
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
    
    def _get_key_dict(self):
        dict = self.config['child_feeds']
        dict[self.config['feed_id']] = self.config['secret']
        print(dict)
        return dict
    
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
        feed = self.feed_mngr.get_feed(feed_id)
        seq, prev_hash = feed.get_front()
        next_seq = (seq + 1).to_bytes(4, 'big')
        pkt_dmx = dmx(feed.fid + next_seq + prev_hash)
        print('dmx 1')
        print(pkt_dmx)
        print('dmx 2')
        print(feed.get_next_dmx())
        return pkt_dmx
    
    def _load_dmx_front_filters(self):
        """
        Adds the dmx bytes of expected packets to dmx-filter."""
        self.dmx_front_filters = {} # reset dictionary
        self.blob_filters = {} # reset dictionary
        for feed in self.feed_mngr.feeds:
            if ssb_util.to_hex(feed.fid) == self.config['feed_id']:
                continue
            if ssb_util.to_hex(feed.parent_id) == self.config['feed_id']:
                continue
            next_hash = feed.waiting_for_blob()
            if next_hash:
                print("waiting for blob")
                self.blob_filters[ssb_util.to_hex(feed.fid)] = next_hash
                continue # blob chain not yet complete, therefore no dmx request
            dmx = feed.get_next_dmx()
            print('front_filters: ')
            print(dmx)
            if dmx:
                self.dmx_front_filters[feed.fid] = dmx
    
    def _load_dmx_want_filters(self):
        """
        Adds the dmx bytes of expected want requests to dmx-filter.
        By default blocks of all feeds stored in node can be requested and therefore
        for each feed a want dmx gets loaded into the filterbank.
        """
        self.dmx_want_filters = {} # reset dictionary
        for feed in self.feed_mngr.feeds:
            self.dmx_want_filters[ssb_util.to_hex(feed.fid)] = dmx(feed.fid + b'want')
            print('want filters: ')
            print(self.dmx_want_filters[ssb_util.to_hex(feed.fid)])
    
                       
    def _pack_want(self, feed):
        """Returns for given feed a want packet 
        according to ssb protocol conventions.
        """
        want_dmx = dmx(feed.fid + b'want')
        seq = len(feed) + 1
        wire = want_dmx + feed.fid + seq.to_bytes(4, 'big')
        return wire

    def _want_broadcast(self):
        # TODO: implement want for feeds that are not yet in repo but in admin feed
        # or alternatively directly add feed when admin msg arrives
        """
        Adds want packets for feeds that are not owned by this node to priority queue.
        If a feed is 'critical', it will have highest priority. 
        """
        for feed in self.feed_mngr.feeds:
            if ssb_util.to_hex(feed.fid) == self.config['feed_id']:
                continue
            if ssb_util.to_hex(feed.parent_id) == self.config['feed_id']:
                continue
            if feed.fid in self.critical_feeds:
                self.out_queue.append(0, (self._pack_want(feed), None))
            else:
                self.out_queue.append(2, (self._pack_want(feed), None))

    def _handle_front_receive(self, buf, feed_id):
        feed = self.feed_mngr.get_feed(feed_id)
        if feed == None:
            print('error while trying to get feed')
            return
        if feed.verify_and_append_bytes(buf):
            print('new packet was appended')
            self.dmx_front_filters.pop(feed_id)
            self.dmx_front_filters[feed_id] = feed.get_next_dmx()
            # TODO: add new front dmx

    
    def _handle_want_request(self, buf, neigh):
        """If requested feed and block or blob with requested seq is present, 
        the packet will be appended to the out queue and sent when possible."""
        buf = buf[7:]
        assert len(buf) >= 36
        feed_id = buf[:32]
        seq = int.from_bytes(buf[32:36], 'big')

        # check if it is a blob request
        blob_seq = -1
        if len(buf) == 40:
            blob_seq = int.from_bytes(buf[36:40], 'big')
        
        # get wanted paket and append to out queue
        feed = self.feed_mngr.get_feed(feed_id)
        if feed == None:
            print("Requested feed not found")
            return
        if seq > feed.front_seq:
            print("Requested block with given seq not found")
            return
        if blob_seq == -1: # no block seq given -> return block
            self.out_queue.append(2, (feed.get_wire(seq), neigh.face))
            return
        # TODO: if blob seq is found: append out
    
    def _handle_blob_receive(self, buf):
        # TODO: check if blob complete. If yes -> add front dmx to filterbank
        # TODO: if blob can be appended, change next_hash filter in filterbank
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
            if next_out:
                (pkt, face) = next_out
                if pkt != None:
                    # print('send: ')
                    # print(pkt)
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