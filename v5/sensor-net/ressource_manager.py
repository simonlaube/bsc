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
        self.faces = faces
        self.path = path
        self.config = {}
        with open(path + 'config.json') as f:
            self.config = json.load(f)

        self.feed_mngr = feed_manager.FeedManager(self.path, self._get_key_dict())
        self.dmx_front_filters = {}
        self.dmx_want_filters = {}
        self.blob_filters = {}
        self.in_queue = PriorityQueue(3) # queue with 3 priority classes
        self.in_blob_queue = []
        self.out_queue = PriorityQueue(3) # queue with 3 priority classes
        self.in_queue_lock  = _thread.allocate_lock()
        self.critical_feeds = self._get_critical_feeds()
        # TODO: maybe add medium critical category
        self._load_dmx_front_filters()
        self._load_dmx_want_filters()
        print('ressource manager initialized')

    def _get_key_dict(self):
        dict = self.config['child_feeds']
        dict[self.config['feed_id']] = self.config['secret']
        return dict

    def _get_critical_feeds(self):
        """Returns a list of feed_ids that are considered critical."""
        if self.config['feed_id'] == self.config['admin']:
            return []
        critical_feed_ids = []
        critical_feed_ids.append(self.config['admin'])
        # TODO: add child feeds of admin
        return critical_feed_ids
    
    def _update_dmx_front(self, feed):
        """If the given feed has not yet all blobs of newest blob chain,
        the hash pointer to the next blob gets added to filter.
        If the feed has not yet ended, the expected dmx of the next packet
        gets added to the filter.
        Else, the dmx filter of this feed gets set to \'None\'
        """
        # check if front is blob. If so, add blob pointer to front_filter
        # TODO: If we want to handle blobs seperately, append to seperate filterbank
        next_blob_ptr = feed.waiting_for_blob()
        if next_blob_ptr:
            self.dmx_front_filters[ssb_util.to_hex(feed.fid)] = next_blob_ptr
            return
        
        if feed.has_ended():
            print('feed has already ended')
            self.dmx_front_filters[ssb_util.to_hex(feed.fid)] = None


        dmx = feed.get_next_dmx()
        if dmx:
            self.dmx_front_filters[ssb_util.to_hex(feed.fid)] = dmx
            return
        print('could not update dmx front for ' + str(ssb_util.to_hex(feed.fid)))
        

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
            self.in_queue_lock.acquire()
            self._update_dmx_front(feed)
            self.in_queue_lock.release()

    def _load_dmx_want_filters(self):
        """
        Adds the dmx bytes of expected want requests to dmx-filter.
        By default blocks of all feeds stored in node can be requested and therefore
        for each feed a want dmx gets loaded into the filterbank.
        """
        self.dmx_want_filters = {} # reset dictionary
        for feed in self.feed_mngr.feeds:
            self.dmx_want_filters[ssb_util.to_hex(feed.fid)] = dmx(feed.fid + b'want')

    def _pack_want(self, feed):
        """Returns for given feed a want packet
        according to ssb protocol conventions.
        """
        want_dmx = dmx(feed.fid + b'want')
        seq = len(feed) + 1
        hash_pointer = feed.waiting_for_blob()
        # if next packet has to be blob -> append ptr to want request
        if hash_pointer:
            # we only want to check until current seq and not the next
            wire = want_dmx + feed.fid + (seq - 1).to_bytes(4, 'big') + hash_pointer
        else:
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
            print('incoming front error: feed not found')
            return
        self.in_queue.append(1, (buf, feed))
        """if feed.verify_and_append_bytes(buf):
            print('new packet was appended')
            self.dmx_front_filters[feed_id] = feed.get_next_dmx()"""
            # TODO: add new front dmx

    def _handle_blob_receive(self, buf, feed_id):
        """Blobs are written directly and not first appended to in queue."""
        # TODO: don't get feed from argument (not necessary)
        feed = self.feed_mngr.get_feed(feed_id)
        if feed.verify_and_append_blob(buf):
            print('blob was appended')
            self._update_dmx_front(feed)
            return
        print('blob was not appended')

    def _handle_want_request(self, buf, neigh):
        """If requested feed and block or blob with requested seq is present,
        the packet will be appended to the out queue and sent when possible."""

        buf = buf[7:]
        if len(buf) < 36:
            print('want request is too short')
            return

        feed_id = buf[:32]
        feed = self.feed_mngr.get_feed(feed_id)
        if feed == None:
            print("Requested feed not found")
            return

        seq = int.from_bytes(buf[32:36], 'big')
        if feed.front_seq < seq:
            print('requested blob/block is newer than current feed')
            return

        # check if it is a blob request
        if len(buf) == 56:
            hash_pointer = buf[36:56]
            blob = feed._get_blob(hash_pointer)
            if blob:
                self.out_queue.append(2, (blob.wire, neigh.face))
                return
            else:
                print('error while retrieving blob')
                return

        # get wanted packet and append to out queue
        self.out_queue.append(2, (feed.get_wire(seq), neigh.face))


    def on_receive(self, buf, neigh):
        """If incoming packet dmx / hash is in filters, this function handles the
        packets appropriately. If not, the packet gets discarded."""
        # TODO: proper uncloaking
        dmx = buf[:7]
        self.in_queue_lock.acquire()
        for k, v in self.dmx_front_filters.items():
            if v == dmx:
                print('received front dmx: ' + str(dmx))
                self._handle_front_receive(buf, k)
                self.in_queue_lock.release()
                return

        for k, v in self.dmx_want_filters.items():
            if v == dmx:
                print('received want dmx: ' + str(dmx))
                self._handle_want_request(buf, neigh)
                self.in_queue_lock.release()
                return

        # check if incoming pkt is blob (automatically verified with hash)
        hash_ptr = hashlib.sha256(buf).digest()[:20]
        # if blobs and dmx handled separately, change filter bank here
        for k, v in self.dmx_front_filters.items():
            if v == hash_ptr:
                print('received expected blob')
                self._handle_blob_receive(buf, k)
                
        # if hash_ptr in self.dmx_front_filters.values():
        #     print('received expected blob')
        #     # self.in_blob_queue.append((buf, k))
        #     self._handle_blob_receive(buf, k)
        # else:
        print('dmx not expected: ' + str(dmx))
        self.in_queue_lock.release()
        # print('neighbour: ' + str(neighbour))

    def ressource_manager_loop(self):
        # TODO: handle out / in queues individually for a given amount of time
        # TODO: Log time spent for different queues for optimizing
        while True:
            # if len(self.in_blob_queue) > 0:
            #     blob_buf, blob_k = self.in_blob_queue.pop(0)
            #     self._handle_blob_receive(blob_buf, blob_k)

            next_in = self.in_queue.next()
            if next_in:
                (buf, feed) = next_in
                if feed.verify_and_append_bytes(buf):
                    print('new packet was appended: ' + str(feed.get_next_dmx()))
                    self.in_queue_lock.acquire()
                    self._update_dmx_front(feed)
                    self.in_queue_lock.release()

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
            time.sleep(0.5)

    def start(self):
        self.io_loop = io.IOLOOP(self.faces, self.on_receive)
        print('io loop created')
        _thread.start_new_thread(self.io_loop.run, tuple())
        _thread.start_new_thread(self.ressource_manager_loop, tuple())

        # keep main thread alive
        while True:
            time.sleep(1)
            self._want_broadcast()
            # for feed_id in self.repo.listlog():
            #     if feed_id == self.config['feedID']:
            #         continue
            #     self._send_want(self.repo.get_log(feed_id))
