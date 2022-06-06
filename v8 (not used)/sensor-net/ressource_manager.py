import time
import hashlib
import sys
import _thread
import config
from dmx_fltr import DMXFilter
from priority_queue import PriorityQueue
import fork_tree
import session_tree
from feed_forest import FeedForest
# from tinyssb import io
from microssb import packet, feed_manager, ssb_util, io
from microssb import feed as fd

if sys.implementation.name == "micropython":
    import machine
    import gc

def dmx(msg: bytes):
    return hashlib.sha256(msg).digest()[:7]

class RessourceManager:

    # TODO: add states for energy and storage availability

    def __init__(self, faces, path):
        self.faces = faces
        self.path = path
        self.config = config.Config(self.path)
        self.dmx_fltr = DMXFilter()
        self.want_fltr = {}
        self.blob_filters = {}
        self.in_queue = PriorityQueue(4) # queue with 4 priority classes
        self.in_blob_queue = []
        self.out_queue = PriorityQueue(3) # queue with 3 priority classes
        self.in_queue_lock = _thread.allocate_lock()
        # self.critical_feeds = self._get_critical_feeds()

        self.feed_mngr = feed_manager.FeedManager()
        self.feed_mngr.update_keys(self.get_key_dict())
        self._load_want_fltr()
        self._load_dmx_fltr()
        self.feed_forest = FeedForest(self.feed_mngr, self.dmx_fltr, self.want_fltr, self.config)

        self.append_lock = _thread.allocate_lock()

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
        Only feeds that are not part of a tree structure should be handled here.
        """
        # TODO: add this function
        """
        if feed.has_ended():
            print('feed has already ended')
            self.dmx_fltr.pop(ssb_util.to_hex(feed.fid))
        """

        # check if front is blob. If so, add blob pointer to front_filter
        # TODO: If we want to handle blobs seperately, append to seperate filterbank
        next_blob_ptr = fd.waiting_for_blob(feed)
        if next_blob_ptr:
            self.dmx_fltr[ssb_util.to_hex(feed.fid)] = (next_blob_ptr, self._handle_blob_receive)
            return

        dmx = fd.get_next_dmx(feed)
        if dmx:
            self.dmx_fltr.append('id', ssb_util.to_hex(feed.fid), (dmx, self._set_priority_in))

            return
        print('could not update dmx front for ' + str(ssb_util.to_hex(feed.fid)))


    def _load_dmx_fltr(self):
        """
        Adds the dmx bytes of expected packets to dmx-filter."""
        self.dmx_fltr.reset() # reset dictionary
        self.blob_filters = {} # reset dictionary
        print('front-filters: ')
        for fid in self.feed_mngr.listfids():
            if ssb_util.to_hex(fid) == self.config['feed_id']:
                continue
            if ssb_util.to_hex(fd.get_parent(fd.get_feed(fid)).fid) == self.config['feed_id']:
                continue
            # if ssb_util.to_hex(feed.fid) == self.config['admin']:
            # only put ID feeds in dmx front (others are handled in trees)
            if not fd.get_prev(fd.get_feed(fid)) and not fd.get_parent(fd.get_feed(fid)):
                self._update_dmx_front(fd.get_feed(fid))
        # TODO: add dmx for feeds of 3rd party nodes

    def _load_want_fltr(self):
        """
        Adds the dmx bytes of expected want requests to dmx-filter.
        By default blocks of all feeds stored in node can be requested and therefore
        for each feed a want dmx gets loaded into the filterbank.
        """
        self.want_fltr = {} # reset dictionary
        # TODO: only add wants for own and critical feeds (handle tree wants in tree)
        for fid in self.feed_mngr.listfeeds():
            self.want_fltr[ssb_util.to_hex(fid)] = dmx(fid + b'want')

    def _pack_want(self, feed):
        """Returns for given feed a want packet
        according to ssb protocol conventions.
        """
        want_dmx = dmx(feed.fid + b'want')
        seq = feed.front_seq + 1
        print('want: ' + ssb_util.to_hex(feed.fid) + ' - ' + str(seq))
        hash_pointer = fd.waiting_for_blob(feed)
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
        next_want = self.dmx_fltr.get_next_want_wire(self.feed_mngr, dmx)
        self.out_queue.append(0, (next_want, None))

    def _set_priority_in(self, buf, fid, in_queue):
        # It is assumed, only priorities of id feed packets are set here
        # Packets of trees are managed in tree specific functions
        if fid == self.config['admin']:
            in_queue.append(0, (buf, fid, self._handle_received_pkt))
        else:
            in_queue.append(2, (buf, fid, self._handle_received_pkt))

    def _handle_received_pkt(self, buf, fid, _, _2, _3, _4):
        feed = fd.get_feed(fid)
        if feed == None:
            print('incoming front error: feed not found')
            return

        if fd.waiting_for_blob(feed):
            success = fd.verify_and_append_blob(feed, buf)
            if success:
                self.update_dmx_front(feed)
            return success
        pkt = fd.verify_and_append_bytes(feed, buf)
        if pkt:
            self._update_dmx_front(feed)

        return pkt
        # TODO: add new front dmx

    def _handle_blob_receive(self, buf, fid, _1, _2, _3):
        """Blobs are written directly and not first appended to in queue."""
        # TODO: don't get feed from argument (not necessary)
        feed = fd.get_feed(fid)
        if fd.verify_and_append_blob(feed, buf):
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

        fid = buf[:32]
        feed = fd.get_feed(fid)
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
        self.out_queue.append(2, (fd.get_wire(feed, seq), neigh.face))


    def on_receive(self, buf, neigh):
        """If incoming packet dmx / hash is in filters, this function handles the
        packets appropriately. If not, the packet gets discarded."""
        # TODO: proper uncloaking
        dmx = buf[:7]
        self.in_queue_lock.acquire()
        for k, v in self.dmx_fltr:
            d, fct = v
            if d == dmx:
                print('received front dmx: ' + str(dmx))
                # self._handle_front_receive(buf, k)
                fct(buf, k, self.in_queue)
                self.in_queue_lock.release()
                return

        for k, v in self.want_fltr.items():
            if v == dmx:
                print('received want dmx: ' + str(dmx))
                self._handle_want_request(buf, neigh)
                self.in_queue_lock.release()
                return

        # check if incoming pkt is blob (automatically verified with hash)
        hash_ptr = hashlib.sha256(buf).digest()[:20]
        # if blobs and dmx handled separately, change filter bank here
        for k, v in self.dmx_fltr:
            d, fct = v
            if d == hash_ptr:
                print('received expected blob')
                # self._handle_blob_receive(buf, k)
                fct(buf, k, self.in_queue)

        print('dmx not expected: ' + str(dmx))
        self.in_queue_lock.release()

    def try_append(self, priority, buf, fid, fct_handle_receive):
        self.append_lock.acquire()
        if sys.implementation == 'micropython':
            gc.collect() # is this necessary?
        self.in_queue_lock.acquire()
        pkt = fct_handle_receive(buf, fid, self.in_queue, self.feed_mngr, self.dmx_fltr, self.want_fltr)
        self.in_queue_lock.release()
        if pkt == True:
            print('new blob was appended')
        elif pkt:
            print('new packet was appended: ' + str(buf[:7]))
            # TODO: check for other tree packets + handle feed creation fail
            if pkt.pkt_type == packet.PacketType.mk_fork_tree:
                # TODO: handle critical feeds that are not admin
                is_critical = fid == self.config['admin']
                tree = fork_tree.load_fork_tree(pkt.payload[:32], self.feed_mngr, self.dmx_fltr, self.want_fltr, self.config, False, is_critical)
                self.feed_forest.add_subtree(tree)
            if pkt.pkt_type == packet.PacketType.mk_session_tree:
                print('make session tree')
                is_critical = fid == self.config['admin']
                tree = session_tree.load_session_tree(pkt.payload[:32], self.feed_mngr, self.dmx_fltr, self.want_fltr, self.config, False, is_critical)
                self.feed_forest.add_subtree(tree)

            # only remove pkt from priority queue after verify
            # feed = self.feed_mngr.get_feed(fid)
        else:
            print('packet could not be appended')
        self.in_queue.remove(priority, (buf, fid, fct_handle_receive))
        self.append_lock.release()

    def ressource_manager_loop(self):
        # TODO: handle want / out / in queues individually for a given amount of time
        # TODO: Log time spent for different queues for optimizing
        while True:
            # --------- want broadcast ---------------
            next_want = self.dmx_fltr.get_next_want_wire(self.feed_mngr, dmx)
            if next_want:
                for f in self.faces:
                    f.enqueue(next_want)

            # --------- append next pkt ---------------
            self.append_lock.acquire()
            self.append_lock.release()
            next_in = self.in_queue.next()
            if next_in:
                priority, (buf, fid, fct_handle_receive) = next_in
                _thread.start_new_thread(self.try_append, (priority, buf, fid, fct_handle_receive))

            # --------- send next pkt ---------------
            next_out = self.out_queue.pop_next()

            # print(next_out)
            if next_out != None:
                pkt, face = next_out
                if pkt != None:
                    # print('send: ')
                    # print(pkt)
                    if not face:
                        for f in self.faces:
                            f.enqueue(pkt)
                    else:
                        face.enqueue(pkt)
            # TODO: check battery and decide
            time.sleep(4)

    def start(self):
        self.io_loop = io.IOLOOP(self.faces, self.on_receive)
        print('io loop created')
        _thread.start_new_thread(self.io_loop.run, tuple())
        _thread.start_new_thread(self.ressource_manager_loop, tuple())

        # keep main thread alive
        while True:
            time.sleep(2)