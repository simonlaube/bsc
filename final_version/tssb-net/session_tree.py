# -------------------------------------------------
# Implementation by Simon laube
# -------------------------------------------------

from tinyssb import ssb_util, packet
import hashlib

def _dmx(msg: bytes):
    return hashlib.sha256(msg).digest()[:7]

class SessionTree:

    def __init__(self, fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical, l=6):
        self.max_length = l
        self.max_sessions_stored = 3
        self.root_fid = fid
        self.cache = feed_mngr.load_tree_cache(self.root_fid)
        self.feeds = []
        self.session_feeds = []
        self.is_valid = False
        self.is_owner = is_owner
        self.is_critical = is_critical
        self.load(feed_mngr, dmx_fltr, want_fltr, config)
        # for demo purposes do not delete feeds in admin
        if self.is_critical:
            self._collect(feed_mngr)
        print(self.__str__(feed_mngr))
    
    def demo_print(self, dict, current_f, feed_mngr):
        """Prints the tree and colors the requests."""
        res = 'Session Feed \n\n'
        seq = -1
        if self.root_fid in dict.keys() != None:
            seq = dict[self.root_fid]
        res += feed_mngr.get_feed(self.root_fid).demo_print(seq, current_f.fid == self.root_fid) + '\n\n'
        for f in self.feeds:
            if f == None:
                continue
            seq = -1
            if f.fid in dict.keys() != None:
                seq = dict[f.fid]
            tmp = f.demo_print(seq, current_f == f)
            p = f.get_prev()
            while p:
                p = feed_mngr.get_feed(p)
                if p == None:
                    break
                seq = -1
                if p.fid in dict.keys() != None:
                    seq = dict[p.fid]
                    
                tmp = p.demo_print(seq, current_f == p) + ' -> \n' + tmp
                p = p.get_prev()
            res += tmp + "\n\n\n"
        return res
        

    def __str__(self, feed_mngr):
        res = 'Session Feed \n\n'
        res += feed_mngr.get_feed(self.root_fid).__str__() + '\n\n'
        for f in self.feeds:
            tmp = f.__str__()
            if f == None:
                continue
            p = f.get_prev()
            while p:
                p = feed_mngr.get_feed(p)
                if p == None:
                    break
                tmp = p.__str__() + ' -> \n' + tmp
                p = p.get_prev()
            res += tmp + "\n\n\n"
        return res

    def load(self, feed_mngr, dmx_fltr, want_fltr, config):
        """Loads the feeds from the root feed."""
        self.feeds = []
        root_feed = feed_mngr.get_feed(self.root_fid)
        if root_feed == None:
            root_feed = feed_mngr.create_feed(self.root_fid)
            print('root feed created because not yet in feed dir')
        self._add_want_fltr(self.root_fid, want_fltr)
        if len(root_feed) < 2:
            print('session feed not created yet')
            self.load_dmx(dmx_fltr, feed_mngr)
            return

        # initialize next_feed to highest level ptr-feed
        next_fid = root_feed[-1][:32]
        next_feed = feed_mngr.get_feed(next_fid)

        # load pointer feeds
        for i in range(0, len(root_feed) - 1):
            self.feeds.append(None)
        layer = len(root_feed) - 2
        while next_feed != None and layer > 0:
            self.feeds[layer] = next_feed
            layer -= 1
            self._add_want_fltr(next_feed.fid, want_fltr)
            
            if len(next_feed) < 2:
                self.load_dmx(dmx_fltr, feed_mngr)
                print('loading via ptr feeds ended before reaching session feed')
                return

            next_fid = next_feed[-1][:32] # get newest pointer
            next_feed = feed_mngr.get_feed(next_fid)

        if next_feed == None:
            next_feed = feed_mngr.create_feed(next_fid)
            feed_mngr.append_to_tree_cache(self.root_fid, next_feed.fid)
            self._add_want_fltr(next_feed.fid, want_fltr)
            if layer >= 0:
                self.feeds[layer] = next_feed
            else:
                print('error: loading feed list')
        else:
            self.feeds[0] = next_feed

        # load session feeds
        self._load_session_feeds(feed_mngr, want_fltr)
        self.load_dmx(dmx_fltr, feed_mngr)
    
    def _load_session_feeds(self, feed_mngr, want_fltr):
        """Starting at the newest session feed it tries to load
        max_sessions_stored session feeds via the prev feed pointers."""
        session_fid = self.feeds[0].fid
        pos = 0
        self.session_feeds = []
        while session_fid != None and pos < self.max_sessions_stored:
            session_feed = feed_mngr.get_feed(session_fid)
            if session_feed == None:
                session_feed = feed_mngr.create_feed(session_fid)
                feed_mngr.append_to_tree_cache(self.root_fid, session_feed.fid)

            self._add_want_fltr(session_feed.fid, want_fltr)
            self.session_feeds.append(session_feed)
            session_fid = session_feed.get_prev()
            pos += 1
        
        
    def load_dmx(self, dmx_fltr, feed_mngr):
        """Adds the current dmx values to the dmx filter."""
        if self.is_owner:
            return
        cat = ssb_util.to_hex(self.root_fid)[:8]
        dmx_fltr.reset_category(cat)
        dmx_fltr.append(cat, ssb_util.to_hex(self.root_fid), self._next_dmx(feed_mngr.get_feed(self.root_fid)))
        if len(self.feeds) == 0:
            return

        for f in self.feeds[1:]:
            if f == None:
                continue
            dmx_fltr.append(cat, ssb_util.to_hex(f.fid), self._next_dmx(f))
        for f in self.session_feeds:
            dmx_fltr.append(cat, ssb_util.to_hex(f.fid), self._next_dmx(f))

    def _set_priority_in(self, buf, fid, in_queue):
        """Sets a priority between 0 and 3 and appends it to the in_queue."""
        admin = 2 # if is critical, priorities 0 / 1 else priorities 2 / 3
        priority = 1
        if self.is_critical:
            admin = 0
        if ssb_util.from_hex(fid) in [f.fid for f in self.feeds if f != None]:
            priority = 0
        in_queue.append(priority + admin, (buf, ssb_util.from_hex(fid), self._handle_received_pkt))
    
    def _handle_received_pkt(self, buf, fid, in_queue, feed_mngr, dmx_fltr, want_fltr):
        """Tries to append the packet. If successful, the dmx values get updated."""
        append_type = ''
        if fid == self.root_fid:
            append_type = 'root'
            print('try append to root feed')

        elif fid in [f.fid for f in self.session_feeds]:
            append_type = 'session'
            print('try append to session feed')
            
        elif fid in [f.fid for f in self.feeds[1:] if f != None]:
            append_type = 'ptr'
            print('try append to ptr-feeds')
            
        else:
            append_type = 'background'
            print('packet for prev feed in tree received')        
        
        feed = feed_mngr.get_feed(fid)
        if feed.waiting_for_blob():
            return feed.verigy_and_append_blob(buf)
        else:
            pkt = feed.verify_and_append_bytes(buf)
        if pkt:
            if append_type == 'background':
                self.load_dmx(dmx_fltr, feed_mngr)
                return pkt
            # create new ptr layer
            if pkt.pkt_type == packet.PacketType.mkchild:
                fd = feed_mngr.create_feed(buf[8:40])
                feed_mngr.append_to_tree_cache(self.root_fid, fd.fid)
                if len(self.feeds) == 0:
                    self.session_feeds.append(fd)
                self.feeds.append(fd)
                print('created pointer feed')
            # create prev session feed if new contn pkt received
            elif pkt.pkt_type == packet.PacketType.iscontn:
                if fid in [f.fid for f in self.session_feeds]:
                    self._load_session_feeds(feed_mngr, want_fltr)
            # create continuation feed
            elif pkt.pkt_type == packet.PacketType.contdas:
                fd = feed_mngr.create_feed(buf[8:40])
                if fd != None:
                    feed_mngr.append_to_tree_cache(self.root_fid, fd.fid)
                for i, f in enumerate(self.feeds):
                    if f.fid == fid:
                        print('replaced ptr feed in layer ' + str(i))
                        self.feeds[i] = fd
                        if i == 0:
                            self._load_session_feeds(feed_mngr, want_fltr)                            
                print('created continuation feed')
            # add ptr packet and create feed if not yet present
            elif append_type == 'ptr':
                # print('new ptr feed: ' + str(buf[8:40]))
                fd = feed_mngr.get_feed(buf[8:40])
                if fd == None: # update new pointer feeds
                    fd = feed_mngr.create_feed(buf[8:40])
                    if fd == None:
                        print(ssb_util.to_hex(buf[8:40]))
                    feed_mngr.append_to_tree_cache(self.root_fid, fd.fid)
                    for i, f in enumerate(self.feeds):
                        if f == feed:
                            self._add_want_fltr(fd.fid, want_fltr)
                            self.feeds[i - 1] = fd
                            if i - 1 == 0:
                                self._load_session_feeds(feed_mngr, want_fltr)
                print('new pointer was appended')
            elif append_type == 'session':
                print('new pkt payload was appended')
            else:
                print('should not end up here')

            self.load_dmx(dmx_fltr, feed_mngr)
            print(self.__str__(feed_mngr))
        return pkt

    def _next_dmx(self, feed):
        """Returns the next dmx value, hash pointer or None for given feed."""
        next_blob_ptr = feed.waiting_for_blob()
        if next_blob_ptr:
            return (next_blob_ptr, self._set_priority_in)
        dmx = feed.get_next_dmx()
        if dmx:
            return (dmx, self._set_priority_in)
        print('could not load dmx front')
            
    def append_bytes(self, payload: bytes, feed_mngr, dmx_fltr, want_fltr, config):
        """Appends bytes to the session layer and updates ptr feeds.
           (only used by producer node)"""
        assert len(payload) <= 48
        if len(self.feeds) == 0:
            sk, pk = config.new_child_keypair(True)
            f = feed_mngr.create_child_feed(self.root_fid, pk, sk)
            feed_mngr.append_to_tree_cache(self.root_fid, f.fid)
            self.feeds.append(f)
            print('session feed created')
        contn_feed = self._append_to_layer(payload, 0, feed_mngr, config)
        if contn_feed:
            self.feeds[0] = contn_feed
        layer = 1
        while contn_feed:
            if len(feed_mngr.get_feed(self.root_fid)) - 2 < layer: # create new (higher) pointer layer
                sk, pk = config.new_child_keypair(True)
                ptr_feed = feed_mngr.create_child_feed(self.root_fid, pk, sk)
                feed_mngr.append_to_tree_cache(self.root_fid, ptr_feed.fid)
                self.feeds.append(ptr_feed)
            payload = contn_feed.fid
            contn_feed = self._append_to_layer(payload, layer, feed_mngr, config)
            layer += 1
        self.load(feed_mngr, dmx_fltr, want_fltr, config)
               
    def _append_to_layer(self, payload, layer, feed_mngr, config):
        """Adds packet to given session / head-ptr layer.
        Returns contn feed if new contn feed had to be created, else None."""
        feed = self.feeds[layer]
        if len(feed) > self.max_length: # create contn feed first
            sk, pk = config.new_child_keypair(True)
            contn_feed = feed_mngr.create_contn_feed(feed.fid, pk, sk)
            feed_mngr.append_to_tree_cache(self.root_fid, contn_feed.fid)
            contn_feed.append_bytes(payload)
            self.feeds[layer] = contn_feed
            return contn_feed
        else: # no contn feed needed
            feed.append_bytes(payload)

    def _add_want_fltr(self, fid, want_fltr):
        """only add want if this is a feed that has to be propagated"""
        if self.is_owner or self.is_critical:
            want_fltr[ssb_util.to_hex(fid)] = _dmx(fid + b'want')
    
    # deletion not implemented yet
    def _collect(self, feed_mngr):
        """Deletes all feeds that are not used anymore."""
        # TODO: delete all feeds that are not used anymore
        # delete want / dmx when deleting feed
        sess = [f.fid for f in self.session_feeds]
        feeds = [f.fid for f in self.feeds if f != None]
        for fid in self.cache:
            f = ssb_util.from_hex(fid)
            if f not in sess and f not in feeds:
                feed_mngr.delete_from(0, ssb_util.from_hex(fid))
            

def create_session_tree(feed_id, feed_mngr, dmx_fltr, want_fltr, config, l=6):
    sk, pk = config.new_child_keypair(True)
    f = feed_mngr.create_tree_root_feed(ssb_util.from_hex(feed_id), pk, sk, packet.PacketType.mk_session_tree)
    
    st = SessionTree(f.fid, feed_mngr, dmx_fltr, want_fltr, config, True, True, l)
    return st

def load_session_tree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
    st = SessionTree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical)
    return st