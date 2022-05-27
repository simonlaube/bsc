from microssb import ssb_util, packet
import pure25519
import hashlib

def _dmx(msg: bytes):
    return hashlib.sha256(msg).digest()[:7]

# TODO: Add cache file containing all feeds created for this tree
# remove feeds that are not needed anymore

class SessionTree:

    def __init__(self, fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
        self.max_length = 4 # this can be changed to much higher number
        self.max_sessions_stored = 3
        self.root_fid = fid
        self.feeds = []
        self.session_feeds = []
        self.is_valid = False
        # has_ended = False
        self.is_owner = is_owner
        self.is_critical = is_critical
        self.load(feed_mngr, dmx_fltr, want_fltr, config)
        print(self.__str__(feed_mngr))

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
            # feed = feed_mngr.get_feed(root_feed[i + 2][:32])
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
            self._add_want_fltr(next_feed.fid, want_fltr)
            if layer >= 0:
                self.feeds[layer] = next_feed
            else:
                print('error: loading feed list')
        else:
            self.feeds[0] = next_feed

        # load session feeds
        session_feed = self.feeds[0]
        pos = 0
        while session_feed != None and pos < self.max_sessions_stored - 1:
            self._add_want_fltr(session_feed.fid, want_fltr)
            self.session_feeds.append(session_feed)
            session_fid = session_feed.get_prev()
            if session_fid == None:
                break
            session_feed = feed_mngr.get_feed(session_fid)
            if session_feed == None:
                session_feed = feed_mngr.create_feed(session_fid)
            pos += 1

        self.load_dmx(dmx_fltr, feed_mngr)
        
    def load_dmx(self, dmx_fltr, feed_mngr):
        # TODO: ADD DMX FOR SESSION LIST AND FEED LIST
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
        admin = 2 # if is critical, priorities 0 / 1 else priorities 2 / 3
        if self.is_critical:
            admin = 0
        if ssb_util.from_hex(fid) == self.root_fid: # root feed
            priority = 0
        elif ssb_util.from_hex(fid) == self.feeds[0].fid: # session feed
            priority = 0
        elif ssb_util.from_hex(fid) in [f.fid for f in self.feeds]: # ptr-feed
            priority = 1
        for f in self.session_feeds:
            if f.fid == ssb_util.from_hex(fid):
                priority = 0
        in_queue.append(priority + admin, (buf, ssb_util.from_hex(fid), self._handle_received_pkt))
    
    def _handle_received_pkt(self, buf, fid, in_queue, feed_mngr, dmx_fltr, want_fltr):
        append_type = ''
        if fid == self.root_fid:
            append_type = 'root'
            print('try append to root feed')

        elif fid in [f.fid for f in self.session_feeds]:
            append_type = 'session'
            print('try append to session feed')
            
        elif fid in [f.fid for f in self.feeds[1:]]:
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
                if len(self.feeds) == 0:
                    self.session_feeds.append(fd)
                self.feeds.append(fd)
                print('created pointer feed')
            # create continuation feed
            elif pkt.pkt_type == packet.PacketType.contdas:
                fd = feed_mngr.create_feed(buf[8:40])
                for i, f in enumerate(self.feeds):
                    print('replaced ptr feed in layer ' + str(i))
                    if f.fid == fid:
                        print('appended feed to list')
                        self.feeds[i] = fd
                print('created continuation feed')
            # add ptr packet and create feed if not yet present
            elif append_type == 'ptr':
                print('new ptr feed: ' + str(buf[8:40]))
                fd = feed_mngr.get_feed(buf[8:40])
                if fd == None: # update new pointer feeds
                    fd = feed_mngr.create_feed(buf[8:40])
                    for i, f in enumerate(self.feeds):
                        if f == feed:
                            self._add_want_fltr(fd.fid, want_fltr)
                            self.feeds[i - 1] = fd
                            if i - 1 == 0:
                                self.session_feeds = []
                                session_feed = self.feeds[0]
                                pos = 0
                                while session_feed != None and pos < self.max_sessions_stored - 1:
                                    self.session_feeds.append(session_feed)
                                    session_fid = session_feed.get_prev()
                                    if session_fid == None:
                                        break
                                    session_feed = feed_mngr.get_feed(session_fid)
                                    if session_feed == None:
                                        session_feed = feed_mngr.create_feed(session_fid)
                                    pos += 1
                print('new pointer was appended')
            elif append_type == 'session':
                print('new pkt payload was appended')
            else:
                print('should not end up here')
            # create prev session feed if new contn pkt received
            if pkt.pkt_type == packet.PacketType.iscontn and fid in [f.fid for f in self.session_feeds]:
                session_feed = self.feeds[0]
                pos = 0
                while session_feed != None and pos < self.max_sessions_stored:
                    self.session_feeds.append(session_feed)
                    session_fid = session_feed.get_prev()
                    if session_fid == None:
                        break
                    session_feed = feed_mngr.get_feed(session_fid)
                    if session_feed == None:
                        session_feed = feed_mngr.create_feed(session_fid)
                    pos += 1


            self.load_dmx(dmx_fltr, feed_mngr)
            print(self.__str__(feed_mngr))
            print(dmx_fltr)
        return pkt

    def _next_dmx(self, feed):
        next_blob_ptr = feed.waiting_for_blob()
        if next_blob_ptr:
            return (next_blob_ptr, self._set_priority_in)
        dmx = feed.get_next_dmx()
        if dmx:
            return (dmx, self._set_priority_in)
        print('could not load dmx front')
    # TODO NEXT: def _set_priority_in()

            
    def append_bytes(self, payload: bytes, feed_mngr, config):
        """Appends bytes to the session layer and updates ptr feeds.
           (only used by producer node)"""
        if len(self.feeds) == 0:
            sk, pk = config.new_child_keypair(True)
            f = feed_mngr.create_child_feed(self.root_fid, pk, sk)
            self.feeds.append(f)
            print('session feed created')
        contn_feed = self._append_to_layer(payload, 0, feed_mngr, config)
        # TODO: still reference prev feed...?
        if contn_feed:
            self.feeds[0] = contn_feed
        layer = 1
        while contn_feed:
            if len(feed_mngr.get_feed(self.root_fid)) - 2 < layer: # create new (higher) pointer layer
                sk, pk = config.new_child_keypair(True)
                ptr_feed = feed_mngr.create_child_feed(self.root_fid, pk, sk)
                self.feeds.append(ptr_feed)
            payload = contn_feed.fid
            contn_feed = self._append_to_layer(payload, layer, feed_mngr, config)
            layer += 1
               
    def _append_to_layer(self, payload, layer, feed_mngr, config):
        """Adds packet to given session / head-ptr layer.
        Returns contn feed if new contn feed had to be created, else None."""
        feed = self.feeds[layer]
        if len(feed) > self.max_length: # create contn feed first
            # TODO: maybe add old feed to list that deletes feeds later...
            sk, pk = config.new_child_keypair(True)
            contn_feed = feed_mngr.create_contn_feed(feed.fid, pk, sk)
            contn_feed.append_bytes(payload)
            self.feeds[layer] = contn_feed
            return contn_feed
        else: # no contn feed needed
            feed.append_bytes(payload)

    def _add_want_fltr(self, fid, want_fltr):
        # only add want if this is a feed that has to be propagated
        if self.is_owner or self.is_critical:
            want_fltr[ssb_util.to_hex(fid)] = _dmx(fid + b'want')
    
    def collect(self):
        # TODO: delete all feeds that are not used anymore
        # delete want / dmx when deleting feed
        pass
            

def create_session_tree(feed_id, feed_mngr, dmx_fltr, want_fltr, config):
    sk, pk = config.new_child_keypair(True)
    f = feed_mngr.create_tree_root_feed(ssb_util.from_hex(feed_id), pk, sk, packet.PacketType.mk_session_tree)
    
    st = SessionTree(f.fid, feed_mngr, dmx_fltr, want_fltr, config, True, True)
    return st

def load_session_tree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
    st = SessionTree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical)
    return st