# -------------------------------------------------
# Implementation by Simon laube
# -------------------------------------------------

from tinyssb import ssb_util, packet
import hashlib

def _dmx(msg: bytes):
    return hashlib.sha256(msg).digest()[:7]

class ForkTree:

    def __init__(self, fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
        self.root_fid = fid # id of the root feed of this tree
        self.feeds = []
        self.is_valid = False
        self.has_ended = False
        self.is_owner = is_owner
        self.is_critical = is_critical

        # This is the relative front pos of the tree object,
        # not to be confused with the front seq of a feed.
        # If it is set to -1, no payload packet exists in the tree
        self.front_pos = -1
        self.load(feed_mngr, dmx_fltr, want_fltr, config)

    def demo_print(self, dict, current_f, feed_mngr):
        """Prints the tree and colors the requested packets."""
        string = '\nForkTree: \n\n'
        for i, f in enumerate(self.feeds):
            seq = -1
            if f.fid in dict.keys():
                seq = dict[f.fid]
            string += f.demo_print(seq, current_f == f) + '\n\n\n'
        return string
    
    def __str__(self):
        string = '\n\nForkTree: \n\n'
        for i, f in enumerate(self.feeds):
            string += f.__str__() + '\n\n\n'
        return string

    def load(self, feed_mngr, dmx_fltr, want_fltr, config):
        """Loads the feeds, and front position from feeds. If cache file available,
        use this to load tree."""
        # TODO: Maybe check first if tree has ended and act appropriately
        self.feeds = []
        next_feed = feed_mngr.get_feed(self.root_fid)
        if next_feed == None:
            next_feed = feed_mngr.create_feed(self.root_fid)
            print('root feed created because not yet in feed dir')
        while next_feed != None:
            # only add want if feed is own or or critical
            self._add_want_fltr(next_feed.fid, want_fltr)
            self.feeds.append(next_feed)
            if len(next_feed) >= 2: # at least one payload pkt appended
                next_fid = next_feed[2][:32] # get feed id of child feed (fork feed)
                next_feed = feed_mngr.get_feed(next_fid)
                continue
            break
        print(self)
        self.load_dmx(dmx_fltr, feed_mngr)

        if self._update_tree_validity(feed_mngr):
            print('loaded fork tree ' + str(ssb_util.to_hex(self.root_fid)))
        
    def load_dmx(self, dmx_fltr, feed_mngr):
        """Loads or resets the dmx values for this tree in the dmx filter."""
        # Add to dmx front filters if not owner of tree
        if self.is_owner:
            return
        cat = ssb_util.to_hex(self.root_fid)[:8] # category name for dmx of this tree
        dmx_fltr.reset_category(cat)
        if len(self.feeds) == 0:
            print('error in loading dmx for fork tree')
            return
        if len(self.feeds) == 1:
            dmx_fltr.append(cat, ssb_util.to_hex(self.feeds[-1].fid), self._next_dmx(self.feeds[-1]))
        else:
            if len(self.feeds[-1]) < 2: # last feed is emergency feed
                dmx_fltr.append(cat, ssb_util.to_hex(self.feeds[-1].fid), self._next_dmx(self.feeds[-1]))
                prev_feed = self.feeds[-2]
            else: # last feed is not emergency feed
                prev_feed = self.feeds[-1]
            prev_seq = len(prev_feed) + 1 # guarantees feed will be appended to dmx
            while prev_feed: # walk back fork path
                # next_feed is not yet complete up until fork
                if prev_seq > len(prev_feed):
                    dmx_fltr.append(cat, ssb_util.to_hex(prev_feed.fid), self._next_dmx(prev_feed))

                if len(prev_feed) > 2: # fork pkt exists
                    pkt = prev_feed[3]
                    prev_fid = pkt[4:36]
                    prev_seq = int.from_bytes(pkt[:4], 'big')
                    prev_feed = feed_mngr.get_feed(prev_fid)
                    continue
                if len(prev_feed) == 2: # no fork pkt exists
                    break
                print('error in tree structure')
                break
        # TODO: Later maybe load from cache file if available
    
    def _get_abs_pos(self, pos, feed_mngr):
        """Returns the feed and sequence number of the given tree position.
        The given position is the relative position of the packet in the
        packet chain (all non reverted payload packets over all feeds)."""
        # curr_pos will be decreased until equal to the position we look for
        if not self.is_valid:
            print('cannot get abs position because tree is not vaild (yet)')
        curr_pos = self.front_pos
        if pos > curr_pos:
            print('couldn\'t retrieve abs pos: position is larger than newest position')
            return None
        curr_feed = self.feeds[-2] # second last feed (last is next emergency feed)
        curr_seq = len(curr_feed) # absolute seq in current feed
        while curr_feed != self.feeds[0]:
            pkts_in_feed = curr_seq - 3 # all tree pkts in feed older than fork pos
            if curr_pos - pkts_in_feed < pos: # packet is in current feed
                return (curr_feed.fid, curr_seq - (curr_pos - pos))
            # set (virtual tree) curr_pos to pos of fork position in previous feed
            curr_pos -= pkts_in_feed
            
            # get fork seq in previouse feed from fork packet
            curr_seq = int.from_bytes(curr_feed.get(3)[0:4], 'big')
            
            # get previouse feed from fork packet
            curr_feed = feed_mngr.get_feed(curr_feed.get(3)[4:36])
        return (curr_feed.fid, pos + 4)
    
    def _set_priority_in(self, buf, fid, in_queue):
        """Sets priority between 0 and 3 and puts it into the in-queue."""
        admin = 2 # if is critical, priorities 0 / 1 else priorities 2 / 3
        if self.is_critical:
            admin = 0
        if ssb_util.from_hex(fid) == self.feeds[-1].fid: # emergency feed
            priority = 0
        elif ssb_util.from_hex(fid) in [f.fid for f in self.feeds]: # any feed in tree
            priority = 1
        else:
            print('given feed not present in tree')
            return
        in_queue.append(priority + admin, (buf, ssb_util.from_hex(fid), self._handle_received_pkt))

    def _handle_received_pkt(self, buf, fid, in_queue, feed_mngr, dmx_fltr, want_fltr):
        """If packet is verified, it is appended to the tree and the tree is updated."""
        if fid not in [f.fid for f in self.feeds]:
            print('given feed not in feed list of this tree')
            return None

        feed = feed_mngr.get_feed(fid)
        if feed.waiting_for_blob():
            return feed.verify_and_append_blob(buf)
        else:
            pkt = feed.verify_and_append_bytes(buf)

            print(self)
            if pkt:
                if buf[7:8] == packet.PacketType.mkchild:
                    print('try create emergency feed')
                    # TODO: potential issue: if device crashes after append, no feed created
                    f = feed_mngr.create_feed(buf[8:40])
                    self._add_want_fltr(f.fid, want_fltr)
                    self.feeds.append(f)
                    print('emergency feed created')
                self.load_dmx(dmx_fltr, feed_mngr)

                if not self.is_valid or fid == self.feeds[-1]:
                    self._update_tree_validity(feed_mngr)

            return pkt


    def _next_dmx(self, feed):
        """Returns the next dmx, next hash pointer or None for given feed"""
        next_blob_ptr = feed.waiting_for_blob()
        if next_blob_ptr:
            return (next_blob_ptr, self._set_priority_in)
        dmx = feed.get_next_dmx()
        if dmx:
            return (dmx, self._set_priority_in)
        print('could not load dmx front ' + str(ssb_util.to_hex(feed.fid)))
        
    def _update_tree_validity(self, feed_mngr):
        """Returns True if path exists from last packet in tree to any
        packet in the first feed and the last feed is an emergency feed"""
        # get number of packets by walking backwards via the fork pointers
        if len(self.feeds) < 2:
            print('fork tree is not valid at the moment')
            self.is_valid = False
            return False
        curr_feed = self.feeds[-2]
        curr_seq = len(self.feeds[-2])
        while curr_feed != self.feeds[0]:
            self.front_pos += (curr_seq - 4)
            if len(curr_feed) < 3:
                print('tree is not valid (yet) because no fork pkt present')
                return False
            curr_seq = int.from_bytes(curr_feed.get(3)[0:4], 'big')
            curr_feed = feed_mngr.get_feed(curr_feed.get(3)[4:36])
        if len(self.feeds[-1]) != 1:
            print('tree is not valid (yet) because no emergency feed present')
            return False
        self.is_valid = True
        return True
    
    def append_bytes(self, payload: bytes) -> bool:
        """Appends payload at the end of the tree and returns True if successful."""
        success = self.feeds[-2].append_bytes(payload)
        if success:
            self.front_pos += 1
        return success
    
    def append_blob(self, payload: bytes):
        """Appends blob at end of tree and returns True on success."""
        return self.feeds[-2].append_blob(payload)
        
    
    def fork_at(self, pos, feed_mngr, config) -> bool:
        """Creates a new emergency feed at the end of the tree and appends
        a fork pkt in the now second last feed. Only used by producer."""
        if pos < 0 or pos >= self.front_pos:
            print('could not fork (front_pos: ' + str(self.front_pos) + ' given pos: ' + str(pos) + ')')
            return False
        # TODO: give dmx + want filter bank and update when fork created
        forked_fid, forked_seq = self._get_abs_pos(pos, feed_mngr)
        fork_fid = self.feeds[-1].fid
        fork_feed = feed_mngr.get_feed(fork_fid)
        next_emergency_feed = prepare_fork_feed(fork_fid, feed_mngr, config)

        seq, prev_mid = fork_feed.get_front()
        sk = ssb_util.from_hex(config['child_feeds'][ssb_util.to_hex(fork_fid)])
        fork_pkt = packet.create_fork_pkt(fork_fid,
                                          (seq + 1).to_bytes(4, 'big'),
                                          prev_mid,
                                          forked_seq.to_bytes(4, 'big'),
                                          forked_fid,
                                          sk)
        fork_feed.append_pkt(fork_pkt)
        self.feeds.append(next_emergency_feed) # update feed list
        self.front_pos = pos
        return True
    
    def _add_want_fltr(self, fid, want_fltr):
        """Adds a want filter if this node owns the feed or the feed is critical.
        """
        if self.is_owner or self.is_critical:
            want_fltr[ssb_util.to_hex(fid)] = _dmx(fid + b'want')
   
    def _collect(self, feed_mngr):
        pass

    def clear_tree(self):
        """Deletes all feeds and cache of this tree"""
        pass

def prepare_fork_feed(feed_id, feed_mngr, config):
    """Creates the next emergency feed of a fork tree."""
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_child_feed(feed_id, pk, sk) 
    return f

def create_fork_tree(feed_id, feed_mngr, dmx_fltr, want_fltr, config):
    """Creates + appends a mk_fork_tree packet to given feed, creates a
    subtree-root-feed and returns a newly created ForkTree object."""
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_tree_root_feed(ssb_util.from_hex(feed_id), pk, sk, packet.PacketType.mk_fork_tree)

    prepare_fork_feed(pk, feed_mngr, config)
    ct = ForkTree(f.fid, feed_mngr, dmx_fltr, want_fltr, config, True, True)

    # TODO: dummy packet, maybe change to something more useful later
    ct.feeds[-2].append_bytes(b'') 

    return ct

def load_fork_tree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
    """Creates root feed for fork feed after mk_fork_tree pkt
    has been received."""    

    ct = ForkTree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical)
    return ct