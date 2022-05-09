from microssb import ssb_util, packet
import config
import pure25519
import hashlib

def _dmx(msg: bytes):
    return hashlib.sha256(msg).digest()[:7]

class FeedForest:

    def __init__(self, feed_mngr, dmx_fltr, want_fltr, conf):
        self.trees = {}

        for feed in feed_mngr.feeds:
            # find ID feeds and add as tree to tree dict
            # ID feeds are the only feeds that are not child and not continuation
            if not feed.get_prev() and not feed.get_parent():
                # print(ssb_util.to_hex(feed.fid))
                # self.trees[ssb_util.to_hex(feed.fid)] = feed
                self.trees[ssb_util.to_hex(feed.fid)] = (self.load_subtrees(feed,
                                                         feed_mngr,
                                                         dmx_fltr,
                                                         want_fltr,
                                                         conf))
    
    def load_subtrees(self, feed, feed_mngr, dmx_fltr, want_fltr, conf):
        subtrees = []
        self.is_owner = False
        self.is_critical = False
        if ssb_util.to_hex(feed.fid) in conf['child_feeds'] or ssb_util.to_hex(feed.fid) == conf['feed_id']:
            self.is_owner = True
        # TODO: Maybe not only admin feeds are critical, also others apply...
        if feed.fid == conf['admin']:
            self.is_critical = True
        for i in range(1, feed.front_seq + 1):
            type = feed.get_type(i) 
            if type == packet.PacketType.mk_continuous_tree:
                # TODO: check for type of subtree
                ct = load_continuous_tree(feed[i][:32],
                                    feed_mngr,
                                    dmx_fltr,
                                    want_fltr,
                                    config,
                                    self.is_owner,
                                    self.is_critical)
                subtrees.append(ct)

    def add_subtree(self, subtree):
        self.trees[ssb_util.to_hex(subtree.root_fid)] = subtree

class ContinuousTree:

    def __init__(self, fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
        self.root_fid = fid # id of the root feed of this tree
        self.feeds = []
        self.is_valid = False
        self.has_ended = False
        self.is_owner = is_owner
        self.is_critical = is_critical
        # this is the relative front pos of the tree object
        # not to be confused with the front seq of a feed
        self.front_pos = -1
        self.load(feed_mngr, dmx_fltr, want_fltr, config)
    
    def __str__(self):
        string = '/---------------------------------------------------'
        string += '\nContinuousTree: \n\n'
        for i, f in enumerate(self.feeds):
            string += f.__str__() + '\n\n'
        string += '\---------------------------------------------------'
        return string
    
    def _get_abs_pos(self, pos, feed_mngr):
        """Returns the feed and sequence number of given tree position."""
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

    def _handle_received_pkt(self, buf, fid, in_queue, feed_mngr):
        # TODO: implement (if fork pkt -> create fork, remove dmx of now 3rd last feed)
        if fid not in [f.fid for f in self.feeds]:
            print('given feed not in feed list of this tree')
            return None
        pkt = self.verify_and_append_bytes(buf, fid)
        if not pkt:
            return None
        if pkt.pkt_type == packet.PacketType.mkchild and int.from_bytes(pkt.seq, 'big') != 2:
            # TODO: This may be implemented as a feature later.
            # When forked before this packed later (mk child should be reverted),
            # consider to remove all feeds that followed (including) this child feed
            print('can\'t make child inside tree, packet appended anyway')
            return pkt
        if pkt.pkt_type == packet.PacketType.mkchild:
            f = feed_mngr.create_child_feed(fid, pkt[:32])
            # TODO: remove front dmx of all feeds that are not needed anymore
            if f:
                print('emergency feed created')

        return pkt
        # TODO: return pkt if appended

    def load(self, feed_mngr, dmx_fltr, want_fltr, config):
        """Loads the feeds, and front position from feeds. If cache file available,
        use this to load tree."""
        # TODO: Maybe check first if tree has ended and act appropriately
        next_feed = feed_mngr.get_feed(self.root_fid)
        if next_feed == None:
            next_feed = feed_mngr.create_feed(self.root_fid)
            print('root feed created because not yet in feed dir')
        while next_feed != None:
            # only add want if feed is own or or critical
            if self.is_owner or self.is_critical:
                want_fltr[ssb_util.to_hex(next_feed.fid)] = _dmx(next_feed.fid + b'want')
            self.feeds.append(next_feed)
            if len(next_feed) >= 2: # at least one payload pkt appended
                next_fid = next_feed[2][:32] # get feed id of child feed (fork feed)
                next_feed = feed_mngr.get_feed(next_fid)
                continue
            break
        
        # Add to dmx front filters if not owner of tree
        if not self.is_owner:
            if len(self.feeds) == 1:
                newest_feeds = [self.feeds[-1]]
            elif len(self.feeds) == 0:
                print('error: at least one feed must be present')
                return
            else:
                newest_feeds = [self.feeds[-2], self.feeds[-1]]
            
            for f in newest_feeds:
                next_blob_ptr = f.waiting_for_blob()
                if next_blob_ptr:
                    dmx_fltr[ssb_util.to_hex(f.fid)] = (next_blob_ptr, self._set_priority_in)
                    continue
                dmx = f.get_next_dmx()
                if dmx:
                    dmx_fltr[ssb_util.to_hex(f.fid)] = (dmx, self._set_priority_in)
                else:
                    print('could not load dmx front ' + str(ssb_util.to_hex(f.fid)))

        if self._update_tree_validity(feed_mngr):
            print('loaded continuous tree ' + str(ssb_util.to_hex(self.root_fid)))

        # TODO: Later maybe load from cache file if available
    
    def _update_tree_validity(self, feed_mngr):
        # get number of packets by walking backwards via the fork pointers
        print(self)
        if len(self.feeds) < 2:
            print('continuous tree is not valid at the moment')
            self.is_valid = False
            return False
        curr_feed = self.feeds[-2]
        curr_seq = len(self.feeds[-2])
        while curr_feed != self.feeds[0]:
            self.front_pos += (curr_seq - 4)
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
    
    def verify_and_append_bytes(self, pkt_wire: bytes, fid = None) -> bool:
        if self.has_ended:
            return False        

        # if only the first feed available or new emergency -> fid != None
        if fid == self.feeds[-1].fid:
            success = self.feeds[-1].verify_and_append_bytes(pkt_wire)

        else:
            success = self.feeds[-2].verify_and_append_bytes(pkt_wire)
            # TODO: check if pkt ends tree / forks / ...
            # TODO: update dmx
        return success
    
    def end_tree(self):
        pass

    def clear_tree(self):
        """Deletes all feeds and cache of this tree"""
        pass

def prepare_fork_feed(feed_id, feed_mngr, config):
    # TODO: give dmx + want filter bank and update when fork created
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_child_feed(feed_id, pk, sk) 
    return f

def create_continuous_tree(feed_id, feed_mngr, dmx_fltr, want_fltr, config):
    # TODO: give dmx + want filter bank and update when fork created
    """Creates + appends a mk_continuous_tree packet to given feed, creates a
    subtree-root-feed and returns secret key, public key as well as a 
    newly created ContinuousTree object."""
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_subtree_root_feed(ssb_util.from_hex(feed_id), pk, sk, packet.PacketType.mk_continuous_tree)

    prepare_fork_feed(pk, feed_mngr, config)
    ct = ContinuousTree(f.fid, feed_mngr, dmx_fltr, want_fltr, config, True, True)

    # TODO: dummy packet, maybe change to something more useful later
    seq, prev_mid = f.get_front()
    ct.feeds[-2].append_bytes(b'') 

    return (sk, pk, ct)

def load_continuous_tree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical):
    """Creates root feed for continuous feed after mk_continuous_tree pkt
    has been received."""    

    ct = ContinuousTree(fid, feed_mngr, dmx_fltr, want_fltr, config, is_owner, is_critical)
    return ct