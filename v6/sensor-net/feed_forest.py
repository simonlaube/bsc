from microssb import ssb_util, packet
import config
import pure25519

class FeedForest:

    def __init__(self, feed_mngr):
        self.feed_mngr = feed_mngr
        self.trees = {}
        self.load_structure()

    def load_structure(self):
        for feed in self.feed_mngr.feeds:
            # find ID feeds and add as tree to tree dict
            # ID feeds are the only feeds that are not child and not continuation
            if not feed.get_prev() and not feed.get_parent():
                # print(ssb_util.to_hex(feed.fid))
                # self.trees[ssb_util.to_hex(feed.fid)] = feed
                self.load_subtrees(feed)
            
        for feed in self.trees.values():
            pass
    
    def load_subtrees(self, feed):
        subtrees = []
        for i in range(1, feed.front_seq + 1):
            type = feed.get_type(i) 
            if type == packet.PacketType.mk_continuous_tree:
                # TODO: check for type of subtree
                ct = ContinuousTree(feed[i][:32])
                ct.load(self.feed_mngr)
                print(ct)
                subtrees.append(ct)

class ContinuousTree:

    def __init__(self, fid, feed_mngr, config):
        self.root_fid = fid # id of the root feed of this tree
        self.feeds = []
        self.fork_pos = []

        # this is the relative front pos of the tree object
        # not to be confused with the front seq of a feed
        self.front_pos = -1
        self.load(feed_mngr, config)
    
    def __str__(self):
        string = 'ContinuousTree: \n'
        for i, f in enumerate(self.feeds):
            # string += '[' + str(i) + '] '
            # string += ssb_util.to_hex(f.fid) + '\n'
            string += f.__str__() + '\n\n'
        return string
    
    def _get_abs_pos(self, pos, feed_mngr):
        print('front_pos: ' + str(self.front_pos))
        curr_pos = self.front_pos
        if pos > curr_pos:
            print('couldn\'t retrieve abs pos: position is larger than newest position')
            return None
        curr_feed = self.feeds[-2]
        curr_seq = len(curr_feed)
        while curr_feed != self.feeds[0]:
            pkts_in_feed = curr_seq - 3
            if curr_pos - pkts_in_feed < pos: # packet is in current feed
                return (curr_feed.fid, curr_seq - (curr_pos - pos))
            curr_pos -= pkts_in_feed
            curr_seq = int.from_bytes(curr_feed.get(3)[0:4], 'big')
            curr_feed = feed_mngr.get_feed(curr_feed.get(3)[4:36])
        return (curr_feed.fid, pos + 4)
        if curr_pos <= 0:
            print('Something went wrong calculating abs position')    

    def load(self, feed_mngr, config):
        next_feed = feed_mngr.get_feed(self.root_fid)
        while next_feed:
            self.feeds.append(next_feed)
            if len(next_feed) >= 2: # at least one payload pkt appended
                next_fid = next_feed[2][:32] # get feed id of child feed (fork feed)
                next_feed = feed_mngr.get_feed(next_fid)
                continue
            break

        # load the fork positions of each feed
        # (first feed trivial (0), last one has not yet fork pos)
        for f in self.feeds[1:-2]:
            if f.get_type(3) != packet.PacketType.fork:
                print('continuous tree: this packet should be a fork')
                continue
            pos = int.from_bytes(f.get(3)[0:4], 'big')
    
        if len(self.feeds[-2]) < 3: # the first fork packet not yet created
            seq, prev_mid = self.feeds[-2].get_front()

            # TODO: dummy packet, maybe change to something more useful later
            self.feeds[-2].append_bytes(b'') 
            # self.fork_pos.insert(0, 0) # update fork pos list
        
        # get number of packets by walking backwards via the fork pointers
        curr_feed = self.feeds[-2]
        curr_seq = len(self.feeds[-2])
        while curr_feed != self.feeds[0]:
            self.front_pos += (curr_seq - 4)
            curr_seq = int.from_bytes(curr_feed.get(3)[0:4], 'big')
            curr_feed = feed_mngr.get_feed(curr_feed.get(3)[4:36])
        print('loaded continuos tree')
        # TODO: Later maybe load from cache file if available
        

    def append_bytes(self, payload: bytes) -> bool:
        success = self.feeds[-2].append_bytes(payload)
        if success:
            self.front_pos += 1
        return success

    def fork_at(self, pos, feed_mngr, config) -> bool:
        # TODO: create new feed and append fork packet in now second last feed
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


def prepare_fork_feed(feed_id, feed_mngr, config):
    # TODO: give dmx + want filter bank and update when fork created
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_child_feed(feed_id, pk, sk) 
    return f

def create_continuous_tree(feed_id, feed_mngr, config):
    # TODO: give dmx + want filter bank and update when fork created
    """Creates a mk_continuous_tree packet to given feed, creates a
    subtree-root-feed and returns secret key, public key as well as a 
    newly created ContinuousTree object."""
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_subtree_root_feed(ssb_util.from_hex(feed_id), pk, sk, packet.PacketType.mk_continuous_tree)

    prepare_fork_feed(pk, feed_mngr, config)
    ct = ContinuousTree(f.fid, feed_mngr, config)
    # append fork pkt in first feed (for uniform feed structure)
    # ct.fork_at(0, feed_mngr, config)
    return (sk, pk, ct)
    