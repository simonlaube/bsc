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

    def __init__(self, fid):
        self.subtree_fid = fid
        self.feeds = []
    
    def __str__(self):
        string = 'ContinuousTree: \n'
        for i, f in enumerate(self.feeds):
            string += '[' + str(i) + '] '
            string += ssb_util.to_hex(f.fid)
        return string

    def load(self, feed_mngr):
        next_feed = feed_mngr.get_feed(self.subtree_fid)
        while next_feed:
            # TODO: check if seq of mk_child is 1 or 2
            self.feeds.append(next_feed)
            if len(next_feed) > 2:
                next_fid = next_feed[1][:32] # get feed id of child feed (fork feed)
                next_feed = feed_mngr.get_feed(next_fid)
                continue
            break

    def append_bytes(self, payload: bytes):
        pass

    def fork_at(self, seq):
        # TODO: create new feed and append fork packet in now second last feed
        pass

def prepare_fork_feed(feed_id, feed_mngr, config):
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_child_feed(feed_id, pk, sk) 

def create_continuous_tree(feed_id, feed_mngr, config):
    """Creates a mk_continuous_tree packet to given feed, creates a
    subtree-root-feed and returns secret key, public key as well as a 
    newly created ContinuousTree object."""
    sk, pk = config.new_child_keypair(as_bytes=True)
    f = feed_mngr.create_subtree_root_feed(ssb_util.from_hex(feed_id), pk, sk, packet.PacketType.mk_continuous_tree)
    prepare_fork_feed(pk, feed_mngr, config)
    ct = ContinuousTree(f.fid)
    return (sk, pk, ct)
    