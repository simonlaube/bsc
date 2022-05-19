from microssb import ssb_util, packet
import fork_tree
import config
import fork_tree

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
            if type == packet.PacketType.mk_fork_tree:
                # TODO: check for type of subtree
                ct = fork_tree.load_fork_tree(feed[i][:32],
                                    feed_mngr,
                                    dmx_fltr,
                                    want_fltr,
                                    config,
                                    self.is_owner,
                                    self.is_critical)
                print(ct)
                subtrees.append(ct)

    def add_subtree(self, subtree):
        self.trees[ssb_util.to_hex(subtree.root_fid)] = subtree
