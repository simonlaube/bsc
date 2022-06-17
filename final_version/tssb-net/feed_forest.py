from tinyssb import ssb_util, packet
import fork_tree
import session_tree
import config

"""All feed trees are stored in this dictionary."""
class FeedForest:

    def __init__(self, feed_mngr, dmx_fltr, want_fltr, conf):
        self.trees = {}

        # TODO: check for peer id feeds not only admin
        feed = feed_mngr.get_feed(conf['admin'])
        if feed != None:
            self.trees[ssb_util.to_hex(feed.fid)] = self.load_subtrees(feed,
                                                     feed_mngr,
                                                     dmx_fltr,
                                                     want_fltr,
                                                     conf)

    
    def load_subtrees(self, feed, feed_mngr, dmx_fltr, want_fltr, conf):
        """Loads all trees that are started with a make tree packet
        from within the given feed."""
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
                subtrees.append(ct)
            if type == packet.PacketType.mk_session_tree:
                st = session_tree.load_session_tree(feed[i][:32],
                                                    feed_mngr,
                                                    dmx_fltr,
                                                    want_fltr,
                                                    config,
                                                    self.is_owner,
                                                    self.is_critical)
                subtrees.append(st)
        return subtrees

    def add_subtree(self, subtree):
        """Adds a subtree to the dictionary. The root feed ID is the key."""
        self.trees[ssb_util.to_hex(subtree.root_fid)] = subtree
