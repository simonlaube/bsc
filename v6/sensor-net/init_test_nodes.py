#!/usr/bin/env python3

# ---------------------------------------------------------------------------- #
# This script creates an admin key pair and three network nodes.
# Each node has a config file containing its name, private key, public key and
# the public key of the network admin. Additionally the nodes have an instance
# of an initialized admin log where they can later append admin log entries.
# ---------------------------------------------------------------------------- #

import binascii
import json
import os
import pure25519
import sys

from microssb import feed_manager, packet, ssb_util
from config import Config
import feed_forest

os.system("rm -rf data")

# create admin key pair
sk, _ = pure25519.create_keypair()
sk_admin, pk_admin = sk.sk_s[:32], sk.vk_s
name = 'admin'
text = f"sk: {ssb_util.to_hex(sk_admin)}\npk: {ssb_util.to_hex(pk_admin)}"
print(text)

# create key pairs of network nodes
configs = {}
# nodes[pk_admin] = {
#     'name' : 'Admin',
#     'feed_id' : pk_admin,
#     'secret' : sk_admin,
#     'admin' : pk_admin, # here admin anchor is personal key
#     'child_feeds' : {}
# }
conf = Config('./data/Admin/')
conf.new('Admin')
pk_admin = conf['admin']
configs[pk_admin] = conf

for nm in ['NodeA', 'NodeB', 'NodeC']:
    # sk, _ = pure25519.create_keypair()
    # sk, pk = sk.sk_s[:32], sk.vk_s
    # nodes[pk] = {
    #     'name' : nm,
    #     'feed_id' : pk,
    #     'secret' : sk,
    #     'admin' : pk_admin, # admin anchor is set here
    #     'child_feeds' : {}
    # }
    conf = Config('./data/' + nm + '/')
    conf.new(nm, pk_admin)
    print(conf['admin'])
    configs[conf['feed_id']] = conf

# create config and log files for admin and all other nodes
for c in configs.values():
    pfx = './data/' + c['name']
    print(pfx)
    os.system(f"mkdir -p {pfx}/_blobs")
    os.system(f"mkdir -p {pfx}/_feeds")

    # create logs
    dict = { c['feed_id'] : c['secret'] }
    feed_mngr = feed_manager.FeedManager(pfx + '/', dict)

    # create feed and admin anchor for not admin nodes
    if c['feed_id'] != c['admin']:
        feed_mngr.create_feed(c['feed_id'], c['secret'])
        # install admin trust anchor
        feed_mngr.create_feed(c['admin'])
        
    # create admin feed and three child nodes (subtrees)
    else:
        f = feed_mngr.create_feed(c['feed_id'], c['secret'])

        ct = None
        for i in range(0, 3):

            # f = feed_mngr.create_subtree_root_feed(n['feed_id'], pk, sk, packet.PacketType.mk_continuous_tree)
            sk, pk, ct = feed_forest.create_continuous_tree(c['feed_id'], feed_mngr, {}, {}, c)
        if ct:
            print("subtree root feed created")
        ct.append_bytes(b'hello')
        ct.append_bytes(b'hello')
        ct.append_bytes(b'hello')
        if ct.fork_at(3, feed_mngr, c):
            pass
        if ct.fork_at(2, feed_mngr, c):
            print('fork creation successful')
        if ct.fork_at(1, feed_mngr, c):
            print('fork creation successful')
        if ct.fork_at(3, feed_mngr, c):
            print('fork creation successful')
        ct.append_bytes(b'lksdjf')
        ct.append_bytes(b'lksdjf')
        if ct.fork_at(2, feed_mngr, c):
            print('fork creation successful')
        else:
            print('could not fork')
        ct.fork_at(0, feed_mngr, c)

        print(ct)

        # feed = feed_mngr.get_feed(n['feed_id'])
        # feed.append_blob(bytes(500))

    # list values of node in config, if values are in bytes -> hexlify



