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

def hex(b):
    return binascii.hexlify(b).decode()


os.system("rm -rf data")

# create admin key pair
sk, _ = pure25519.create_keypair()
sk_admin, pk_admin = sk.sk_s[:32], sk.vk_s
name = 'admin'
text = f"sk: {hex(sk_admin)}\npk: {hex(pk_admin)}"
print(text)

# create key pairs of network nodes
nodes = {}
nodes[pk_admin] = {
    'name' : 'Admin',
    'feed_id' : pk_admin,
    'secret' : sk_admin,
    'admin' : pk_admin, # here admin anchor is personal key
    'child_feeds' : {}
}

for nm in ['NodeA', 'NodeB', 'NodeC']:
    sk, _ = pure25519.create_keypair()
    sk, pk = sk.sk_s[:32], sk.vk_s
    nodes[pk] = {
        'name' : nm,
        'feed_id' : pk,
        'secret' : sk,
        'admin' : pk_admin, # admin anchor is set here
        'child_feeds' : {}
    }

# create config and log files for admin and all other nodes
for n in nodes.values():

    pfx = './data/' + n['name']
    os.system(f"mkdir -p {pfx}/_blobs")
    os.system(f"mkdir -p {pfx}/_feeds")

    # create first log entry
    # TODO: probably delete this later and make first entry with actual data
    """
    repo = repository.REPO(pfx, mk_verify_fct(n['secret']))
    if n['feed_id'] != n['admin']:
        repo.mk_generic_log(n['feed_id'], packet.PKTTYPE_plain48,
                               b'log entry 1', mk_sign_fct(n['secret']))
    """

    # create logs
    dict = { hex(n['feed_id']) : hex(n['secret']) }
    feed_mngr = feed_manager.FeedManager(pfx + '/', dict)

    # create feed and admin anchor for not admin nodes
    if n['feed_id'] != n['admin']:
        feed_mngr.create_feed(n['feed_id'], n['secret'])
        # install admin trust anchor
        feed_mngr.create_feed(n['admin'])
        
    # create admin feed and three child nodes
    else:
        feed_mngr.create_feed(n['admin'], n['secret'])
        for i in range(0, 3):
            sk, _ = pure25519.create_keypair()
            sk, pk = sk.sk_s[:32], sk.vk_s
            # add new keys to feed manager
            # feed_mngr.keys[hex(pk)] = hex(sk)
            n['child_feeds'][hex(pk)] = hex(sk)
            f = feed_mngr.create_child_feed(n['feed_id'], pk, sk)
            if f:
                print("child feed created")

    
    # list values of node in config, if values are in bytes -> hexlify
    config = {k : hex(v) if type(v) == bytes else v for k, v in n.items() }
    with open(f"{pfx}/config.json", "w") as f:
        json.dump(config, f)



