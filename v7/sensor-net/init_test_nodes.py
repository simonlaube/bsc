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
import fork_tree
import session_tree
import dmx_fltr

os.system("rm -rf data")

# create admin key pair
sk, _ = pure25519.create_keypair()
sk_admin, pk_admin = sk.sk_s[:32], sk.vk_s
name = 'admin'
text = f"sk: {ssb_util.to_hex(sk_admin)}\npk: {ssb_util.to_hex(pk_admin)}"
print(text)

# create key pairs of network nodes
configs = {}
conf = Config('./data/Admin/')
conf.new('Admin')
pk_admin = conf['admin']
configs[pk_admin] = conf

for nm in ['NodeA', 'NodeB', 'NodeC']:
    conf = Config('./data/' + nm + '/')
    conf.new(nm, pk_admin)
    print(conf['admin'])
    configs[conf['feed_id']] = conf

# create config and log files for admin and all other nodes
def init_session():
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
            dmx = dmx_fltr.DMXFilter
            want = {}
            f = feed_mngr.create_feed(c['feed_id'], c['secret'])

            ct = None
            st = session_tree.create_session_tree(c['feed_id'], feed_mngr, {}, {}, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            st.append_bytes(b'test', feed_mngr, dmx, want, c)
            print(st.__str__(feed_mngr))

def init_fork():
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
            dmx = dmx_fltr.DMXFilter
            want = {}
            f = feed_mngr.create_feed(c['feed_id'], c['secret'])

            ft = fork_tree.create_fork_tree(c['feed_id'], feed_mngr, {}, {}, c)
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.fork_at(8, feed_mngr, c)
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.fork_at(6, feed_mngr, c)
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            ft.fork_at(9, feed_mngr, c)
            ft.append_bytes(b'hello')
            ft.append_bytes(b'hello')
            print(ft)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('please provide arguments fork or session')    
    elif sys.argv[1] == 'session':
        init_session()
    elif sys.argv[1] == 'fork':
        init_fork()

