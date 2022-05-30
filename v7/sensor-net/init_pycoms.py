# --------------------------------------------------------------------------- #
# This script initializes the folder 'pycom' on the desktop.
# With the argument 'reset', the folder will be deleted and a new admin folder
# created. With the argument 'add' a new node will be initialized and added.
# --------------------------------------------------------------------------- #
 
import os
import shutil
import sys
import json
import pure25519
import random
import string
import binascii

from microssb import feed_manager, packet, ssb_util
from config import Config
from prepare_for_pycom import clear_folder, copy_source_code
import feed_forest
import fork_tree
import session_tree

pk_admin = 'd730877d91c0ffd84c26c6c7eb281c082d2c2d8c3d613c645fd5aea51153b6ab'
sk_admin = 'bae0c60ad02faabe23ed24a643db4f920c1bd869cfdbecee132b47b7282dba40'

dest = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/pycom/')

def hex(b):
    return binascii.hexlify(b).decode()

def from_hex(s):
    return binascii.unhexlify(s.encode())
    
    
def create_files(config, admin = False):
    pfx = dest + config['name'] + '/data'
    os.system(f"mkdir -p {pfx}/_blobs")
    os.system(f"mkdir -p {pfx}/_feeds")
    
    dict = { config['feed_id'] : config['secret'] }
    feed_mngr = feed_manager.FeedManager(pfx + '/', dict)
    
    if not admin:
        feed_mngr.create_feed(config['feed_id'], config['secret'])
        # create admin anchor
        feed_mngr.create_feed(config['admin'])

    else:
        main_feed = feed_mngr.create_feed(pk_admin, sk_admin)
        st = session_tree.create_session_tree(pk_admin, feed_mngr, {}, {}, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        st.append_bytes(b'test', feed_mngr, config)
        print(st.__str__(feed_mngr))
        return
        for i in range(0, 3):
            # sk, _ = pure25519.create_keypair()
            # sk, pk = sk.sk_s[:32], sk.vk_s
            sk, pk, ct = fork_tree.create_fork_tree(pk_admin, feed_mngr, {}, {}, config)
            # config['child_feeds'][hex(pk)] = hex(sk)
            if i != 2:
                continue
            if ct:
                print('subtree root created')
            ct.append_bytes(b'hello')
            ct.append_bytes(b'hello')
            ct.append_bytes(b'hello')
            ct.fork_at(3, feed_mngr, config) # should fail
            ct.fork_at(2, feed_mngr, config) # should fail (cannot fork newest pkt)
            ct.fork_at(1, feed_mngr, config)
            ct.append_bytes(b'sdfds')
            ct.append_bytes(b'lkjsdflkjsl')
            ct.fork_at(2, feed_mngr, config)
            ct.fork_at(0, feed_mngr, config)

def get_random_name():
    return ''.join(random.choice(string.ascii_letters) for x in range(10))

def init_network_node():
    # sk, _ = pure25519.create_keypair()
    # sk, pk = sk.sk_s[:32], sk.vk_s
    name = get_random_name()
    print(name)
    conf = Config(dest + name + '/data/')
    conf.new(name, pk_admin)

    create_files(conf)
    copy_source_code(dest + '/' + conf['name'])
    # TODO: Add node key to admin subfeed

def init_admin_node():
    conf = Config(dest + 'Admin/data/')
    conf.set('admin', pk_admin, sk_admin)

    create_files(conf, True)
    copy_source_code(dest + '/' + conf['name'])

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == 'reset':
            clear_folder(dest)            
            init_admin_node()
            return
        if sys.argv[1] == 'add':
            init_network_node()
    else:
        print('add \'reset\' to delete all nodes and create a new admin node or \'add\' to add a new network node')

if __name__ == '__main__':
    main()