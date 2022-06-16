# --------------------------------------------------------------------------- #
# This script initializes the folder 'pycom' on the desktop.
# With the argument 'reset', the folder will be deleted and a new admin folder
# created. With the argument 'add' a new node will be initialized and added.
# --------------------------------------------------------------------------- #
 
import os
import sys
import random
import string
import binascii

from tinyssb import feed_manager
from config import Config
from prepare_for_pycom import clear_folder, copy_source_code
import fork_tree
import session_tree
import dmx_fltr

pk_admin = 'd730877d91c0ffd84c26c6c7eb281c082d2c2d8c3d613c645fd5aea51153b6ab'
sk_admin = 'bae0c60ad02faabe23ed24a643db4f920c1bd869cfdbecee132b47b7282dba40'

dest = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/pycom/')

def hex(b):
    return binascii.hexlify(b).decode()

def from_hex(s):
    return binascii.unhexlify(s.encode())
    
    
def create_files_node(config):
    pfx = dest + config['name'] + '/data'
    os.system(f"mkdir -p {pfx}/_blobs")
    os.system(f"mkdir -p {pfx}/_feeds")
    
    dict = { config['feed_id'] : config['secret'] }
    feed_mngr = feed_manager.FeedManager(pfx + '/', dict)
    
    feed_mngr.create_feed(config['feed_id'], config['secret'])
    # create admin anchor
    feed_mngr.create_feed(config['admin'])
    
def create_files_session(config):
    pfx = dest + config['name'] + '/data'
    os.system(f"mkdir -p {pfx}/_blobs")
    os.system(f"mkdir -p {pfx}/_feeds")
    
    dict = { config['feed_id'] : config['secret'] }
    feed_mngr = feed_manager.FeedManager(pfx + '/', dict)
    
    dmx = dmx_fltr.DMXFilter()
    want = {}
    main_feed = feed_mngr.create_feed(config['feed_id'], config['secret'])
    st = session_tree.create_session_tree(config['feed_id'], feed_mngr, {}, {}, config, 6)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    
    
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    st.append_bytes(b'test', feed_mngr, dmx, want, config)
    print(st.__str__(feed_mngr))

def create_files_fork(config):
    pfx = dest + config['name'] + '/data'
    os.system(f"mkdir -p {pfx}/_blobs")
    os.system(f"mkdir -p {pfx}/_feeds")
    
    dict = { config['feed_id'] : config['secret'] }
    feed_mngr = feed_manager.FeedManager(pfx + '/', dict)
    
    main_feed = feed_mngr.create_feed(config['feed_id'], config['secret'])
    ft = fork_tree.create_fork_tree(config['feed_id'], feed_mngr, {}, {}, config)
    ft.append_bytes(b'hello')
    ft.append_bytes(b'hello')
    ft.append_bytes(b'hello')
    ft.fork_at(3, feed_mngr, config) # should fail
    ft.fork_at(2, feed_mngr, config) # should fail (cannot fork newest pkt)
    ft.fork_at(1, feed_mngr, config)
    ft.append_bytes(b'sdfds')
    ft.append_bytes(b'lkjsdflkjsl')
    ft.fork_at(2, feed_mngr, config)
    ft.fork_at(0, feed_mngr, config)
    print(ft)

def get_random_name():
    return ''.join(random.choice(string.ascii_letters) for x in range(10))

def init_network_node():
    # sk, _ = pure25519.create_keypair()
    # sk, pk = sk.sk_s[:32], sk.vk_s
    name = get_random_name()
    print(name)
    admin_conf = Config(dest + 'Admin/data/')
    conf = Config(dest + name + '/data/')
    conf.new(name, admin_conf['feed_id'])

    create_files_node(conf)
    copy_source_code(dest + '/' + conf['name'])
    # TODO: Add node key to admin subfeed

def init_admin_node(tree_type):
    conf = Config(dest + 'Admin/data/')
    conf.new('admin')
    # conf = Config(dest + 'Admin/data/')
    # conf.set('admin', pk_admin, sk_admin)

    if tree_type == 'fork':
        create_files_fork(conf)
    if tree_type == 'session':
        create_files_session(conf)
    copy_source_code(dest + '/' + conf['name'])

def main():
    if len(sys.argv) < 2:
        print('add \'fork\' or \'session\' to delete all nodes and create a new admin node or \'add\' to add a new network node')
        return
        
    if sys.argv[1] == 'add':
        init_network_node()
        return
    if sys.argv[1] == 'fork':
        clear_folder(dest)
        init_admin_node('fork')
        return
    if sys.argv[1] == 'session':
        clear_folder(dest)
        init_admin_node('session')
        
if __name__ == '__main__':
    main()