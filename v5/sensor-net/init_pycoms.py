# --------------------------------------------------------------------------- #
# This script creates / replaces the folder pycom on the desktop containing
# an admin node and network node folder ready to be loaded on a lopy 4.
# With the argument 'reset', both folders will be initialized.
# With the argument 'add' a new node will be initialized.
# --------------------------------------------------------------------------- #
 
import os
import shutil
import sys
import json
import pure25519
import random
import string
import binascii

from microssb import feed_manager
from prepare_for_pycom import clear_folder, copy_source_code

pk_admin = 'd730877d91c0ffd84c26c6c7eb281c082d2c2d8c3d613c645fd5aea51153b6ab'
sk_admin = 'bae0c60ad02faabe23ed24a643db4f920c1bd869cfdbecee132b47b7282dba40'

dest = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/pycom/')

def hex(b):
    return binascii.hexlify(b).decode()

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
        feed_mngr.create_feed(pk_admin, sk_admin)
        for i in range(0, 3):
            sk, _ = pure25519.create_keypair()
            sk, pk = sk.sk_s[:32], sk.vk_s
            config['child_feeds'][hex(pk)] = hex(sk)
            f = feed_mngr.create_child_feed(pk_admin, pk, sk)

    config = { k : hex(v) if type(v) == bytes else v for k, v in config.items() }
    with open(f"{pfx}/config.json", "w") as f:
        json.dump(config, f)

def get_random_name():
    return ''.join(random.choice(string.ascii_letters) for x in range(10))

def init_network_node():
    sk, _ = pure25519.create_keypair()
    sk, pk = sk.sk_s[:32], sk.vk_s
    name = get_random_name()
    print(name)

    config = {
        'name' : name,
        'feed_id' : pk,
        'secret' : sk,
        'admin' : pk_admin,
        'child_feeds' : {}
    }

    create_files(config)
    copy_source_code(dest + '/' + config['name'])
    # TODO: Add node key to admin subfeed

def init_admin_node():
    name = 'admin'

    config = {
        'name' : name,
        'feed_id' : pk_admin,
        'secret' : sk_admin,
        'admin' : pk_admin,
        'child_feeds' : {}
    }

    create_files(config, True)
    copy_source_code(dest + '/' + config['name'])

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == 'reset':
            clear_folder(dest)            
            init_admin_node()
            return
        if sys.argv[1] == 'add':
            init_network_node()

if __name__ == '__main__':
    main()