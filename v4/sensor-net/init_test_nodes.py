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

from tinyssb import repository, packet

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

def mk_sign_fct(secret):
    sk = pure25519.SigningKey(secret)
    return lambda m: sk.sign(m)

def mk_verify_fct(secret):
    def vfct(pk, s, msg):
        try:
            pure25519.VerifyingKey(pk).verify(s, msg)
            return True
        except Exception as e:
            print(e)
        return False
    return vfct

# create config and log files for admin and all other nodes
for n in nodes.values():

    pfx = './data/' + n['name']
    os.system(f"mkdir -p {pfx}/_blob")
    os.system(f"mkdir -p {pfx}/_feeds")


    # create first log entry
    # TODO: probably delete this later and make first entry with actual data
    repo = repository.REPO(pfx, mk_verify_fct(n['secret']))
    if n['feed_id'] != n['admin']:
        repo.mk_generic_log(n['feed_id'], packet.PKTTYPE_plain48,
                               b'log entry 1', mk_sign_fct(n['secret']))
    
    # install admin trust anchor
    repo.allocate_log(pk_admin, 0, pk_admin[:20])

    # add three child feeds    
    if n['feed_id'] == n['admin']:
        for i in range(0, 3):
            sk, _ = pure25519.create_keypair()
            sk, pk = sk.sk_s[:32], sk.vk_s
            n['child_feeds'][hex(pk)] = hex(sk)
            repo.mk_child_log(pk_admin, mk_sign_fct(sk_admin), pk, mk_sign_fct(sk))

    # list values of node in config, if values are in bytes -> hexlify
    config = {k : hex(v) if type(v) == bytes else v for k, v in n.items() }
    with open(f"{pfx}/config.json", "w") as f:
        json.dump(config, f)



