# -------------------------------------------------
# Implementation by Simon laube
# -------------------------------------------------

import os
from tinyssb import ssb_util
import pure25519
import json

class Config:

    def __init__(self, path):
        self.config = {}
        self.path = path
        try:
            with open(self.path + 'config.json') as f:
                self.config = json.load(f)
                f.close()
        except Exception as e:
            print(e)
    
    def __getitem__(self, key):
        return self.config[key]
    
    def new(self, name, admin=None):
        """Creates a config object with a new key-pair
        and writes it to a file."""
        self._new_id_keypair(False) # creates and adds sk, pk
        if admin == None:
            admin = self.config['feed_id']
        self.config['name'] = name
        self.config['admin'] = admin
        self.config['child_feeds'] = {}
        self._write()
    
    def set(self, name, pk, sk, admin=None):
        """Creates a config object with a given key-pair
        and writes it to a file."""
        if admin == None:
            admin = pk
        self.config['admin'] = admin
        self.config['name'] = name
        self.config['feed_id'] = pk
        self.config['secret'] = sk
        self.config['child_feeds'] = {}
        self._write()
    
    def _new_keypair(self):
        """Returns a keypair in hexadecimals."""
        sk, _ = pure25519.create_keypair()
        sk, pk = sk.sk_s[:32], sk.vk_s
        return (ssb_util.to_hex(sk), ssb_util.to_hex(pk))

    def _new_id_keypair(self, as_bytes: bool):
        """Creates a new ID keypair, writes it to the config file
        and returns the keys."""
        sk, pk = self._new_keypair()
        self.config['secret'] = sk
        self.config['feed_id'] = pk
        if as_bytes:
            sk = ssb_util.from_hex(sk)
            pk = ssb_util.from_hex(pk)
        self._write()
        return (sk, pk)

    def new_child_keypair(self, as_bytes: bool):
        """Creates a child keypair, writes it to the config file
        and returns the keys."""
        sk, pk = self._new_keypair()
        self.config['child_feeds'][pk] = sk
        if as_bytes:
            sk = ssb_util.from_hex(sk)
            pk = ssb_util.from_hex(pk)
        self._write()
        return (sk, pk)

    def remove_child_keypair(self, pk):
        """Removes the given child key from the config file."""
        self.config['child_feeds'].pop(pk)
        self._write()
    
    def get_key_dict(self):
        dict = self.config['child_feeds']
        dict[self.config['feed_id']] = self.config['secret']
        return dict

    def _write(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        with open(self.path + 'config.json', 'w') as f:
            json.dump(self.config, f)
            f.close()

    def get_sk(self, pk):
        """Returns the corresponding secret key
        to the given public key."""
        sk = self.config[pk]
        if sk:
            return sk
        return None