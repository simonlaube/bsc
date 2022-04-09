import sys
import os
import json
import binascii
import pure25519
import binascii

def hex(b):
    return binascii.hexlify(b).decode()

def main():
    """If flag admin set: Creates admin keys and main feed ankor log.
    Else create keys for new node.
    """
    # create root key pair
    if len(sys.argv) > 1 and sys.argv[1] == '-root':
        sk, _ = pure25519.create_keypair()
        priv_key, pub_key = sk.sk_s[:32], sk.vk_s


if __name__ == '__main__':
    main()
