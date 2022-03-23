import ubinascii
import os

# just for testing purposes
def get_pk():
    with open('keys.txt') as f:
        lines = f.readlines()
    return ubinascii.a2b_base64(lines[0].encode())

# just for testing purposes
def get_secret():
    with open('keys.txt') as f:
        lines = f.readlines()
    return ubinascii.a2b_base64(lines[1].encode())

def generate_pk():
    return os.urandom(16)

def generate_secret():
    return os.urandom(42)

# a = ubinascii.b2a_base64(private_key).decode().replace('\n', '') # to string
# b = ubinascii.a2b_base64(a.encode())
