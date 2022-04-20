from pathlib import Path
import os
import shutil

main = '.'
tinyssb = 'tinyssb'
microssb = 'microssb'
pure = 'pure25519'
srcs = [main, tinyssb, microssb, pure]
src = '.'
dest = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/pycom/admin-node')

files = os.listdir(dest)

for fname in files:
    print(fname)