import socket # uses python sockets for development
import time
from lora_node import LoRaNode
#from hashlib import md5
from prog import ProgList
import rs_talk
from llssb import LlssbType

import sys
  
  

def main():
    is_user_A = True

    if len(sys.argv) > 1:
        if sys.argv[1] == 'A':
            is_user_A = True
        elif sys.argv[1] == 'B':
            is_user_A = False
        else:
            return
    else:
        print('You must specify a user')
        return
    if is_user_A:
        print('started user A...')
        lora_node = LoRaNode(True)
        bs = b'Hello over there, this is just a string that is being sent over LoRa and the llssb protocol for testing.'
        # print(bs)
        lora_node.send_data(bs, ProgList.PROG_PAYLOAD)
    else:
        print('started user B...')
        pass

if __name__== "__main__":
    main()
"""
while True:
    s = cargo_send.pack_next(LlssbType.STD_48B)
    if s == None:
        break
    r = cargo_recv.unpack_next(s)
print(cargo_recv.data)
"""


"""
b = os.urandom(1)
print(b)
pkt = rs_talk.encode(b)
print(pkt)
b_restored = rs_talk.decode(pkt)
print(b_restored)
"""
