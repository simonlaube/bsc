import pycom
from network import LoRa
import socket
import time
import os
from communication import LoRaNode
#from hashlib import md5
import rs_talk
from llssb import LlssbType
from port import PortNumber, Port

pycom.rgbled(0x00FF00)  # Green

is_sender = True

if is_sender:
    port1 = Port(PortNumber.SOME_PORT_1, is_sender=True)
    ports = {
        PortNumber.SOME_PORT_1 : port1
    }
    lora_node = LoRaNode(ports)
    bs = b'Hello over there, this is just a string that is being sent over LoRa and the llssb protocol for testing.'
    # print(bs)
    lora_node.send_data(bs, PortNumber.SOME_PORT_1)
else:
    port1 = Port(PortNumber.SOME_PORT_1, is_sender=False)
    ports = {
        PortNumber.SOME_PORT_1 : port1
    }
    lora_node = LoRaNode(ports)
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
