import pycom
from network import LoRa
import socket
import time
import os
#from hashlib import md5
import rs_talk
from llssb import LlssbType
from cargo import CargoSend, CargoRecv, CargoProtocol, Port

pycom.rgbled(0x00FF00)  # Green


#shipment = Cargo(os.urandom(6), CargoProtocol.RS_TALK)

bs = b'Hello over there, this is just a string that is being sent over LoRa and the llssb protocol for testing.'
# print(bs)
cargo_send = CargoSend(Port.SOME_PORT_1, bs)
cargo_recv = CargoRecv(Port.SOME_PORT_1)
while True:
    s = cargo_send.pack_next(LlssbType.STD_48B)
    if s == None:
        break
    r = cargo_recv.unpack_next(s)
print(cargo_recv.data)


"""
b = os.urandom(1)
print(b)
pkt = rs_talk.encode(b)
print(pkt)
b_restored = rs_talk.decode(pkt)
print(b_restored)
"""
