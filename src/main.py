import pycom
from network import LoRa
import socket
import time
import os
#from hashlib import md5
import rs_talk
from llssb import LlssbType
from cargo import Cargo, CargoProtocol

pycom.rgbled(0x00FF00)  # Green


#shipment = Cargo(os.urandom(6), CargoProtocol.RS_TALK)
shipment = Cargo(os.urandom(120), CargoProtocol.LLSSB, LlssbType.STD_ENCRYPTION)
for i in shipment.pkt_gen():
    print(i)


b = os.urandom(1)
print(b)
pkt = rs_talk.encode(b)
print(pkt)
"""
b_restored = rs_talk.decode(pkt)
print(b_restored)
"""
