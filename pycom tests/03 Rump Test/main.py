import pycom
from network import LoRa
import socket
import time
import os
#from hashlib import md5
#import rs_talk
from cargo import Cargo, CargoProtocol, LlssbType

pycom.rgbled(0x00FF00)  # Green


shipment = Cargo(os.urandom(6), CargoProtocol.RS_TALK)
for i in shipment.pkt_gen():
    print(i)

"""
b = os.urandom(1)
print(b)
pkt = rs_talk.encode(b)
b_restored = rs_talk.decode(pkt)
print(b_restored)
"""
