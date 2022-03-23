import pycom
from network import LoRa
import socket
import time

pycom.rgbled(0x00FF00)  # Green

# change depending on what mode the device should be in
is_sender = True

if is_sender:
    # sender
    lora = LoRa(mode=LoRa.LORA, region=LoRa.EU868)
    s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
    s.setblocking(False)
    i = 0
    while True:
        s.send('Ping')
        print('Ping {}'.format(i))
        i += 1
        time.sleep(0.2)
else:
    # receiver
    lora = LoRa(mode=LoRa.LORA, region=LoRa.EU868)
    s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
    s.setblocking(True)
    i = 0
    while True:
        bytes = s.recv(64)
        if bytes == b'Ping':
            if i == 200:
                pycom.rgbled(0xFFFFFF)
                break
            if i % 3 == 0:
                pycom.rgbled(0xFF0000)  # Red
            elif i % 3 == 1:
                pycom.rgbled(0x00FF00)  # Green
            else:
                pycom.rgbled(0x0000FF)  # Blue
            i += 1
