from network import LoRa
import socket
import _thread
import time

def init():
    _thread.start_new_thread(listen, ())
    # send_time_broadcast()

def listen():
    """Listents for incoming LoRa packets."""
    lora = LoRa(mode=LoRa.LORA, region=LoRa.EU868)
    # TODO: test out multiple lora configurations
    s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
    s.setblocking(True) # maybe change this later
    while True:
        msg = s.recv(64)
        if msg != b'':
            print(msg.decode())

def handle_packet():
    """Incoming packets will be handled in this separate thread"""
    pass
