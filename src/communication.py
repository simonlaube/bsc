from network import LoRa
import socket
import _thread
import time
from hashlib import sha256
from port import PortNumber

class LoRaNode:
    def __init__(self, ports):
        self.ports = ports
        lora = LoRa(mode=LoRa.LORA, region=LoRa.EU868)
        # TODO: test out multiple lora configurations
        self.socket = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
        self.socket.setblocking(True) # maybe change this later

        _thread.start_new_thread(self.listen, ())
        # send_time_broadcast()

    def send_data(self, data, port_nr):
        if port_nr not in self.ports:
            print("Port number is not valid.")
            return
        _thread.start_new_thread(self._send, (data, port_nr, ))

    def _send(self, data, port_nr):
        port = self.ports[port_nr]
        # TODO: Add Mutex to ensure no other thread uses port
        if not port.prepare_to_send():
            return
        port.cargo_send(data, self.socket)


    def listen(self):
        """Listents for incoming LoRa packets."""
        while True:
            pkt = self.socket.recv(128)
            _thread.start_new_thread(self._assign_port, (pkt, ))


    def _assign_port(self, pkt):
        """Incoming llssb packet parameters will be checked for validity.
        Demuxed content will then be further handled in separate function
        """
        if len(pkt) != 128: # add rs_talk check
            return
        cloak_header = pkt[:8]
        dmx = pkt[8:15]
        for port in self.ports.values():
            if dmx == sha256(bytes([port.port_nr + 0])).digest()[:7]:
                port.handle_llssb_pkt(pkt[15:], 0) # seq = 0
                break
            elif dmx == sha256(bytes([port.port_nr + 1])).digest()[:7]:
                port.handle_llssb_pkt(pkt[15:], 1) # seq = 1
                break
            # TODO: add all possible combinations
