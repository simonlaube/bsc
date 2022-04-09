from network import LoRa
import socket
import _thread
import time
from hashlib import sha256
from port import PortNumber

class LoRaNode:

    def __init__(self, progs, debugging = False):
        self.progs = progs
        if debugging:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.sendto(b'test', ("127.0.0.1", 5000))
            self.socket.recv(128)
        else:
            # TODO: test out multiple lora configurations
            lora = LoRa(mode=LoRa.LORA, region=LoRa.EU868)
            self.socket = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
            self.socket.setblocking(True) # maybe change this later

        _thread.start_new_thread(self.listen, ())
        # send_time_broadcast()

    def send_data(self, data, prog_id):
        if prog_id not in self.progs:
            print("Prog is not valid.")
            return
        _thread.start_new_thread(self._send, (data, prog_id, ))

    def _send(self, data, prog_id):
        prog = self.progs[prog_id]
        # TODO: Add Mutex to ensure no other thread uses port
        if not prog.prepare_to_send('some secret'):
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
            if dmx == sha256((str(port.port_nr) + str(0)).encode('utf-8')).digest()[:7]:
                port.handle_llssb_pkt(pkt[15:], 0, self.socket) # seq = 0
                break
            elif dmx == sha256((str(port.port_nr) + str(1)).encode('utf-8')).digest()[:7]:
                port.handle_llssb_pkt(pkt[15:], 1, self.socket) # seq = 1
                break
            elif dmx == sha256((str(port.port_nr) + str(port.cargo_out.seq) + 'ack').encode('utf-8')).digest()[:7]:
                port.handle_ack() # ack flag
                break
            # TODO: add all possible combinations
        print('Packet could not be demultiplexed')
