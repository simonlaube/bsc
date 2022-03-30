from cargo import CargoOut, CargoIn
from hashlib import sha256
import time
from machine import Timer
from hashlib import sha256

class PortNumber:
    # TODO: use random numbers / bytes / strings to make hash more difficult to guess
    SOME_PORT_1 = 1
    SOME_PORT_2 = 2

class Port:
    def __init__(self, port_nr, is_sender):
        self.port_nr = port_nr
        self.secret = None
        self.sender = sender # TODO: use secret in demux hash
        self.is_open = False
        self.cargo_out = CargoOut(port_nr)
        self.cargo_in = CargoIn(port_nr)

    def _set_is_sender(self, is_sender=True):
        if is_open:
            print('This port is currently open. is_sender can only be changed when port is closed.')
            return
        self.is_sender = is_sender

    def prepare_to_send(self, secret):
        """Returns False if port is already being used.
        Otherwise prepares port and returns True.
        """
        if self.is_open:
            print('This port is currently open. You can retry send after port has closed.')
            return False
        if not self.is_sender:
            self._set_is_sender()
        self.secret = secret
        return True

    def cargo_send(self, data, socket):
        """Open port and send packets iteratively after ack of
        previous pkt was received.
        """
        self.is_open = True
        self.cargo_out.set_data(data)
        # data is packed and sent in chunks of 128B packets
        pkt = self.cargo_out.pack_next()
        while pkt != None:
            socket.send(pkt)
            print('send packet')
            while not self.cargo_out.ack:
                time.sleep(1) # TODO: set time according to LoRa toa rule
                socket.send(pkt) # try sending again
            self.cargo_out.ack = False
            pkt = self.cargo_out.pack_next()
        print("Packet is sent. Port will close...")
        self.close()

    def handle_llssb_pkt(self, demuxed_pkt, seq, socket):
        """Verifies encoding. If encoded correctly, adds data to cargo_in and
        sends ack, if not, sends ack of last sequence number.
        """
        if self.cargo_in.unpack_next(demuxed_pkt, seq):
            print("packet is valid")
            print(demuxed_pkt)
            self.send_ack(seq, socket)
        else:
            print("packet is not valid")
            print(demuxed_pkt)
            self.send_ack((-1) * seq + 1, socket) # packet already received

    def handle_ack(self):
        """If ack was correctly received, update sequence number and flag."""
        self.cargo_out.seq = (-1) * self.cargo_out.seq + 1
        self.cargo_out.ack = True

    def send_ack(self, seq, socket):
        """Send packet with ack in header hash with empty body."""
        header = b'\0' * 8 + sha256((str(self.port_nr) + str(seq) + 'ack').encode('utf-8')).digest()[:7] 
        pkt = header + b'\0' * 113
        socket.send(pkt)

    def close(self):
        """Close port by reinitializing object."""
        self.__init__(self.port_nr)
