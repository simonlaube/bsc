from cargo import CargoSend, CargoRecv
import time

class PortNumber:
    # TODO: use random numbers to make hash more difficult to guess
    SOME_PORT_1 = 1
    SOME_PORT_2 = 2

class Port:
    def __init__(self, port_nr, is_sender):
        self.port_nr = port_nr
        self.is_sender = is_sender
        self.is_open = False
        self.cargo_out = CargoSend(port_nr)
        self.cargo_in = CargoRecv(port_nr)

    def _set_is_sender(self, is_sender=True):
        if is_open:
            print('This port is currently open. is_sender can only be changed when port is closed.')
            return
        self.is_sender = is_sender

    def prepare_to_send(self):
        if self.is_open:
            print('This port is currently open. You can retry send after port has closed.')
            return False
        if not self.is_sender:
            self._set_is_sender()
        return True

    def cargo_send(self, data, socket):
        self.is_open = True
        self.cargo_out.set_data(data)
        # data is packed and sent in chunks of 128B packets
        pkt = self.cargo_out.pack_next()
        while pkt != None:
            socket.send(pkt)
            print('send packet')
            # TODO: wait for ack, set timer
            time.sleep(1)
            pkt = self.cargo_out.pack_next()
        print("Packet is sent.")

    def handle_llssb_pkt(self, data, seq):
        # check sequence number
        if self.cargo_in.unpack_next(data[15:], 0):
            self.send_ack()
        else:
            self.send_nak()

    def send_ack(self):
        pass

    def send_nak(self):
        pass

    def close(self):
        pass
