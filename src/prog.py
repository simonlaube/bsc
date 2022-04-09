class ProgList:
    PROG_PAYLOAD = b'prog_payload',
    PROG_ADMIN = b'prog_admin'

class ProgSender:

    def __init__(self, secret, socket, prog_id):
        self.secret = secret
        self.socket = socket
        self.prog_id = prog_id
        self.ack = False

    def send(self):
        pass


class ProgReceiver:

    def __init__(self):
        # if a connection is blocked by a sender, others cannot use this program
        self.blocking_secret = None
