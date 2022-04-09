class ProgPayloadSender(ProgSender):

    def __init__(self, secret, socket):
        ProgSender.__init__(secret, socket, b'prog_payload_sender')


class ProgPayloadReceiver(ProgReceiver):

    def __init__():
        pass
