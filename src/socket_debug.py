import socket
import time

class socket:
    
    AF_LORA = 'af_lora'
    SOCK_RAW = 'sock_raw'

    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.queue = []
        port = 5000
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("", port))

    def setblocking(self, setblocking = True):
        self.setblocking = setblocking

    def recv(buffer_size):
        self.buffer_size = buffer_size
        while 1:
            data, addr = s.recvfrom(buffer_size)
            print(data)
            return data
        
    def send(pkt):
        time.sleep(.15) 
        self.s.send(pkt)
