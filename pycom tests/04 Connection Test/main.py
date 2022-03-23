import pycom
from network import LoRa
import socket
import time
import _thread
from machine import Timer

is_user_A = False

lora = LoRa(mode=LoRa.LORA, region=LoRa.EU868)
s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
s.setblocking(False)
pos = 0
ack = 0

def send_A():
    global pos
    global ack
    unanswered_msg = 0
    succ_msg_streak = 0
    timer = .2

    while ack < 64:
        if ack == 0: # change led colors to visually see progress
            pycom.rgbled(0xff1100)
        elif ack <= 10:
            pycom.rgbled(0xcc3300)
        elif ack <= 20:
            pycom.rgbled(0xaa5500)
        elif ack <= 30:
            pycom.rgbled(0x888800)
        elif ack <= 40:
            pycom.rgbled(0x55aa00)
        elif ack <= 50:
            pycom.rgbled(0x33cc00)
        elif ack == 63:
            pycom.rgbled(0x11ffff)
            return
        if unanswered_msg > 5:
            print('msg still unanswered after', unanswered_msg, ' tries')
        if ack == pos:
            pos += 1
            unanswered_msg = 0
            succ_msg_streak += 1
        elif ack != pos - 1: # has not happened yet
            print('ack and pos are messed up. ack: ', ack, ', pos: ', pos)
            return
        else:
            unanswered_msg += 1
            succ_msg_streak = 0
            timer = min(timer + .1, 2) # increase timer
        try:
            s.send(bytes(pos))
        except:
            print('exception in user A after sending')
        print('send', pos)
        try:
            time.sleep(timer)
        except:
            print('exception in user A')
        if succ_msg_streak == 2:
            timer = max(int(timer / 1.5), .2) # decrease timer

def recv_A():
    global ack
    while True:
        msg = s.recv(64)
        if msg == bytes(63):
            ack += 1
            print('received 63')
            return
        if msg == bytes(ack + 1):
            ack += 1
            print('recv ack ', ack)

def recv_B():
    ack_B = 0
    alarm = Timer.Alarm(self._seconds_handler, 1, periodic=True)
    while ack_B < 64:
        msg = s.recv(64)
        if msg == bytes(63):
            ack_B += 1
            print('received 63')
            s.send(bytes(ack_B)) # resend last ack a couple of times
            time.sleep(1)
            s.send(bytes(ack_B))
            ack_B = 0 # for debugging purposes reset acks
        if msg == bytes(ack_B + 1):
            ack_B += 1
            s.send(bytes(ack_B))
            print('received new pkg ', ack_B)
        elif msg == bytes(ack_B):
            try:
                s.send(bytes(ack_B))
            except:
                print('something went wrong user B')
            print('ack ', ack_B, ' was sent again')

if is_user_A:
    # user A
    _thread.start_new_thread(send_A, ())
    _thread.start_new_thread(recv_A, ())
else:
    # user B
    _thread.start_new_thread(recv_B, ())
