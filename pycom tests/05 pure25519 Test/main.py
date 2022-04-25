import pure25519
import time

def sign(sk, msg):
    return pure25519.SigningKey(sk).sign(msg)

def verify(pk, signed_msg, msg):
    return pure25519.VerifyingKey(pk).verify(signed_msg, msg)

def main():
    key = b'\xd70\x87}\x91\xc0\xff\xd8L&\xc6\xc7\xeb(\x1c\x08-,-\x8c=a<d_\xd5\xae\xa5\x11S\xb6\xab'
    signed_msg = b'\x85\t\x92\xa9\xb9^\xab\xd8Z\x8fKqz\x07\xdb\xbe\x9d\xce\xa8\x10jW5\xf2t\xd8U\x17\xad\x98\x16\x1e-\x0eA\xcfM\xd9\x02j+\x19\xe8f\xb7p\xf9^f71U\x8e5\x06uF\xf4c)\xa1\xda\x08\x05'
    msg = b'\xd70\x87}\x91\xc0\xff\xd8L&\xc6\xc7\xeb(\x1c\x08-,-\x8c=a<d_\xd5\xae\xa5\x11S\xb6\xab\x00\x00\x00\x01\xd70\x87}\x91\xc0\xff\xd8L&\xc6\xc7\xeb(\x1c\x08-,-\x8c\xe5\xd7\xf2\xaf\x06:x\x04\x03\xf2Q*\xa8\x9an\x17\xd8\xa7\xed5\xae\xb7o\xbe\xe5\xb9\x82\xc9\x12\x96^\xf0Y>\x02\x87\x06\xe5(]\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    verify(key, signed_msg, msg)
    print('done')
    return
    for i in range(0, 10):
        sk, _ = pure25519.create_keypair()
        sk, pk = sk.sk_s[:32], sk.vk_s
        print("let's go")
        msg = b'holiduli'
        t = time.ticks_ms()
        signed_msg = sign(sk, msg)
        t_s = time.ticks_diff(time.ticks_ms(), t)
        print("signing done")
        print(t_s)
        t = time.ticks_ms()
        verify(pk, signed_msg, msg)
        t_v = time.ticks_diff(time.ticks_ms(), t)
        print("verifying done")
        print(t_v)

    # wrong_msg = b'huliholi'
    # t = time.millis()
    # verify(pk, signed_msg, wrong_msg)
    # t_v = time.millis() - t
    # print("verified wrong msg")
    # print(t_v)

if __name__ == '__main__':
    main()
