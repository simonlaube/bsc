import pure25519
import time

def sign(sk, msg):
    return pure25519.SigningKey(sk).sign(msg)

def verify(pk, signed_msg, msg):
    return pure25519.VerifyingKey(pk).verify(signed_msg, msg)

def main():
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
