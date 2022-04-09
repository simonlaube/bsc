from microssb import repo, log, packet
import pure25519

def mk_sign_fct(secret):
    sk = pure25519.SigningKey(secret)
    return lambda m: sk.sign(m)

def mk_verify_fct(secret):
    def vfct(pk, s, msg):
        try:
            pure25519.VerifyingKey(pk).verify(s,msg)
            return True
        except Exception as e:
            print(e)
        return False
    return vfct

def main():
    sk, _ = pure25519.create_keypair()
    sk,pk = sk.sk_s[:32], sk.vk_s # just the bytes

    path = './micro_data'
    rep = repo.Repo(path, mk_verify_fct(sk))
    feed_id = bytes(32)
    print("feed-id: " + str(pk))
    payload = bytes(48)
    print("payload: " + str(payload))
    rep.genesis_log(feed_id, payload, mk_sign_fct(sk))

if __name__ == '__main__':
    main()