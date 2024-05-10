from sage.all import *
from Crypto.Util.number import *
from secret import flag, secret
import secrets

random = secrets.SystemRandom()
assert flag == b"miniLCTF{" + secret + b"}"


def gen_key(length):
    while True:
        s = [random.getrandbits(128) for _ in range(length)]
        p = sum(s) + 2
        e = random.randint((p-1)//2,p-1)
        if isPrime(p):
            break
    
    a = [e*s[_] % p for _ in range(length)]
    b = [s[_] % 2 for _ in range(length)]
    
    PrivateKey = (s,p,e)
    PublicKey = (a,b)
    return PrivateKey, PublicKey


def encrypt_bit(bit, PublicKey):
    a, b = PublicKey
    length = len(a)
    
    r = [random.randint(0,1) for _ in range(length)]
    m = sum([b[_]*r[_] for _ in range(length)]) % 2
    
    while m != bit:
        r = [random.randint(0,1) for _ in range(length)]
        m = sum([b[_]*r[_] for _ in range(length)]) % 2
    
    c = sum([a[_]*r[_] for _ in range(length)])
    return c


def encrypt(message,PublicKey):
    ciphertext = []
    mlist = f'{(int.from_bytes(message, "big")):b}'
    for i in mlist:
        ciphertext.append(encrypt_bit(int(i,2), PublicKey))
    return ciphertext


def main():
    PublicKey = gen_key(256)[1]
    a, b = PublicKey
    cipher = encrypt(secret, PublicKey)
    
    print("a = ", a)
    print("b = ", b)
    print(cipher)


if __name__ == "__main__":
    main()
