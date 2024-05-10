from random import randint
from os import urandom
from collections import namedtuple
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from secret import FLAG


Point = namedtuple("Point", "x y")


def add(P, Q):
    Px, Py = P.x, P.y
    Qx, Qy = Q.x, Q.y
    Rx = (Px*Qx-e*Py*Qy) % N
    Ry = (Px*Qy+Py*Qx) % N
    return Point(Rx ,Ry)


def mul(P, exp):
    Q = Point(1, 0)
    while exp > 0:
        if exp & 1:
            Q = add(Q, P)
        P = add(P, P)
        exp >>= 1
    return Q


def gen_key():
    private_key = randint(1, N)
    public_key = mul(G, private_key)
    return (public_key, private_key)


def share_secret(P, d):
    return mul(P, d).x


def encrypt(share_secret, flag):
    key = sha256(long_to_bytes(share_secret)).digest()[:16]
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag,16))
    data = {"iv":iv.hex(),"encrypt_flag":ciphertext.hex()}
    return data


N = 61820395509869592945047899644070363303060865412602815892951881829112472104091
e = 133422
G = Point(37234080987968345210046814543941568534026683208134935256498818666416936228347,23681207802011885401101067347527183297441941230486570817545706194562153385116)
Alice_pub, n_a = gen_key()
Bob_pub, n_b = gen_key()
assert (Alice_pub.x**2 + e*Alice_pub.y**2) % N == 1
assert (Bob_pub.x**2 + e*Bob_pub.y**2) % N == 1

print(f"Alice's public key: {Alice_pub}")
print(f"Bob's public key: {Bob_pub}")

share = share_secret(Bob_pub, n_a)
enc = encrypt(share, FLAG)

print(f'Encrypted flag: {enc}')