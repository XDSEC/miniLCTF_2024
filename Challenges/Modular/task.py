from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secret import flag
import random
import os


n = 16
p = getPrime(1024)
s = random.randint(1,p-1)
T = 1 << 512
E = 1 << 328


t = [random.randint(1, T) for _ in range(n)]
e = [random.randint(1, E) for _ in range(n)]
h = [(inverse(s + t[i], p) - e[i]) % p for i in range(n)]

print("t = ", t)
print("h = ", h)
print("p = ", p)

key = sha256(long_to_bytes(s)).digest()[:16]
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(flag, 16))
data = {"iv": iv.hex(), "encrypt_flag": ciphertext.hex()}
print(data)
