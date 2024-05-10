from z3 import *
import copy

enc = [187, 191, 185, 190, 195, 204, 206, 220, 158, 143, 157,
       155, 167, 140, 215, 149, 176, 173, 189, 180, 136, 175,
       146, 208, 207, 161, 163, 146, 183, 180, 201, 158, 148,
       167, 174, 240, 161, 153, 192, 227, 180, 180, 191, 227]

s = Solver()

input = [BitVec(f'input[{i}]', 8) for i in range(44)]
input_ref = copy.deepcopy(input)

for i in range(0, 43, 2):
    x = (input[i] + input[i+1]) & 0xff
    input[i] = input[i] ^ x
    input[i] &= 0xff
    input[i+1] = input[i+1] ^ x
    input[i+1] &= 0xff

for i in range(44):
    s.add(input[i] == enc[i])

s.check()
m = s.model()
flag = "".join(chr(m[input_ref[i]].as_long()) for i in range(len(m)))
print(flag)