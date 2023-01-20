#!/usr/bin/python3

from z3 import *
flag = [BitVec(f'{i}', 8) for i in range(0x8)]
s = Solver()

len_of_flag = 0x8
for i in range(len_of_flag):
    s.add(Or(And(flag[i] >= 47, flag[i] <= 57), And(flag[i] >= 64, flag[i] <= 122)))

s.add(flag[0] + flag[1] + flag[2] + flag[3] + flag[4] + flag[5] + flag[6] + flag[7] == 0x287)
s.add(flag[0] * flag[1] * flag[2] * flag[3] * flag[4] * flag[5] * flag[6] * flag[7] == 1018068377040000)
s.add(flag[0] ^ flag[1] ^ flag[2] ^ flag[3] ^ flag[4] ^ flag[5] ^ flag[6] ^ flag[7] == 0x3b)

flag_1 = flag[1]
flag_2 = flag[2] + flag_1
flag_4 = flag[4] + flag_2
s.add( flag_4 + flag[5] == 0xCE )

s.add(And(flag[0] * flag[0] == 0x2F44, flag[4] * flag[4] == 0xA29))

v25 = 0
v26 = 0
v27 = 0

for n in range(0,  len_of_flag >> 1):
    v25 ^= flag[n];

for ii in range(len_of_flag >> 1, len_of_flag):
    v26 ^= flag[ii];

for jj in range(1, len_of_flag, 2):
    v27 ^= flag[jj];

s.add(And(v25 == 0x36, v26 == 0xD, v27 == 0x22 ))
print(s.check())
model = s.model()
flag = ''.join([chr(int(str(model[flag[i]]))) for i in range(len(model))])
print(flag)