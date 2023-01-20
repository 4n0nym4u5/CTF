#!/usr/bin/env python3

from z3 import *

s = [BitVec(f"flag_{i}", 32) for i in range(4)]
sol = Solver()
sol.add(s[1]!=3273654782)
sol.add(s[0] + s[1] + s[2] + s[3] == 0xdeadbeef)

for i in range(4):
    for j in range(4):
        print(f"i = {i} j = {j}")
        sol.add((s[i] >> 8*j) & 0xff != 0)

print(sol.check())
m = sol.model()
print(m)

flag = [hex(int(str(m[s[i]])))[2:] for i in range(len(m))]

print(''.join(flag))
