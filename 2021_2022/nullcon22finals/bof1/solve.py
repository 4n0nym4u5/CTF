#! /usr/bin/python3

from z3 import *

# List of BitVec
a1 = [BitVec(f"{i}", 8) for i in range(41)]
s = Solver()


print(s.check())
model = s.model()
flag = "".join([chr(int(str(model[a1[i]]))) for i in range(len(model))])
print(flag)
