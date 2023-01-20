#!/usr/bin/python3
from z3 import *
bit64 = 0xffffffffffffffff
def LShL(x, n): return (x << n) & bit64
size = 0xc48a
s = Solver()
flag = [BitVec(f'{i}', 8) for i in range(0x8)]
s.add(flag[0] == ord("B"))
s.add(flag[1] == ord("M"))
s.add(flag[2] == ord("X"))
s.add(flag[3] == ord("Y"))
# if ( size != ((buf[5] << 16) | buf[3] | (buf[4] << 8) | (buf[6] << 24)) )
# if ( size != ((a << 16)      | b      | (c << 8)      | (d << 24)) )

s.add(size == ((flag[5] << 16)) , flag[3] , (flag[4] << 8),  (flag[6] << 24))
print(flag)
print(s.check())