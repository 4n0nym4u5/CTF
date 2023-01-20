#!/usr/bin/python3

from z3 import *

a1 = [BitVec(f"flag_{i}",32) for i in range(40)]

s = Solver()

#v1 = -35397 * a1[25] + 24137 * a1[24] + 56856 * a1[23] + -31572 * a1[22] + 39924 * a1[21] + 8244 * a1[20] + 2290 * a1[19] + 25788 * a1[18] + 31926 * a1[17] + -4419 * a1[16] + -16288 * a1[15] + -468 * a1[14] + -20947 * a1[13] + 65096 * a1[12] + 60426 * a1[11] + -64214 * a1[10] + -36720 * a1[9] + 31858 * a1[8] + 39001 * a1[7] + 46450 * a1[6] + 41203 * a1[5] + -15260 * a1[4] + -17002 * a1[3] + 26275 * a1[2] + 28492 * a1[1] + 60938 * a1[0]
#s.add( 7182 * a1[38] + 17471 * a1[37] + 44700 * a1[36] + 3521 * a1[35] + 20023 * a1[34] + -54131 * a1[33] + -14875 * a1[32] + -30740 * a1[31] + 23243 * a1[30] + 26893 * a1[29] + 51520 * a1[28] + 31174 * a1[27] + -57819 * a1[26] + v1 - 43770 * a1[39] != 42079889)
s.add(a1[0] == ord('e'))
s.add(a1[1] == ord('s'))
s.add(a1[2] == ord('C'))
s.add(a1[3] == ord('T'))
s.add(a1[4] == ord('F'))
s.add(a1[5] == ord('{'))
s.add(a1[39] == ord('}'))

v1 = ((0xffff5506 * a1[39]) & 0xffffffff)
v1+= ((7182 * a1[38]) & 0xffffffff) 
v1+= ((17471 * a1[37]) & 0xffffffff) 
v1+= ((44700 * a1[36]) & 0xffffffff) 
v1+= ((3521 * a1[35]) & 0xffffffff) 
v1+= ((20023 * a1[34]) & 0xffffffff) 
v1+= ((0xffff2c8d * a1[33]) & 0xffffffff) 
v1+=((0xffffc5e5 * a1[32]) & 0xffffffff) 
v1+=((0xffff87ec * a1[31]) & 0xffffffff) 
v1+= ((23243 * a1[30]) & 0xffffffff) 
v1+=((26893 * a1[29]) & 0xffffffff) 
v1+=((51520 * a1[28]) & 0xffffffff) 
v1+= ((31174 * a1[27]) & 0xffffffff) 
v1+= ((0xffff1e25 * a1[26]) & 0xffffffff) 
v1+= ((0xffff75bb * a1[25])& 0xffffffff) 
v1+= ((24137 * a1[24]) & 0xffffffff) 
v1+= ((56856 * a1[23]) & 0xffffffff) 
v1+= ((0xffff84ac * a1[22]) & 0xffffffff) 
v1+= ((39924 * a1[21]) & 0xffffffff) 
v1+= ((8244 * a1[20]) & 0xffffffff) 
v1+= ((2290 * a1[19]) & 0xffffffff) 
v1+=((25788 * a1[18]) & 0xffffffff) 
v1+= ((31926 * a1[17]) & 0xffffffff) 
v1+= ((0xffffeebd * a1[16]) & 0xffffffff) 
v1+= ((0xffffc060 * a1[15]) & 0xffffffff) 
v1+= ((0xfffffe2c * a1[14]) & 0xffffffff) 
v1+= ((0xffffae2d * a1[13]) & 0xffffffff) 
v1+= ((65096 * a1[12]) & 0xffffffff) 
v1+= ((60426 * a1[11]) & 0xffffffff) 
v1+= ((0xffff052a * a1[10]) & 0xffffffff) 
v1+= ((0xffff7090 * a1[9]) & 0xffffffff) 
v1+= ((31858 * a1[8]) & 0xffffffff) 
v1+= ((39001 * a1[7]) & 0xffffffff) 
v1+= ((46450 * a1[6]) & 0xffffffff) 
v1+= ((41203 * a1[5]) & 0xffffffff) 
v1+= ((0xffffc464 * a1[4]) & 0xffffffff) 
v1+= ((0xffffbd96 * a1[3] ) & 0xffffffff) 
v1+= ((26275 * a1[2]) & 0xffffffff) 
v1+= ((28492 * a1[1]) & 0xffffffff) 
v1+= ((60938 * a1[0]) & 0xffffffff)
s.add(v1 == 42079889)

v1 = ((0xffff5506 * a1[39]) & 0xffffffff)
v1+= ((7182 * a1[38]) & 0xffffffff) 
v1+= ((17471 * a1[37]) & 0xffffffff) 
v1+= ((44700 * a1[36]) & 0xffffffff) 
v1+= ((3521 * a1[35]) & 0xffffffff) 
v1+= ((20023 * a1[34]) & 0xffffffff) 
v1+= ((0xffff2c8d * a1[33]) & 0xffffffff) 
v1+=((0xffffc5e5 * a1[32]) & 0xffffffff) 
v1+=((0xffff87ec * a1[31]) & 0xffffffff) 
v1+= ((23243 * a1[30]) & 0xffffffff) 
v1+=((26893 * a1[29]) & 0xffffffff) 
v1+=((51520 * a1[28]) & 0xffffffff) 
v1+= ((31174 * a1[27]) & 0xffffffff) 
v1+= ((0xffff1e25 * a1[26]) & 0xffffffff) 
v1+= ((0xffff75bb * a1[25])& 0xffffffff) 
v1+= ((24137 * a1[24]) & 0xffffffff) 
v1+= ((56856 * a1[23]) & 0xffffffff) 
v1+= ((0xffff84ac * a1[22]) & 0xffffffff) 
v1+= ((39924 * a1[21]) & 0xffffffff) 
v1+= ((8244 * a1[20]) & 0xffffffff) 
v1+= ((2290 * a1[19]) & 0xffffffff) 
v1+=((25788 * a1[18]) & 0xffffffff) 
v1+= ((31926 * a1[17]) & 0xffffffff) 
v1+= ((0xffffeebd * a1[16]) & 0xffffffff) 
v1+= ((0xffffc060 * a1[15]) & 0xffffffff) 
v1+= ((0xfffffe2c * a1[14]) & 0xffffffff) 
v1+= ((0xffffae2d * a1[13]) & 0xffffffff) 
v1+= ((65096 * a1[12]) & 0xffffffff) 
v1+= ((60426 * a1[11]) & 0xffffffff) 
v1+= ((0xffff052a * a1[10]) & 0xffffffff) 
v1+= ((0xffff7090 * a1[9]) & 0xffffffff) 
v1+= ((31858 * a1[8]) & 0xffffffff) 
v1+= ((39001 * a1[7]) & 0xffffffff) 
v1+= ((46450 * a1[6]) & 0xffffffff) 
v1+= ((41203 * a1[5]) & 0xffffffff) 
v1+= ((0xc674 * a1[4]) & 0xffffffff) 
v1+= ((0xe349 * a1[3] ) & 0xffffffff) 
v1+= ((0xffffd66a * a1[2]) & 0xffffffff) 
v1+= ((0xffffe5d3 * a1[1]) & 0xffffffff) 
v1+= ((0xffff815f * a1[0]) & 0xffffffff)
s.add(v1 == 42079889)
















































#result = (29400 * a1[38] + 10922 * a1[37] + -452 * a1[36] + 43546 * a1[35] + -21601 * a1[34] + -29177 * a1[33] + 62415 * a1[32] + 15708 * a1[31] + 54441 * a1[30] + 43227 * a1[29] + -41262 * a1[28] + 40047 * a1[27] + 24491 * a1[26] + v22 + 17802 * a1[39])
#s.add(result == 14043797)

for i in a1:
    s.add(i >= 0x20)
    s.add(i < 0x7E)
    s.add(i != ord(' '))



print("solving...")
if s.check() == sat:
    m = s.model()
    f = bytes([m[i].as_long() for i in a1])
    print(m, f)
