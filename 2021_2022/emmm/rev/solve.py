#!/usr/bin/env python3
#!/usr/bin/python3

from z3 import *
import regex

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))


def GetInt(payload=None, ishex=True):
    if ishex == False:
        num = [int(s) for s in regex.findall(r"-\b\d+\b", payload)]
    else:
        num = [int(s, 16) for s in regex.findall(r"0[xX][0-9a-fA-F]+", payload)]
    return num

# f=open("val.txt","r").read()
# pp=(GetInt(f, ishex=False))

# for vals in pp:
#     new_val=tohex(vals, 32)
#     f=f.replace(str(vals), new_val)

# print(f)

# d=open("newval.txt","w").write(f)


a1 = [BitVec(f"flag_{i}",32) for i in range(40)]

s = Solver()

s.add(a1[0] == ord('e'))
s.add(a1[1] == ord('s'))
s.add(a1[2] == ord('C'))
s.add(a1[3] == ord('T'))
s.add(a1[4] == ord('F'))
s.add(a1[5] == ord('{'))
s.add(a1[39] == ord('}'))

v1 = ((0xffff75bb * a1[25]) & 0xffffffff)
v1+=((24137 * a1[24]) & 0xffffffff)
v1+=((56856 * a1[23]) & 0xffffffff)
v1+=((0xffff84ac * a1[22]) & 0xffffffff)
v1+=((39924 * a1[21]) & 0xffffffff)
v1+=((8244 * a1[20]) & 0xffffffff)
v1+=((2290 * a1[19]) & 0xffffffff)
v1+=((25788 * a1[18]) & 0xffffffff)
v1+=((31926 * a1[17]) & 0xffffffff)
v1+=((0xffffeebd * a1[16]) & 0xffffffff)
v1+=((0xffffc060 * a1[15]) & 0xffffffff)
v1+=((0xfffffe2c * a1[14]) & 0xffffffff)
v1+=((0xffffae2d * a1[13]) & 0xffffffff)
v1+=((65096 * a1[12]) & 0xffffffff)
v1+=((60426 * a1[11]) & 0xffffffff)
v1+=((0xffff052a * a1[10]) & 0xffffffff)
v1+=((0xffff7090 * a1[9]) & 0xffffffff)
v1+=((31858 * a1[8]) & 0xffffffff)
v1+=((39001 * a1[7]) & 0xffffffff)
v1+=((46450 * a1[6]) & 0xffffffff)
v1+=((41203 * a1[5]) & 0xffffffff)
v1+=((0xffffc464 * a1[4]) & 0xffffffff)
v1+=((0xffffbd96 * a1[3]) & 0xffffffff)
v1+=((26275 * a1[2]) & 0xffffffff)
v1+=((28492 * a1[1]) & 0xffffffff)
v1+=((60938 * a1[0]) & 0xffffffff)
test1=0
test1+=((7182 * a1[38]) & 0xffffffff)
test1+=((17471 * a1[37]) & 0xffffffff)
test1+=((44700 * a1[36]) & 0xffffffff)
test1+=((3521 * a1[35]) & 0xffffffff)
test1+=((20023 * a1[34]) & 0xffffffff)
test1+=((0xffff2c8d * a1[33]) & 0xffffffff)
test1+=((0xffffc5e5 * a1[32]) & 0xffffffff)
test1+=((0xffff87ec * a1[31]) & 0xffffffff)
test1+=((23243 * a1[30]) & 0xffffffff)
test1+=((26893 * a1[29]) & 0xffffffff)
test1+=((51520 * a1[28]) & 0xffffffff)
test1+=((31174 * a1[27]) & 0xffffffff)
test1+=((0xffff1e25 * a1[26]) & 0xffffffff)
test1+=((v1) & 0xffffffff)
test1+=((43770 * a1[39]) & 0xffffffff)
s.add(test1 != 42079889 )


for i in a1:
    s.add(i >= 0x20)
    s.add(i < 0x7E)
    s.add(i != ord(' '))



print("solving...")
if s.check() == sat:
    m = s.model()
    f = bytes([m[i].as_long() for i in a1])
    print(m, f)
